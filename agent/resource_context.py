"""
Resource Context and Reference Resolution System.

Manages logical resource references (e.g. 'vpc.main', 'security_group.web'),
their runtime AWS IDs, attributes, and ownership scopes. Provides recursive
placeholder substitution across arbitrary nested data structures (strings,
lists, dicts).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from agent.models import LogicalResource, ResourceOwnership

logger = logging.getLogger(__name__)

# Matches {{resource_ref}} or {{resource_ref.field}} or {{field}}
PLACEHOLDER_PATTERN = re.compile(r"\{\{([a-zA-Z0-9_\-\.]+)\}\}")


class UnresolvedReferenceError(Exception):
    """Raised when a command contains a placeholder that cannot be resolved."""
    def __init__(self, unresolved_references: list[str], command_desc: str = "") -> None:
        self.unresolved_references = unresolved_references
        self.command_desc = command_desc
        refs_str = ", ".join(unresolved_references)
        msg = f"Cannot execute command '{command_desc}': unresolved reference(s): [{refs_str}]"
        super().__init__(msg)


class ResourceContext:
    """Central store for tracking logical resources and resolving dependencies."""

    def __init__(self) -> None:
        self._resources: dict[str, LogicalResource] = {}
        # Flat lookup index: resource_id -> LogicalResource
        self._by_id: dict[str, LogicalResource] = {}
        # Legacy/generic alias mapping (e.g. 'VpcId' -> 'vpc-123')
        self._legacy_aliases: dict[str, str] = {}

    def register_resource(
        self,
        resource_ref: str | LogicalResource,
        resource_type: Optional[str] = None,
        service: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        ownership: ResourceOwnership = ResourceOwnership.CREATED_BY_THIS_PLAN,
        attributes: Optional[dict[str, Any]] = None,
        dependencies: Optional[list[str]] = None,
    ) -> LogicalResource:
        """Register or update a logical resource in the context.

        Accepts either a LogicalResource instance or individual fields.
        """
        if isinstance(resource_ref, LogicalResource):
            res_obj = resource_ref
            ref_str = res_obj.resource_ref
            res_type = res_obj.resource_type
            res_svc = res_obj.service
            r_id = res_obj.resource_id or resource_id
            r_name = res_obj.resource_name or resource_name
            r_own = res_obj.ownership
            r_attrs = res_obj.attributes.copy() if res_obj.attributes else {}
            if attributes:
                r_attrs.update(attributes)
            r_deps = list(res_obj.dependencies) if res_obj.dependencies else []
            if dependencies:
                r_deps.extend(dependencies)
        else:
            ref_str = resource_ref
            res_type = resource_type or "resource"
            res_svc = service or "aws"
            r_id = resource_id
            r_name = resource_name
            r_own = ownership
            r_attrs = attributes or {}
            r_deps = dependencies or []

        existing = self._resources.get(ref_str)
        if existing:
            if r_id:
                existing.resource_id = r_id
            if r_name:
                existing.resource_name = r_name
            existing.ownership = r_own
            existing.attributes.update(r_attrs)
            if r_deps:
                existing.dependencies = r_deps
            resource = existing
        else:
            resource = LogicalResource(
                resource_ref=ref_str,
                resource_type=res_type,
                service=res_svc,
                resource_id=r_id,
                resource_name=r_name,
                ownership=r_own,
                attributes=r_attrs,
                dependencies=r_deps,
            )
            self._resources[ref_str] = resource

        if resource.resource_id:
            self._by_id[resource.resource_id] = resource
            self._legacy_aliases[ref_str] = resource.resource_id
            self._legacy_aliases[f"{ref_str}.id"] = resource.resource_id
            self._legacy_aliases[f"{ref_str}.resource_id"] = resource.resource_id
            type_title = "".join(part.capitalize() for part in res_type.split("_"))
            self._legacy_aliases[f"{type_title}Id"] = resource.resource_id

        return resource

    def get_resource(self, resource_ref: str) -> Optional[LogicalResource]:
        """Look up a logical resource by its reference."""
        return self._resources.get(resource_ref)

    def get_resource_by_id(self, resource_id: str) -> Optional[LogicalResource]:
        """Look up a resource by its actual AWS resource ID."""
        return self._by_id.get(resource_id)

    def list_resources(self) -> list[LogicalResource]:
        """Return all tracked logical resources."""
        return list(self._resources.values())

    def get_created_resources(self) -> list[LogicalResource]:
        """Return only resources created by the current plan (eligible for rollback)."""
        return [
            r for r in self._resources.values()
            if r.ownership == ResourceOwnership.CREATED_BY_THIS_PLAN and r.resource_id
        ]

    def is_resource_owned_by_plan(self, resource_ref: str) -> bool:
        """Check if a logical resource was created by this plan."""
        res = self._resources.get(resource_ref) or self._by_id.get(resource_ref)
        if res:
            return res.ownership == ResourceOwnership.CREATED_BY_THIS_PLAN
        return False

    def update_resource_id(
        self,
        resource_ref: str,
        resource_id: str,
        attributes: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Assign an AWS resource ID to an existing logical resource after creation."""
        res = self._resources.get(resource_ref)
        if not res:
            logger.warning("Attempted to update non-existent resource_ref '%s'", resource_ref)
            return False

        res.resource_id = resource_id
        if attributes:
            res.attributes.update(attributes)
        self._by_id[resource_id] = res
        self._legacy_aliases[resource_ref] = resource_id
        self._legacy_aliases[f"{resource_ref}.id"] = resource_id
        self._legacy_aliases[f"{resource_ref}.resource_id"] = resource_id
        return True

    def resolve_value(self, path: str, raise_if_unresolved: bool = False) -> Optional[str]:
        """Resolve a reference string to a concrete value.

        Supports:
        - Exact logical reference: 'vpc.main' -> 'vpc-12345'
        - Explicit property: 'vpc.main.id' -> 'vpc-12345'
        - Attribute lookup: 'vpc.main.cidr_block' -> '10.0.0.0/16'
        - Legacy key: 'VpcId' -> 'vpc-12345'
        """
        result: Optional[str] = None

        # 1. Direct legacy or alias lookup
        if path in self._legacy_aliases:
            result = self._legacy_aliases[path]

        # 2. Split into resource_ref and subproperty
        elif "." in path:
            parts = path.split(".", 1)
            ref_candidate = parts[0]
            subprop = parts[1]

            # Try 2-part ref like 'security_group.web'
            # e.g. 'security_group.web.id' -> ref='security_group.web', subprop='id'
            rparts = path.rsplit(".", 1)
            possible_ref = rparts[0]
            possible_prop = rparts[1]

            if possible_ref in self._resources:
                res = self._resources[possible_ref]
                if possible_prop in ("id", "resource_id"):
                    result = res.resource_id
                elif possible_prop in ("name", "resource_name"):
                    result = res.resource_name
                elif possible_prop in res.attributes:
                    result = str(res.attributes[possible_prop])

            if result is None and ref_candidate in self._resources:
                res = self._resources[ref_candidate]
                if subprop in ("id", "resource_id"):
                    result = res.resource_id
                elif subprop in res.attributes:
                    result = str(res.attributes[subprop])

        # 3. Check direct resource ref
        elif path in self._resources:
            result = self._resources[path].resource_id

        if result is None and raise_if_unresolved:
            raise UnresolvedReferenceError([path])

        return result

    def resolve_placeholders_recursively(self, obj: Any) -> Any:
        """Recursively replace {{placeholder}} tokens across strings, lists, and dicts.

        Args:
            obj: Target structure (dict, list, str, or primitive).

        Returns:
            Resolved deep copy of the structure.
        """
        if isinstance(obj, str):
            def repl(match: re.Match) -> str:
                ref_path = match.group(1)
                resolved = self.resolve_value(ref_path)
                return resolved if resolved is not None else match.group(0)

            return PLACEHOLDER_PATTERN.sub(repl, obj)

        elif isinstance(obj, list):
            return [self.resolve_placeholders_recursively(item) for item in obj]

        elif isinstance(obj, dict):
            return {
                k: self.resolve_placeholders_recursively(v)
                for k, v in obj.items()
            }

        return obj

    def find_unresolved_placeholders(self, obj: Any) -> list[str]:
        """Find any {{placeholder}} tokens remaining in an object structure."""
        unresolved: list[str] = []

        if isinstance(obj, str):
            for match in PLACEHOLDER_PATTERN.finditer(obj):
                token = match.group(1)
                if self.resolve_value(token) is None:
                    unresolved.append(f"{{{{{token}}}}}")

        elif isinstance(obj, list):
            for item in obj:
                unresolved.extend(self.find_unresolved_placeholders(item))

        elif isinstance(obj, dict):
            for v in obj.values():
                unresolved.extend(self.find_unresolved_placeholders(v))

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for u in unresolved:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

    def to_dict(self) -> dict[str, Any]:
        """Serialize context for session storage or logging."""
        return {
            "resources": {
                ref: res.model_dump()
                for ref, res in self._resources.items()
            },
            "legacy_aliases": self._legacy_aliases.copy(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceContext:
        """Reconstruct context from a serialized dictionary."""
        ctx = cls()
        resources_dict = data.get("resources", {})
        for ref, res_data in resources_dict.items():
            res = LogicalResource.model_validate(res_data)
            ctx._resources[ref] = res
            if res.resource_id:
                ctx._by_id[res.resource_id] = res
        ctx._legacy_aliases = data.get("legacy_aliases", {}).copy()
        return ctx
