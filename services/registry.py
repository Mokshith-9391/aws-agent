"""
AWS Service Registry.

Central registry that maps AWS services to their handlers,
providing resource type definitions, supported operations,
validators, command builders, and verification strategies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from agent.models import OperationCategory

logger = logging.getLogger(__name__)


@dataclass
class ResourceTypeDefinition:
    """Definition of a single AWS resource type within a service."""
    service: str
    resource_type: str
    cli_service: str
    description: str
    create_action: Optional[str] = None
    describe_action: Optional[str] = None
    delete_action: Optional[str] = None
    list_action: Optional[str] = None
    required_params: list[str] = field(default_factory=list)
    optional_params: list[str] = field(default_factory=list)
    id_field: Optional[str] = None
    name_tag_key: str = "Name"
    supports_tags: bool = True
    cost_warning: Optional[str] = None
    iam_permissions: list[str] = field(default_factory=list)


@dataclass
class ServiceDefinition:
    """Definition of an AWS service and its resource types."""
    service_name: str
    cli_service: str
    description: str
    resource_types: dict[str, ResourceTypeDefinition] = field(default_factory=dict)
    supported_operations: list[str] = field(default_factory=list)

    def add_resource_type(self, resource_type: ResourceTypeDefinition) -> None:
        """Register a resource type with this service."""
        self.resource_types[resource_type.resource_type] = resource_type


class AmbiguousResourceTypeError(ValueError):
    """Raised when a resource_type matches multiple services without an explicit service hint.

    B5: The compiler must fail with an explicit error rather than silently picking
    the first match. The caller must supply an explicit 'service' field to disambiguate.
    """

    def __init__(self, resource_type: str, matching_services: list[str]) -> None:
        super().__init__(
            "Resource type '" + resource_type + "' is ambiguous: found in services " + str(matching_services) + ". "
            "Specify 'service' explicitly in the desired-state resource to disambiguate."
        )
        self.resource_type = resource_type
        self.matching_services = matching_services


class AWSServiceRegistry:
    """
    Central registry for all supported AWS services.

    Provides lookup, validation, and metadata for services and resource types.
    Designed as a plugin architecture where services can be registered dynamically.
    """

    def __init__(self) -> None:
        self._services: dict[str, ServiceDefinition] = {}
        self._resource_type_map: dict[str, ResourceTypeDefinition] = {}
        self._initialized = False

    def register_service(self, service_def: ServiceDefinition) -> None:
        """Register a service definition."""
        self._services[service_def.service_name] = service_def
        for rt_name, rt_def in service_def.resource_types.items():
            key = service_def.service_name + "." + rt_name
            self._resource_type_map[key] = rt_def
        logger.debug("Registered service: %s with %d resource types", service_def.service_name, len(service_def.resource_types))

    def get_service(self, service_name: str) -> Optional[ServiceDefinition]:
        """Get a service definition by name."""
        return self._services.get(service_name)

    def get_resource_type(self, service: str, resource_type: str) -> Optional[ResourceTypeDefinition]:
        """Get a resource type definition."""
        key = service + "." + resource_type
        return self._resource_type_map.get(key)

    def is_service_supported(self, service_name: str) -> bool:
        """Check if a service is supported."""
        return service_name in self._services

    def list_services(self) -> list[str]:
        """List all registered service names."""
        return list(self._services.keys())

    def list_resource_types(self, service_name: str) -> list[str]:
        """List resource types for a service."""
        svc = self._services.get(service_name)
        if svc:
            return list(svc.resource_types.keys())
        return []

    def get_cli_service(self, service_name: str) -> Optional[str]:
        """Get the CLI service name for an internal service name."""
        svc = self._services.get(service_name)
        return svc.cli_service if svc else None

    def find_resource_type(
        self, resource_type: str, service: Optional[str] = None
    ) -> Optional[tuple[str, ResourceTypeDefinition]]:
        """Find the service name and ResourceTypeDefinition for a given resource_type string.

        B5: Raises AmbiguousResourceTypeError when multiple services provide this resource_type
        and no service hint is given. Previously returned the first match silently.

        Args:
            resource_type: The resource type string (e.g. 'vpc', 'instance').
            service: Optional explicit service hint to disambiguate.

        Returns:
            (service_name, ResourceTypeDefinition) tuple or None if not found.

        Raises:
            AmbiguousResourceTypeError: If multiple services provide this resource_type.
        """
        rtype_norm = resource_type.lower().strip()

        # If explicit service is provided, try exact lookup first
        if service:
            svc_def = self._services.get(service)
            if svc_def and rtype_norm in svc_def.resource_types:
                return service, svc_def.resource_types[rtype_norm]

        # Search all services for matches
        matches: list[tuple[str, ResourceTypeDefinition]] = []
        for svc_name, svc_def in self._services.items():
            if rtype_norm in svc_def.resource_types:
                matches.append((svc_name, svc_def.resource_types[rtype_norm]))

        if len(matches) == 0:
            return None
        elif len(matches) == 1:
            return matches[0]
        else:
            raise AmbiguousResourceTypeError(resource_type, [m[0] for m in matches])

    def deduce_resource_type(self, service: str, action: str) -> Optional[str]:
        """Deduce resource type from CLI service and action."""
        svc_norm = service.lower().strip()
        act_norm = action.lower().strip()
        for svc_def in self._services.values():
            if svc_def.cli_service == svc_norm or svc_def.service_name == svc_norm:
                for rtype, rt_def in svc_def.resource_types.items():
                    if act_norm in (rt_def.create_action, rt_def.describe_action, rt_def.delete_action, rt_def.list_action):
                        return rtype
        return None

    def get_all_resource_definitions(self) -> list[ResourceTypeDefinition]:
        """Get all registered resource type definitions."""
        return list(self._resource_type_map.values())

    def get_service_summary(self) -> dict[str, dict[str, Any]]:
        """Get a summary of all services and their resource types for LLM context."""
        summary = {}
        for name, svc in self._services.items():
            summary[name] = {
                "description": svc.description,
                "cli_service": svc.cli_service,
                "resource_types": {
                    rt_name: {
                        "description": rt_def.description,
                        "create_action": rt_def.create_action,
                        "required_params": rt_def.required_params,
                        "cost_warning": rt_def.cost_warning,
                    }
                    for rt_name, rt_def in svc.resource_types.items()
                }
            }
        return summary


def create_default_registry() -> AWSServiceRegistry:
    """Create and populate the default service registry with all supported services."""
    from services.ec2 import register_ec2_service
    from services.s3 import register_s3_service
    from services.vpc import register_vpc_service
    from services.iam import register_iam_service
    from services.lambda_service import register_lambda_service
    from services.dynamodb import register_dynamodb_service
    from services.rds import register_rds_service
    from services.ecs import register_ecs_service

    registry = AWSServiceRegistry()
    register_ec2_service(registry)
    register_s3_service(registry)
    register_vpc_service(registry)
    register_iam_service(registry)
    register_lambda_service(registry)
    register_dynamodb_service(registry)
    register_rds_service(registry)
    register_ecs_service(registry)

    logger.info("Service registry initialized with %d services", len(registry.list_services()))
    return registry
