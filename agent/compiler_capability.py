"""
CompilerCapability Manifest.

Authoritative declaration of all resource types that the PlanCompiler
can deterministically build commands for. Used by LiveModeSafetyGate
to verify that all registered resource types have full compiler support.

B6 Requirement: Each entry must declare:
  - service and resource_type
  - Which operations are supported (create, read, delete)  
  - What CLI actions each operation maps to
  - Whether a rollback command is generated
  - Whether a verification command is generated
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CompilerCapability:
    """Authoritative declaration of a resource type's compiler support."""

    service: str
    """Logical service name (e.g., 'vpc', 'ec2', 's3')."""

    resource_type: str
    """Resource type name (e.g., 'vpc', 'subnet', 'bucket')."""

    cli_service: str
    """AWS CLI service name (e.g., 'ec2', 's3api', 'iam')."""

    supports_create: bool = False
    """Whether _compile_create_resource handles this resource type."""

    create_cli_action: Optional[str] = None
    """The CLI action used for create (e.g., 'create-vpc', 'run-instances')."""

    supports_read: bool = False
    """Whether _compile_read_command handles this resource type."""

    read_cli_action: Optional[str] = None
    """The CLI action used for read/list (e.g., 'describe-vpcs')."""

    supports_delete: bool = False
    """Whether _compile_delete_command handles this resource type."""

    delete_cli_action: Optional[str] = None
    """The CLI action used for delete (e.g., 'delete-vpc')."""

    generates_verification: bool = False
    """Whether compilation produces a verification command."""

    generates_rollback: bool = False
    """Whether the create command includes a rollback_command."""

    has_create_schema: bool = True
    """Whether RESOURCE_CONFIG_SCHEMAS has an entry for this resource."""

    has_read_schema: bool = True
    """Whether READ_CONFIG_SCHEMAS has an entry for this resource."""

    has_delete_schema: bool = True
    """Whether DELETE_CONFIG_SCHEMAS has an entry for this resource."""


# Authoritative capability manifest for all supported resource types.
# This manifest is the single source of truth for what the compiler can handle.
# The LiveModeSafetyGate validates this manifest against the actual compiler code.

COMPILER_CAPABILITIES: list[CompilerCapability] = [
    # VPC resources
    CompilerCapability(
        service="vpc", resource_type="vpc", cli_service="ec2",
        supports_create=True, create_cli_action="create-vpc",
        supports_read=True, read_cli_action="describe-vpcs",
        supports_delete=True, delete_cli_action="delete-vpc",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    CompilerCapability(
        service="vpc", resource_type="subnet", cli_service="ec2",
        supports_create=True, create_cli_action="create-subnet",
        supports_read=True, read_cli_action="describe-subnets",
        supports_delete=True, delete_cli_action="delete-subnet",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    CompilerCapability(
        service="vpc", resource_type="internet_gateway", cli_service="ec2",
        supports_create=True, create_cli_action="create-internet-gateway",
        supports_read=False, read_cli_action=None,
        supports_delete=False, delete_cli_action=None,
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=False, has_delete_schema=False,
    ),
    CompilerCapability(
        service="vpc", resource_type="route_table", cli_service="ec2",
        supports_create=True, create_cli_action="create-route-table",
        supports_read=False, read_cli_action=None,
        supports_delete=False, delete_cli_action=None,
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=False, has_delete_schema=False,
    ),
    CompilerCapability(
        service="vpc", resource_type="security_group", cli_service="ec2",
        supports_create=True, create_cli_action="create-security-group",
        supports_read=True, read_cli_action="describe-security-groups",
        supports_delete=True, delete_cli_action="delete-security-group",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    # EC2 resources
    CompilerCapability(
        service="ec2", resource_type="instance", cli_service="ec2",
        supports_create=True, create_cli_action="run-instances",
        supports_read=True, read_cli_action="describe-instances",
        supports_delete=True, delete_cli_action="terminate-instances",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    CompilerCapability(
        service="ec2", resource_type="key_pair", cli_service="ec2",
        supports_create=True, create_cli_action="create-key-pair",
        supports_read=False, read_cli_action=None,
        supports_delete=False, delete_cli_action=None,
        generates_verification=True, generates_rollback=False,
        has_create_schema=True, has_read_schema=False, has_delete_schema=False,
    ),
    # S3 resources
    CompilerCapability(
        service="s3", resource_type="bucket", cli_service="s3api",
        supports_create=True, create_cli_action="create-bucket",
        supports_read=True, read_cli_action="list-buckets",
        supports_delete=True, delete_cli_action="delete-bucket",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    # IAM resources
    CompilerCapability(
        service="iam", resource_type="role", cli_service="iam",
        supports_create=True, create_cli_action="create-role",
        supports_read=True, read_cli_action="get-role",
        supports_delete=True, delete_cli_action="delete-role",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    CompilerCapability(
        service="iam", resource_type="policy", cli_service="iam",
        supports_create=True, create_cli_action="create-policy",
        supports_read=True, read_cli_action="get-policy",
        supports_delete=True, delete_cli_action="delete-policy",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
    # DynamoDB resources
    CompilerCapability(
        service="dynamodb", resource_type="table", cli_service="dynamodb",
        supports_create=True, create_cli_action="create-table",
        supports_read=True, read_cli_action="describe-table",
        supports_delete=True, delete_cli_action="delete-table",
        generates_verification=True, generates_rollback=True,
        has_create_schema=True, has_read_schema=True, has_delete_schema=True,
    ),
]


def get_capability(service: str, resource_type: str) -> Optional[CompilerCapability]:
    """Look up a compiler capability by service and resource_type."""
    for cap in COMPILER_CAPABILITIES:
        if cap.service == service and cap.resource_type == resource_type:
            return cap
    return None


def get_compiler_capabilities() -> list[CompilerCapability]:
    """Return all compiler capability manifests."""
    return list(COMPILER_CAPABILITIES)


def validate_manifest_completeness() -> list[str]:
    """Validate the COMPILER_CAPABILITIES manifest for internal consistency.

    Returns a list of issues found. Empty list means the manifest is valid.
    """
    from aws.cli_executor import ALLOWED_ACTIONS

    issues = []
    for cap in COMPILER_CAPABILITIES:
        # Every capability with create support must have a create action
        if cap.supports_create and not cap.create_cli_action:
            issues.append(
                f"{cap.service}.{cap.resource_type}: supports_create=True but create_cli_action is None"
            )

        # Every create action must be in ALLOWED_ACTIONS for its CLI service
        if cap.supports_create and cap.create_cli_action:
            allowed = ALLOWED_ACTIONS.get(cap.cli_service, set())
            if cap.create_cli_action not in allowed:
                issues.append(
                    f"{cap.service}.{cap.resource_type}: create action '{cap.create_cli_action}' "
                    f"not in ALLOWED_ACTIONS['{cap.cli_service}']"
                )

        # Every delete action must be in ALLOWED_ACTIONS
        if cap.supports_delete and cap.delete_cli_action:
            allowed = ALLOWED_ACTIONS.get(cap.cli_service, set())
            if cap.delete_cli_action not in allowed:
                issues.append(
                    f"{cap.service}.{cap.resource_type}: delete action '{cap.delete_cli_action}' "
                    f"not in ALLOWED_ACTIONS['{cap.cli_service}']"
                )

        # Every resource with create support must have a create schema
        if cap.supports_create and not cap.has_create_schema:
            issues.append(
                f"{cap.service}.{cap.resource_type}: supports_create=True but has_create_schema=False"
            )

    return issues
