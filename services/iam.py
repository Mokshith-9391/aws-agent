"""
IAM Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (role, policy),
IAM permissions, parameter requirements, and cost warnings for AWS Identity and Access Management (IAM).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from agent.models import CLICommand, OperationCategory
from services.registry import (
    AWSServiceRegistry,
    ResourceTypeDefinition,
    ServiceDefinition,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Service Constants
# ──────────────────────────────────────────────

SERVICE_NAME = "iam"
CLI_SERVICE = "iam"
SERVICE_DESCRIPTION = "AWS Identity and Access Management"

# ──────────────────────────────────────────────
# Deterministic Command Builders
# ──────────────────────────────────────────────

def build_create_role_command(
    role_name: str,
    assume_role_policy_document: str,
    description: Optional[str] = None,
    tags: Optional[list[dict[str, str]]] = None,
    command_id: Optional[str] = None,
    resource_ref: str = "iam.role",
) -> CLICommand:
    """Deterministically construct a create-role command."""
    params: dict[str, Any] = {
        "role-name": role_name,
        "assume-role-policy-document": assume_role_policy_document,
    }
    if description:
        params["description"] = description
    if tags:
        params["tags"] = tags

    cmd = CLICommand(
        command_id=command_id or "cmd-iam-create-role",
        service="iam",
        action="create-role",
        parameters=params,
        description=f"Create IAM role '{role_name}'",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="Role.Arn",
    )
    cmd.rollback_command = build_delete_role_command(
        role_name=role_name,
        resource_ref=resource_ref,
    )
    return cmd


def build_delete_role_command(
    role_name: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-role command."""
    return CLICommand(
        command_id=command_id or "cmd-iam-delete-role",
        service="iam",
        action="delete-role",
        parameters={"role-name": role_name},
        description=f"Delete IAM role '{role_name}'",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_get_role_command(
    role_name: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a get-role verification command."""
    return CLICommand(
        command_id=command_id or "cmd-iam-get-role",
        service="iam",
        action="get-role",
        parameters={"role-name": role_name},
        description=f"Verify IAM role '{role_name}'",
        operation_category=OperationCategory.READ_ONLY,
        resource_ref=resource_ref,
    )


def build_create_policy_command(
    policy_name: str,
    policy_document: str,
    description: Optional[str] = None,
    tags: Optional[list[dict[str, str]]] = None,
    command_id: Optional[str] = None,
    resource_ref: str = "iam.policy",
) -> CLICommand:
    """Deterministically construct a create-policy command."""
    params: dict[str, Any] = {
        "policy-name": policy_name,
        "policy-document": policy_document,
    }
    if description:
        params["description"] = description
    if tags:
        params["tags"] = tags

    cmd = CLICommand(
        command_id=command_id or "cmd-iam-create-policy",
        service="iam",
        action="create-policy",
        parameters=params,
        description=f"Create IAM policy '{policy_name}'",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="Policy.Arn",
    )
    cmd.rollback_command = build_delete_policy_command(
        policy_arn=f"{{{{{resource_ref}.id}}}}",
        resource_ref=resource_ref,
    )
    return cmd


def build_delete_policy_command(
    policy_arn: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-policy command."""
    return CLICommand(
        command_id=command_id or "cmd-iam-delete-policy",
        service="iam",
        action="delete-policy",
        parameters={"policy-arn": policy_arn},
        description=f"Delete IAM policy '{policy_arn}'",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class IAMRoleParams(BaseModel):
    """Parameter schema for creating an IAM role."""
    model_config = ConfigDict(populate_by_name=True)

    role_name: str = Field(..., alias="role-name", description="Name of the IAM role")
    assume_role_policy_document: str = Field(
        ...,
        alias="assume-role-policy-document",
        description="Trust relationship policy JSON string or file path",
    )
    description: Optional[str] = Field(None, alias="description", description="Description of the role")
    tags: Optional[list[dict[str, str]]] = Field(None, alias="tags", description="List of key-value tag pairs")


class IAMPolicyParams(BaseModel):
    """Parameter schema for creating an IAM policy."""
    model_config = ConfigDict(populate_by_name=True)

    policy_name: str = Field(..., alias="policy-name", description="Name of the IAM policy")
    policy_document: str = Field(
        ...,
        alias="policy-document",
        description="JSON policy document string or file path",
    )
    description: Optional[str] = Field(None, alias="description", description="Description of the policy")
    tags: Optional[list[dict[str, str]]] = Field(None, alias="tags", description="List of key-value tag pairs")


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_role_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for IAM role."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="role",
        cli_service=CLI_SERVICE,
        description="AWS Identity and Access Management (IAM) Role",
        create_action="create-role",
        describe_action="get-role",
        delete_action="delete-role",
        list_action="list-roles",
        required_params=["role-name", "assume-role-policy-document"],
        optional_params=["description", "tags"],
        id_field="Role.Arn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "iam:CreateRole",
            "iam:GetRole",
            "iam:DeleteRole",
            "iam:PassRole",
        ],
    )


def create_policy_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for IAM managed policy."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="policy",
        cli_service=CLI_SERVICE,
        description="AWS Identity and Access Management (IAM) Managed Policy",
        create_action="create-policy",
        describe_action="get-policy",
        delete_action="delete-policy",
        list_action="list-policies",
        required_params=["policy-name", "policy-document"],
        optional_params=["description", "tags"],
        id_field="Policy.Arn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "iam:CreatePolicy",
            "iam:GetPolicy",
            "iam:DeletePolicy",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_iam_service_definition() -> ServiceDefinition:
    """Build and return the IAM ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-role",
            "get-role",
            "delete-role",
            "list-roles",
            "attach-role-policy",
            "detach-role-policy",
            "put-role-policy",
            "delete-role-policy",
            "create-policy",
            "get-policy",
            "delete-policy",
            "list-policies",
        ],
    )

    service_def.add_resource_type(create_role_resource_def())
    service_def.add_resource_type(create_policy_resource_def())

    return service_def


def register_iam_service(registry: AWSServiceRegistry) -> None:
    """
    Register the IAM service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_iam_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered IAM service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register IAM service: %s", exc, exc_info=True)
        raise
