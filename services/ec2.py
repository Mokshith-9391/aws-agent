"""
EC2 Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (instance, key_pair, ami),
IAM permissions, parameter requirements, cost warnings, and deterministic
command builders for Amazon EC2.
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

SERVICE_NAME = "ec2"
CLI_SERVICE = "ec2"
SERVICE_DESCRIPTION = "Amazon Elastic Compute Cloud"


# ──────────────────────────────────────────────
# Deterministic Command Builders
# ──────────────────────────────────────────────

def build_run_instances_command(
    image_id: str,
    instance_type: str = "t3.micro",
    count: int = 1,
    subnet_id: Optional[str] = None,
    security_group_ids: Optional[list[str]] = None,
    key_name: Optional[str] = None,
    name_tag: Optional[str] = None,
    user_data: Optional[str] = None,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
    resource_ref: str = "ec2.instance",
) -> CLICommand:
    """Deterministically construct a run-instances command with proper flags."""
    params: dict[str, Any] = {
        "image-id": image_id,
        "instance-type": instance_type,
        "count": str(count),
    }
    if subnet_id:
        params["subnet-id"] = subnet_id
    if security_group_ids:
        params["security-group-ids"] = security_group_ids
    if key_name:
        params["key-name"] = key_name
    if user_data:
        params["user-data"] = user_data
    if name_tag:
        params["tag-specifications"] = [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": name_tag}],
            }
        ]

    cmd = CLICommand(
        command_id=command_id or "cmd-ec2-run",
        service="ec2",
        action="run-instances",
        parameters=params,
        description=f"Launch {instance_type} EC2 instance using {image_id}",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        depends_on=depends_on or [],
        output_key="Instances[0].InstanceId",
    )
    # Attach rollback command
    cmd.rollback_command = build_terminate_instances_command(
        instance_ids=[f"{{{{{resource_ref}.id}}}}"],
        resource_ref=resource_ref,
    )
    return cmd


def build_describe_instances_command(
    instance_ids: Optional[list[str]] = None,
    filters: Optional[list[dict[str, Any]]] = None,
    command_id: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a describe-instances command."""
    params: dict[str, Any] = {}
    if instance_ids:
        params["instance-ids"] = instance_ids
    if filters:
        params["filters"] = filters

    return CLICommand(
        command_id=command_id or "cmd-ec2-describe",
        service="ec2",
        action="describe-instances",
        parameters=params,
        description="Describe EC2 instances and check their runtime state",
        operation_category=OperationCategory.READ_ONLY,
    )


def build_terminate_instances_command(
    instance_ids: list[str],
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a terminate-instances command."""
    return CLICommand(
        command_id=command_id or "cmd-ec2-terminate",
        service="ec2",
        action="terminate-instances",
        parameters={"instance-ids": instance_ids},
        description=f"Terminate EC2 instance(s): {', '.join(instance_ids)}",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_create_key_pair_command(
    key_name: str,
    command_id: Optional[str] = None,
    resource_ref: str = "ec2.key_pair",
) -> CLICommand:
    """Deterministically construct a create-key-pair command."""
    return CLICommand(
        command_id=command_id or "cmd-ec2-keypair",
        service="ec2",
        action="create-key-pair",
        parameters={"key-name": key_name},
        description=f"Create SSH key pair '{key_name}'",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="KeyPairId",
    )


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_instance_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for EC2 instance."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="instance",
        cli_service=CLI_SERVICE,
        description="Amazon EC2 Virtual Machine Instance",
        create_action="run-instances",
        describe_action="describe-instances",
        delete_action="terminate-instances",
        list_action="describe-instances",
        required_params=["image-id", "instance-type"],
        optional_params=[
            "key-name",
            "security-group-ids",
            "subnet-id",
            "count",
            "tag-specifications",
            "user-data",
        ],
        id_field="Instances[0].InstanceId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning="EC2 instances incur charges while running. Remember to stop or terminate instances when not needed.",
        iam_permissions=[
            "ec2:RunInstances",
            "ec2:DescribeInstances",
            "ec2:TerminateInstances",
        ],
    )


def create_key_pair_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for EC2 key pair."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="key_pair",
        cli_service=CLI_SERVICE,
        description="Amazon EC2 Key Pair for SSH Authentication",
        create_action="create-key-pair",
        describe_action="describe-key-pairs",
        delete_action="delete-key-pair",
        required_params=["key-name"],
        optional_params=[],
        id_field="KeyPairId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateKeyPair",
            "ec2:DescribeKeyPairs",
            "ec2:DeleteKeyPair",
        ],
    )


def create_ami_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for EC2 AMI (read-only)."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="ami",
        cli_service=CLI_SERVICE,
        description="Amazon Machine Image (Read-Only)",
        create_action=None,
        describe_action="describe-images",
        delete_action=None,
        list_action="describe-images",
        required_params=["owners"],
        optional_params=["image-ids", "filters"],
        id_field=None,
        name_tag_key="Name",
        supports_tags=False,
        cost_warning=None,
        iam_permissions=[
            "ec2:DescribeImages",
        ],
    )


def get_ec2_service_definition() -> ServiceDefinition:
    """Build and return the EC2 ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "run-instances",
            "describe-instances",
            "terminate-instances",
            "stop-instances",
            "start-instances",
            "create-key-pair",
            "describe-key-pairs",
            "delete-key-pair",
            "describe-images",
        ],
    )
    service_def.add_resource_type(create_instance_resource_def())
    service_def.add_resource_type(create_key_pair_resource_def())
    service_def.add_resource_type(create_ami_resource_def())
    return service_def


def register_ec2_service(registry: AWSServiceRegistry) -> None:
    """Register the EC2 service with the registry."""
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")
    service_def = get_ec2_service_definition()
    registry.register_service(service_def)
    logger.info("Registered EC2 service")
