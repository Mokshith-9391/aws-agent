"""
EC2 Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (instance, key_pair, ami),
IAM permissions, parameter requirements, and cost warnings for Amazon EC2.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from services.registry import (
    AWSServiceRegistry,
    ResourceTypeDefinition,
    ServiceDefinition,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Service Constants
# ──────────────────────────────────────────────

SERVICE_NAME = "ec2"
CLI_SERVICE = "ec2"
SERVICE_DESCRIPTION = "Amazon Elastic Compute Cloud"

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class EC2InstanceParams(BaseModel):
    """Parameter schema for creating an EC2 instance."""
    model_config = ConfigDict(populate_by_name=True)

    image_id: str = Field(..., alias="image-id", description="ID of the AMI to launch")
    instance_type: str = Field(..., alias="instance-type", description="EC2 instance type (e.g., t3.micro)")
    key_name: Optional[str] = Field(None, alias="key-name", description="Key pair name for SSH access")
    security_group_ids: Optional[list[str]] = Field(None, alias="security-group-ids", description="List of security group IDs")
    subnet_id: Optional[str] = Field(None, alias="subnet-id", description="Subnet ID to launch into")
    count: Optional[int] = Field(1, alias="count", description="Number of instances to launch")
    tag_specifications: Optional[list[dict[str, Any]]] = Field(None, alias="tag-specifications", description="Resource tags specification")
    user_data: Optional[str] = Field(None, alias="user-data", description="Base64-encoded or raw user data script")


class EC2KeyPairParams(BaseModel):
    """Parameter schema for creating an EC2 key pair."""
    model_config = ConfigDict(populate_by_name=True)

    key_name: str = Field(..., alias="key-name", description="Unique name for the key pair")


class EC2AMIQueryParams(BaseModel):
    """Parameter schema for querying AMIs."""
    model_config = ConfigDict(populate_by_name=True)

    owners: list[str] = Field(..., alias="owners", description="List of AMI owners (e.g., ['self'], ['amazon'])")
    image_ids: Optional[list[str]] = Field(None, alias="image-ids", description="Optional list of image IDs")
    filters: Optional[list[dict[str, Any]]] = Field(None, alias="filters", description="Optional search filters")


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


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

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
    """
    Register the EC2 service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_ec2_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered EC2 service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register EC2 service: %s", exc, exc_info=True)
        raise
