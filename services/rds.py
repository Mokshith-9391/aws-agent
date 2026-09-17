"""
RDS Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (db_instance),
IAM permissions, parameter requirements, and cost warnings for Amazon RDS.
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

SERVICE_NAME = "rds"
CLI_SERVICE = "rds"
SERVICE_DESCRIPTION = "Amazon Relational Database Service"

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class RDSInstanceParams(BaseModel):
    """Parameter schema for creating an RDS DB instance."""
    model_config = ConfigDict(populate_by_name=True)

    db_instance_identifier: str = Field(
        ...,
        alias="db-instance-identifier",
        description="Unique identifier for the DB instance",
    )
    db_instance_class: str = Field(
        ...,
        alias="db-instance-class",
        description="Compute and memory capacity of the DB instance (e.g., db.t3.micro)",
    )
    engine: str = Field(
        ...,
        alias="engine",
        description="Database engine name (e.g., mysql, postgres, mariadb)",
    )
    master_username: Optional[str] = Field(
        None,
        alias="master-username",
        description="Login username for the master user",
    )
    master_user_password: Optional[str] = Field(
        None,
        alias="master-user-password",
        description="Password for the master user",
    )
    allocated_storage: Optional[int] = Field(
        None,
        alias="allocated-storage",
        description="Allocated storage size in gigabytes (GB)",
    )
    vpc_security_group_ids: Optional[list[str]] = Field(
        None,
        alias="vpc-security-group-ids",
        description="List of VPC security group IDs to associate",
    )
    db_subnet_group_name: Optional[str] = Field(
        None,
        alias="db-subnet-group-name",
        description="DB subnet group name to use for the DB instance",
    )
    multi_az: Optional[bool] = Field(
        None,
        alias="multi-az",
        description="Whether to create a Multi-AZ deployment",
    )
    storage_type: Optional[str] = Field(
        None,
        alias="storage-type",
        description="Storage type (e.g., gp2, gp3, io1)",
    )


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_db_instance_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for RDS DB instance."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="db_instance",
        cli_service=CLI_SERVICE,
        description="Amazon Relational Database Service (RDS) DB Instance",
        create_action="create-db-instance",
        describe_action="describe-db-instances",
        delete_action="delete-db-instance",
        list_action="describe-db-instances",
        required_params=[
            "db-instance-identifier",
            "db-instance-class",
            "engine",
        ],
        optional_params=[
            "master-username",
            "master-user-password",
            "allocated-storage",
            "vpc-security-group-ids",
            "db-subnet-group-name",
            "multi-az",
            "storage-type",
        ],
        id_field="DBInstance.DBInstanceArn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=(
            "RDS instances incur charges while running. "
            "Multi-AZ deployments cost approximately double. "
            "Remember to delete instances when not needed."
        ),
        iam_permissions=[
            "rds:CreateDBInstance",
            "rds:DescribeDBInstances",
            "rds:DeleteDBInstance",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_rds_service_definition() -> ServiceDefinition:
    """Build and return the RDS ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-db-instance",
            "describe-db-instances",
            "delete-db-instance",
            "modify-db-instance",
            "reboot-db-instance",
            "start-db-instance",
            "stop-db-instance",
        ],
    )

    service_def.add_resource_type(create_db_instance_resource_def())
    return service_def


def register_rds_service(registry: AWSServiceRegistry) -> None:
    """
    Register the RDS service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_rds_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered RDS service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register RDS service: %s", exc, exc_info=True)
        raise
