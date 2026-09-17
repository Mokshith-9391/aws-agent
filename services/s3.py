"""
S3 Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (bucket),
IAM permissions, parameter requirements, and cost warnings for Amazon S3.
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

SERVICE_NAME = "s3"
CLI_SERVICE = "s3api"
SERVICE_DESCRIPTION = "Amazon Simple Storage Service"

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class S3BucketParams(BaseModel):
    """Parameter schema for creating an S3 bucket."""
    model_config = ConfigDict(populate_by_name=True)

    bucket: str = Field(..., alias="bucket", description="Globally unique name for the S3 bucket")
    create_bucket_configuration: Optional[dict[str, Any]] = Field(
        None,
        alias="create-bucket-configuration",
        description="Configuration for the bucket, e.g. LocationConstraint",
    )
    acl: Optional[str] = Field(
        None,
        alias="acl",
        description="Canned ACL to apply to the bucket (e.g., private, public-read)",
    )


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_bucket_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for S3 bucket."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="bucket",
        cli_service=CLI_SERVICE,
        description="Amazon S3 Storage Bucket",
        create_action="create-bucket",
        describe_action="head-bucket",
        delete_action="delete-bucket",
        list_action="list-buckets",
        required_params=["bucket"],
        optional_params=["create-bucket-configuration", "acl"],
        id_field=None,
        name_tag_key="Name",
        supports_tags=True,
        cost_warning="S3 storage incurs costs based on data volume, request frequency, and data transfer.",
        iam_permissions=[
            "s3:CreateBucket",
            "s3:DeleteBucket",
            "s3:ListBucket",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_s3_service_definition() -> ServiceDefinition:
    """Build and return the S3 ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-bucket",
            "head-bucket",
            "delete-bucket",
            "list-buckets",
            "put-bucket-tagging",
            "get-bucket-tagging",
            "delete-objects",
        ],
    )

    service_def.add_resource_type(create_bucket_resource_def())
    return service_def


def register_s3_service(registry: AWSServiceRegistry) -> None:
    """
    Register the S3 service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_s3_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered S3 service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register S3 service: %s", exc, exc_info=True)
        raise
