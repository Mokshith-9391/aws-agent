"""
S3 Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (bucket),
IAM permissions, parameter requirements, cost warnings, and deterministic
command builders for Amazon S3.
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

SERVICE_NAME = "s3"
CLI_SERVICE = "s3api"
SERVICE_DESCRIPTION = "Amazon Simple Storage Service"


# ──────────────────────────────────────────────
# Deterministic Command Builders
# ──────────────────────────────────────────────

def build_create_bucket_command(
    bucket_name: str,
    region: str = "ap-south-1",
    acl: Optional[str] = None,
    command_id: Optional[str] = None,
    resource_ref: str = "s3.bucket",
) -> CLICommand:
    """Deterministically construct a create-bucket command with proper LocationConstraint."""
    params: dict[str, Any] = {"bucket": bucket_name}

    # S3 API rule: us-east-1 does NOT accept LocationConstraint; all other regions REQUIRE it.
    if region and region != "us-east-1":
        params["create-bucket-configuration"] = f"LocationConstraint={region}"

    if acl:
        params["acl"] = acl

    cmd = CLICommand(
        command_id=command_id or "cmd-s3-create",
        service="s3api",
        action="create-bucket",
        parameters=params,
        region=region,
        description=f"Create S3 bucket '{bucket_name}' in {region}",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="Location",
    )
    cmd.rollback_command = build_delete_bucket_command(
        bucket_name=bucket_name,
        resource_ref=resource_ref,
    )
    return cmd


def build_head_bucket_command(
    bucket_name: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a head-bucket verification command."""
    return CLICommand(
        command_id=command_id or "cmd-s3-head",
        service="s3api",
        action="head-bucket",
        parameters={"bucket": bucket_name},
        description=f"Verify existence and access to S3 bucket '{bucket_name}'",
        operation_category=OperationCategory.READ_ONLY,
        resource_ref=resource_ref,
    )


def build_delete_bucket_command(
    bucket_name: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-bucket command."""
    return CLICommand(
        command_id=command_id or "cmd-s3-delete",
        service="s3api",
        action="delete-bucket",
        parameters={"bucket": bucket_name},
        description=f"Delete S3 bucket '{bucket_name}'",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_list_buckets_command(command_id: Optional[str] = None) -> CLICommand:
    """Deterministically construct a list-buckets command."""
    return CLICommand(
        command_id=command_id or "cmd-s3-list",
        service="s3api",
        action="list-buckets",
        parameters={},
        description="List all S3 buckets in account",
        operation_category=OperationCategory.READ_ONLY,
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
    """Register the S3 service with the registry."""
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")
    service_def = get_s3_service_definition()
    registry.register_service(service_def)
    logger.info("Registered S3 service")
