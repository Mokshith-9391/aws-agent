"""
DynamoDB Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (table),
IAM permissions, parameter requirements, and cost warnings for Amazon DynamoDB.
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

SERVICE_NAME = "dynamodb"
CLI_SERVICE = "dynamodb"
SERVICE_DESCRIPTION = "Amazon DynamoDB"

# ──────────────────────────────────────────────
# Deterministic Command Builders
# ──────────────────────────────────────────────

def build_create_table_command(
    table_name: str,
    key_schema: list[dict[str, str]],
    attribute_definitions: list[dict[str, str]],
    billing_mode: str = "PAY_PER_REQUEST",
    tags: Optional[list[dict[str, str]]] = None,
    command_id: Optional[str] = None,
    resource_ref: str = "dynamodb.table",
) -> CLICommand:
    """Deterministically construct a create-table command."""
    params: dict[str, Any] = {
        "table-name": table_name,
        "key-schema": key_schema,
        "attribute-definitions": attribute_definitions,
        "billing-mode": billing_mode,
    }
    if tags:
        params["tags"] = tags

    cmd = CLICommand(
        command_id=command_id or "cmd-ddb-create-table",
        service="dynamodb",
        action="create-table",
        parameters=params,
        description=f"Create DynamoDB table '{table_name}'",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="TableDescription.TableArn",
    )
    cmd.rollback_command = build_delete_table_command(
        table_name=table_name,
        resource_ref=resource_ref,
    )
    return cmd


def build_delete_table_command(
    table_name: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-table command."""
    return CLICommand(
        command_id=command_id or "cmd-ddb-delete-table",
        service="dynamodb",
        action="delete-table",
        parameters={"table-name": table_name},
        description=f"Delete DynamoDB table '{table_name}'",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_describe_table_command(
    table_name: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a describe-table verification command."""
    return CLICommand(
        command_id=command_id or "cmd-ddb-describe-table",
        service="dynamodb",
        action="describe-table",
        parameters={"table-name": table_name},
        description=f"Verify DynamoDB table '{table_name}'",
        operation_category=OperationCategory.READ_ONLY,
        resource_ref=resource_ref,
    )

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class DynamoDBTableParams(BaseModel):
    """Parameter schema for creating a DynamoDB table."""
    model_config = ConfigDict(populate_by_name=True)

    table_name: str = Field(..., alias="table-name", description="Name of the DynamoDB table")
    attribute_definitions: list[dict[str, Any]] = Field(
        ...,
        alias="attribute-definitions",
        description="List of attribute definitions (AttributeName, AttributeType)",
    )
    key_schema: list[dict[str, Any]] = Field(
        ...,
        alias="key-schema",
        description="List of key schema elements (AttributeName, KeyType)",
    )
    billing_mode: str = Field(
        ...,
        alias="billing-mode",
        description="Billing mode: PAY_PER_REQUEST or PROVISIONED",
    )
    provisioned_throughput: Optional[dict[str, Any]] = Field(
        None,
        alias="provisioned-throughput",
        description="Required if billing-mode is PROVISIONED (ReadCapacityUnits, WriteCapacityUnits)",
    )
    tags: Optional[list[dict[str, str]]] = Field(
        None,
        alias="tags",
        description="List of key-value tag pairs",
    )


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_table_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for DynamoDB table."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="table",
        cli_service=CLI_SERVICE,
        description="Amazon DynamoDB NoSQL Database Table",
        create_action="create-table",
        describe_action="describe-table",
        delete_action="delete-table",
        list_action="list-tables",
        required_params=[
            "table-name",
            "attribute-definitions",
            "key-schema",
            "billing-mode",
        ],
        optional_params=["provisioned-throughput", "tags"],
        id_field="TableDescription.TableArn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=(
            "DynamoDB tables with provisioned capacity incur charges. "
            "PAY_PER_REQUEST billing mode is recommended for unpredictable workloads."
        ),
        iam_permissions=[
            "dynamodb:CreateTable",
            "dynamodb:DescribeTable",
            "dynamodb:DeleteTable",
            "dynamodb:ListTables",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_dynamodb_service_definition() -> ServiceDefinition:
    """Build and return the DynamoDB ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-table",
            "describe-table",
            "delete-table",
            "list-tables",
            "put-item",
            "get-item",
            "delete-item",
            "update-item",
            "scan",
            "query",
        ],
    )

    service_def.add_resource_type(create_table_resource_def())
    return service_def


def register_dynamodb_service(registry: AWSServiceRegistry) -> None:
    """
    Register the DynamoDB service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_dynamodb_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered DynamoDB service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register DynamoDB service: %s", exc, exc_info=True)
        raise
