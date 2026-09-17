"""
DynamoDB Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (table),
IAM permissions, parameter requirements, and cost warnings for Amazon DynamoDB.
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

SERVICE_NAME = "dynamodb"
CLI_SERVICE = "dynamodb"
SERVICE_DESCRIPTION = "Amazon DynamoDB"

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
