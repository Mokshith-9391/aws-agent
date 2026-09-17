"""
Lambda Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (function),
IAM permissions, parameter requirements, and cost warnings for AWS Lambda.
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

SERVICE_NAME = "lambda"
CLI_SERVICE = "lambda"
SERVICE_DESCRIPTION = "AWS Lambda"

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class LambdaFunctionParams(BaseModel):
    """Parameter schema for creating a Lambda function."""
    model_config = ConfigDict(populate_by_name=True)

    function_name: str = Field(..., alias="function-name", description="Name of the Lambda function")
    runtime: str = Field(..., alias="runtime", description="Runtime environment (e.g., python3.11, nodejs18.x)")
    role: str = Field(..., alias="role", description="ARN of the IAM execution role")
    handler: str = Field(..., alias="handler", description="Function entrypoint handler (e.g., index.handler)")
    zip_file: Optional[str] = Field(None, alias="zip-file", description="Path to zip deployment package, e.g. fileb://function.zip")
    description: Optional[str] = Field(None, alias="description", description="Description of the function")
    timeout: Optional[int] = Field(None, alias="timeout", description="Function execution timeout in seconds")
    memory_size: Optional[int] = Field(None, alias="memory-size", description="Amount of memory in MB")
    environment: Optional[dict[str, Any]] = Field(None, alias="environment", description="Environment variables configuration")


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_function_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Lambda function."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="function",
        cli_service=CLI_SERVICE,
        description="AWS Lambda Serverless Function",
        create_action="create-function",
        describe_action="get-function",
        delete_action="delete-function",
        list_action="list-functions",
        required_params=["function-name", "runtime", "role", "handler"],
        optional_params=[
            "zip-file",
            "description",
            "timeout",
            "memory-size",
            "environment",
        ],
        id_field="FunctionArn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning="Lambda functions incur charges based on invocation count and duration.",
        iam_permissions=[
            "lambda:CreateFunction",
            "lambda:GetFunction",
            "lambda:DeleteFunction",
            "lambda:InvokeFunction",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_lambda_service_definition() -> ServiceDefinition:
    """Build and return the Lambda ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-function",
            "get-function",
            "delete-function",
            "list-functions",
            "invoke",
            "update-function-code",
            "update-function-configuration",
        ],
    )

    service_def.add_resource_type(create_function_resource_def())
    return service_def


def register_lambda_service(registry: AWSServiceRegistry) -> None:
    """
    Register the Lambda service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_lambda_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered Lambda service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register Lambda service: %s", exc, exc_info=True)
        raise
