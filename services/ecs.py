"""
ECS Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (cluster, task_definition),
IAM permissions, parameter requirements, and cost warnings for Amazon Elastic Container Service (ECS).
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

SERVICE_NAME = "ecs"
CLI_SERVICE = "ecs"
SERVICE_DESCRIPTION = "Amazon Elastic Container Service"

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class ECSClusterParams(BaseModel):
    """Parameter schema for creating an ECS cluster."""
    model_config = ConfigDict(populate_by_name=True)

    cluster_name: str = Field(..., alias="cluster-name", description="Name of the ECS cluster")
    tags: Optional[list[dict[str, str]]] = Field(None, alias="tags", description="List of key-value tag pairs")


class ECSTaskDefinitionParams(BaseModel):
    """Parameter schema for registering an ECS task definition."""
    model_config = ConfigDict(populate_by_name=True)

    family: str = Field(..., alias="family", description="Name of the task definition family")
    container_definitions: list[dict[str, Any]] = Field(
        ...,
        alias="container-definitions",
        description="List of container definitions in JSON format",
    )
    cpu: Optional[str] = Field(None, alias="cpu", description="Number of CPU units used by the task")
    memory: Optional[str] = Field(None, alias="memory", description="Amount of memory (in MiB) used by the task")
    network_mode: Optional[str] = Field(None, alias="network-mode", description="Docker networking mode (e.g., awsvpc, bridge)")
    requires_compatibilities: Optional[list[str]] = Field(
        None,
        alias="requires-compatibilities",
        description="Launch types required (e.g., ['FARGATE'])",
    )
    execution_role_arn: Optional[str] = Field(
        None,
        alias="execution-role-arn",
        description="ARN of the task execution IAM role",
    )
    task_role_arn: Optional[str] = Field(
        None,
        alias="task-role-arn",
        description="ARN of the IAM role that tasks can assume",
    )
    tags: Optional[list[dict[str, str]]] = Field(None, alias="tags", description="List of key-value tag pairs")


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_cluster_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for ECS cluster."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="cluster",
        cli_service=CLI_SERVICE,
        description="Amazon ECS Container Cluster",
        create_action="create-cluster",
        describe_action="describe-clusters",
        delete_action="delete-cluster",
        list_action="list-clusters",
        required_params=["cluster-name"],
        optional_params=["tags", "settings", "capacity-providers"],
        id_field="cluster.clusterArn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ecs:CreateCluster",
            "ecs:DescribeClusters",
            "ecs:DeleteCluster",
            "ecs:ListClusters",
        ],
    )


def create_task_definition_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for ECS task definition."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="task_definition",
        cli_service=CLI_SERVICE,
        description="Amazon ECS Task Definition",
        create_action="register-task-definition",
        describe_action="describe-task-definition",
        delete_action="deregister-task-definition",
        list_action="list-task-definitions",
        required_params=["family", "container-definitions"],
        optional_params=[
            "cpu",
            "memory",
            "network-mode",
            "requires-compatibilities",
            "execution-role-arn",
            "task-role-arn",
            "tags",
        ],
        id_field="taskDefinition.taskDefinitionArn",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning="ECS tasks with Fargate launch type incur charges based on vCPU and memory used.",
        iam_permissions=[
            "ecs:RegisterTaskDefinition",
            "ecs:DescribeTaskDefinition",
            "ecs:DeregisterTaskDefinition",
            "ecs:ListTaskDefinitions",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_ecs_service_definition() -> ServiceDefinition:
    """Build and return the ECS ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-cluster",
            "describe-clusters",
            "delete-cluster",
            "list-clusters",
            "register-task-definition",
            "describe-task-definition",
            "deregister-task-definition",
            "list-task-definitions",
            "run-task",
            "stop-task",
        ],
    )

    service_def.add_resource_type(create_cluster_resource_def())
    service_def.add_resource_type(create_task_definition_resource_def())

    return service_def


def register_ecs_service(registry: AWSServiceRegistry) -> None:
    """
    Register the ECS service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_ecs_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered ECS service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register ECS service: %s", exc, exc_info=True)
        raise
