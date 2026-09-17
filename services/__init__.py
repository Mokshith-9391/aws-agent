"""
Services package for AWS Provisioning Agent.

Provides service definitions, resource type definitions, and registries
for supported AWS services.
"""

from services.registry import (
    AWSServiceRegistry,
    ResourceTypeDefinition,
    ServiceDefinition,
    create_default_registry,
)
from services.ec2 import register_ec2_service
from services.s3 import register_s3_service
from services.vpc import register_vpc_service
from services.iam import register_iam_service
from services.lambda_service import register_lambda_service
from services.dynamodb import register_dynamodb_service
from services.rds import register_rds_service
from services.ecs import register_ecs_service

__all__ = [
    "AWSServiceRegistry",
    "ResourceTypeDefinition",
    "ServiceDefinition",
    "create_default_registry",
    "register_ec2_service",
    "register_s3_service",
    "register_vpc_service",
    "register_iam_service",
    "register_lambda_service",
    "register_dynamodb_service",
    "register_rds_service",
    "register_ecs_service",
]
