"""
VPC Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (vpc, subnet, internet_gateway,
route_table, security_group), IAM permissions, parameter requirements, and cost
warnings for Amazon Virtual Private Cloud (VPC).
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

SERVICE_NAME = "vpc"
CLI_SERVICE = "ec2"
SERVICE_DESCRIPTION = "Amazon Virtual Private Cloud"

# ──────────────────────────────────────────────
# Pydantic Parameter Models
# ──────────────────────────────────────────────

class VPCParams(BaseModel):
    """Parameter schema for creating a VPC."""
    model_config = ConfigDict(populate_by_name=True)

    cidr_block: str = Field(..., alias="cidr-block", description="IPv4 network range for the VPC in CIDR notation")
    tag_specifications: Optional[list[dict[str, Any]]] = Field(None, alias="tag-specifications", description="Resource tags specification")
    amazon_provided_ipv6_cidr_block: Optional[bool] = Field(None, alias="amazon-provided-ipv6-cidr-block", description="Requests an Amazon-provided IPv6 CIDR block")


class SubnetParams(BaseModel):
    """Parameter schema for creating a Subnet."""
    model_config = ConfigDict(populate_by_name=True)

    vpc_id: str = Field(..., alias="vpc-id", description="ID of the VPC to create subnet in")
    cidr_block: str = Field(..., alias="cidr-block", description="IPv4 network range for the subnet in CIDR notation")
    availability_zone: Optional[str] = Field(None, alias="availability-zone", description="Availability Zone for the subnet")
    tag_specifications: Optional[list[dict[str, Any]]] = Field(None, alias="tag-specifications", description="Resource tags specification")


class InternetGatewayParams(BaseModel):
    """Parameter schema for Internet Gateway operations."""
    model_config = ConfigDict(populate_by_name=True)

    internet_gateway_id: Optional[str] = Field(None, alias="internet-gateway-id", description="ID of the Internet Gateway (required for delete)")
    tag_specifications: Optional[list[dict[str, Any]]] = Field(None, alias="tag-specifications", description="Resource tags specification")


class RouteTableParams(BaseModel):
    """Parameter schema for creating a Route Table."""
    model_config = ConfigDict(populate_by_name=True)

    vpc_id: str = Field(..., alias="vpc-id", description="ID of the VPC to create the route table in")
    tag_specifications: Optional[list[dict[str, Any]]] = Field(None, alias="tag-specifications", description="Resource tags specification")


class SecurityGroupParams(BaseModel):
    """Parameter schema for creating a Security Group."""
    model_config = ConfigDict(populate_by_name=True)

    group_name: str = Field(..., alias="group-name", description="Name of the security group")
    description: str = Field(..., alias="description", description="Description of the security group")
    vpc_id: str = Field(..., alias="vpc-id", description="ID of the VPC for the security group")
    tag_specifications: Optional[list[dict[str, Any]]] = Field(None, alias="tag-specifications", description="Resource tags specification")


# ──────────────────────────────────────────────
# Resource Type Definitions
# ──────────────────────────────────────────────

def create_vpc_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for VPC."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="vpc",
        cli_service=CLI_SERVICE,
        description="Amazon Virtual Private Cloud (VPC)",
        create_action="create-vpc",
        describe_action="describe-vpcs",
        delete_action="delete-vpc",
        list_action="describe-vpcs",
        required_params=["cidr-block"],
        optional_params=["tag-specifications", "amazon-provided-ipv6-cidr-block"],
        id_field="Vpc.VpcId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateVpc",
            "ec2:DescribeVpcs",
            "ec2:DeleteVpc",
        ],
    )


def create_subnet_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Subnet."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="subnet",
        cli_service=CLI_SERVICE,
        description="Amazon VPC Subnet",
        create_action="create-subnet",
        describe_action="describe-subnets",
        delete_action="delete-subnet",
        list_action=None,
        required_params=["vpc-id", "cidr-block"],
        optional_params=["availability-zone", "tag-specifications"],
        id_field="Subnet.SubnetId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateSubnet",
            "ec2:DescribeSubnets",
            "ec2:DeleteSubnet",
        ],
    )


def create_internet_gateway_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Internet Gateway."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="internet_gateway",
        cli_service=CLI_SERVICE,
        description="Amazon VPC Internet Gateway",
        create_action="create-internet-gateway",
        describe_action="describe-internet-gateways",
        delete_action="delete-internet-gateway",
        list_action=None,
        required_params=["internet-gateway-id"],
        optional_params=["tag-specifications"],
        id_field="InternetGateway.InternetGatewayId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateInternetGateway",
            "ec2:DescribeInternetGateways",
            "ec2:DeleteInternetGateway",
            "ec2:AttachInternetGateway",
            "ec2:DetachInternetGateway",
        ],
    )


def create_route_table_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Route Table."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="route_table",
        cli_service=CLI_SERVICE,
        description="Amazon VPC Route Table",
        create_action="create-route-table",
        describe_action="describe-route-tables",
        delete_action="delete-route-table",
        list_action=None,
        required_params=["vpc-id"],
        optional_params=["tag-specifications"],
        id_field="RouteTable.RouteTableId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateRouteTable",
            "ec2:DescribeRouteTables",
            "ec2:DeleteRouteTable",
            "ec2:CreateRoute",
        ],
    )


def create_security_group_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Security Group."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="security_group",
        cli_service=CLI_SERVICE,
        description="Amazon VPC Security Group",
        create_action="create-security-group",
        describe_action="describe-security-groups",
        delete_action="delete-security-group",
        list_action=None,
        required_params=["group-name", "description", "vpc-id"],
        optional_params=["tag-specifications"],
        id_field="GroupId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateSecurityGroup",
            "ec2:DeleteSecurityGroup",
            "ec2:AuthorizeSecurityGroupIngress",
        ],
    )


# ──────────────────────────────────────────────
# Service Definition & Registration
# ──────────────────────────────────────────────

def get_vpc_service_definition() -> ServiceDefinition:
    """Build and return the VPC ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-vpc",
            "describe-vpcs",
            "delete-vpc",
            "create-subnet",
            "describe-subnets",
            "delete-subnet",
            "create-internet-gateway",
            "describe-internet-gateways",
            "delete-internet-gateway",
            "attach-internet-gateway",
            "detach-internet-gateway",
            "create-route-table",
            "describe-route-tables",
            "delete-route-table",
            "create-route",
            "create-security-group",
            "describe-security-groups",
            "delete-security-group",
            "authorize-security-group-ingress",
            "revoke-security-group-ingress",
        ],
    )

    service_def.add_resource_type(create_vpc_resource_def())
    service_def.add_resource_type(create_subnet_resource_def())
    service_def.add_resource_type(create_internet_gateway_resource_def())
    service_def.add_resource_type(create_route_table_resource_def())
    service_def.add_resource_type(create_security_group_resource_def())

    return service_def


def register_vpc_service(registry: AWSServiceRegistry) -> None:
    """
    Register the VPC service and its resource types with the service registry.

    Args:
        registry: Target AWSServiceRegistry instance.

    Raises:
        TypeError: If registry is not an instance of AWSServiceRegistry.
    """
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")

    try:
        service_def = get_vpc_service_definition()
        registry.register_service(service_def)
        logger.info(
            "Registered VPC service with %d resource types: %s",
            len(service_def.resource_types),
            list(service_def.resource_types.keys()),
        )
    except Exception as exc:
        logger.error("Failed to register VPC service: %s", exc, exc_info=True)
        raise
