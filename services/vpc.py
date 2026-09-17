"""
VPC Service Handler for AWS Provisioning Agent.

Provides service metadata, resource type definitions (vpc, subnet, internet_gateway,
route_table, security_group), IAM permissions, parameter requirements, cost
warnings, and deterministic command builders for Amazon Virtual Private Cloud (VPC).
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

SERVICE_NAME = "vpc"
CLI_SERVICE = "ec2"
SERVICE_DESCRIPTION = "Amazon Virtual Private Cloud"


# ──────────────────────────────────────────────
# Deterministic Command Builders
# ──────────────────────────────────────────────

def build_create_vpc_command(
    cidr_block: str = "10.0.0.0/16",
    name_tag: Optional[str] = None,
    command_id: Optional[str] = None,
    resource_ref: str = "vpc.main",
) -> CLICommand:
    """Deterministically construct a create-vpc command."""
    params: dict[str, Any] = {"cidr-block": cidr_block}
    if name_tag:
        params["tag-specifications"] = [
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ]

    cmd = CLICommand(
        command_id=command_id or "cmd-vpc-create",
        service="ec2",
        action="create-vpc",
        parameters=params,
        description=f"Create VPC with CIDR {cidr_block}",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="Vpc.VpcId",
    )
    cmd.rollback_command = CLICommand(
        service="ec2",
        action="delete-vpc",
        parameters={"vpc-id": f"{{{{{resource_ref}.id}}}}"},
        description="Delete created VPC on rollback",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )
    return cmd


def build_create_subnet_command(
    vpc_id: str,
    cidr_block: str = "10.0.1.0/24",
    availability_zone: Optional[str] = None,
    name_tag: Optional[str] = None,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
    resource_ref: str = "subnet.public",
) -> CLICommand:
    """Deterministically construct a create-subnet command."""
    params: dict[str, Any] = {
        "vpc-id": vpc_id,
        "cidr-block": cidr_block,
    }
    if availability_zone:
        params["availability-zone"] = availability_zone
    if name_tag:
        params["tag-specifications"] = [
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ]

    cmd = CLICommand(
        command_id=command_id or "cmd-subnet-create",
        service="ec2",
        action="create-subnet",
        parameters=params,
        description=f"Create Subnet {cidr_block} in VPC {vpc_id}",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        depends_on=depends_on or [],
        output_key="Subnet.SubnetId",
    )
    cmd.rollback_command = CLICommand(
        service="ec2",
        action="delete-subnet",
        parameters={"subnet-id": f"{{{{{resource_ref}.id}}}}"},
        description="Delete created Subnet on rollback",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )
    return cmd


def build_create_igw_command(
    name_tag: Optional[str] = None,
    command_id: Optional[str] = None,
    resource_ref: str = "internet_gateway.main",
) -> CLICommand:
    """Deterministically construct a create-internet-gateway command."""
    params: dict[str, Any] = {}
    if name_tag:
        params["tag-specifications"] = [
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ]

    cmd = CLICommand(
        command_id=command_id or "cmd-igw-create",
        service="ec2",
        action="create-internet-gateway",
        parameters=params,
        description="Create Internet Gateway",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        output_key="InternetGateway.InternetGatewayId",
    )
    cmd.rollback_command = CLICommand(
        service="ec2",
        action="delete-internet-gateway",
        parameters={"internet-gateway-id": f"{{{{{resource_ref}.id}}}}"},
        description="Delete created Internet Gateway on rollback",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )
    return cmd


def build_attach_igw_command(
    igw_id: str,
    vpc_id: str,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
) -> CLICommand:
    """Deterministically construct an attach-internet-gateway command."""
    return CLICommand(
        command_id=command_id or "cmd-igw-attach",
        service="ec2",
        action="attach-internet-gateway",
        parameters={"internet-gateway-id": igw_id, "vpc-id": vpc_id},
        description=f"Attach Internet Gateway {igw_id} to VPC {vpc_id}",
        operation_category=OperationCategory.WRITE,
        depends_on=depends_on or [],
    )


def build_create_route_table_command(
    vpc_id: str,
    name_tag: Optional[str] = None,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
    resource_ref: str = "route_table.public",
) -> CLICommand:
    """Deterministically construct a create-route-table command."""
    params: dict[str, Any] = {"vpc-id": vpc_id}
    if name_tag:
        params["tag-specifications"] = [
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ]

    cmd = CLICommand(
        command_id=command_id or "cmd-rt-create",
        service="ec2",
        action="create-route-table",
        parameters=params,
        description=f"Create Route Table in VPC {vpc_id}",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        depends_on=depends_on or [],
        output_key="RouteTable.RouteTableId",
    )
    cmd.rollback_command = CLICommand(
        service="ec2",
        action="delete-route-table",
        parameters={"route-table-ids": f"{{{{{resource_ref}.id}}}}"},
        description="Delete created Route Table on rollback",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )
    return cmd


def build_create_route_command(
    route_table_id: str,
    destination_cidr: str = "0.0.0.0/0",
    gateway_id: Optional[str] = None,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
) -> CLICommand:
    """Deterministically construct a create-route command."""
    params: dict[str, Any] = {
        "route-table-id": route_table_id,
        "destination-cidr-block": destination_cidr,
    }
    if gateway_id:
        params["gateway-id"] = gateway_id

    return CLICommand(
        command_id=command_id or "cmd-route-create",
        service="ec2",
        action="create-route",
        parameters=params,
        description=f"Add route {destination_cidr} to Route Table {route_table_id}",
        operation_category=OperationCategory.WRITE,
        depends_on=depends_on or [],
    )


def build_associate_route_table_command(
    route_table_id: str,
    subnet_id: str,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
) -> CLICommand:
    """Deterministically construct an associate-route-table command."""
    return CLICommand(
        command_id=command_id or "cmd-rt-associate",
        service="ec2",
        action="associate-route-table",
        parameters={"route-table-id": route_table_id, "subnet-id": subnet_id},
        description=f"Associate Route Table {route_table_id} with Subnet {subnet_id}",
        operation_category=OperationCategory.WRITE,
        depends_on=depends_on or [],
    )


def build_security_group_command(
    group_name: str,
    description: str,
    vpc_id: Optional[str] = None,
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
    resource_ref: str = "security_group.web",
) -> CLICommand:
    """Deterministically construct a create-security-group command."""
    params: dict[str, Any] = {
        "group-name": group_name,
        "description": description,
    }
    if vpc_id:
        params["vpc-id"] = vpc_id

    cmd = CLICommand(
        command_id=command_id or "cmd-sg-create",
        service="ec2",
        action="create-security-group",
        parameters=params,
        description=f"Create Security Group '{group_name}'",
        operation_category=OperationCategory.WRITE,
        resource_ref=resource_ref,
        depends_on=depends_on or [],
        output_key="GroupId",
    )
    cmd.rollback_command = CLICommand(
        service="ec2",
        action="delete-security-group",
        parameters={"group-id": f"{{{{{resource_ref}.id}}}}"},
        description="Delete created Security Group on rollback",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )
    return cmd


def build_ingress_command(
    group_id: str,
    protocol: str = "tcp",
    port: int = 80,
    cidr: str = "0.0.0.0/0",
    command_id: Optional[str] = None,
    depends_on: Optional[list[str]] = None,
) -> CLICommand:
    """Deterministically construct an authorize-security-group-ingress command."""
    return CLICommand(
        command_id=command_id or "cmd-sg-ingress",
        service="ec2",
        action="authorize-security-group-ingress",
        parameters={
            "group-id": group_id,
            "protocol": protocol,
            "port": str(port),
            "cidr": cidr,
        },
        description=f"Authorize ingress on port {port} ({protocol}) from {cidr}",
        operation_category=OperationCategory.WRITE,
        depends_on=depends_on or [],
    )


def build_delete_vpc_command(
    vpc_id: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-vpc command."""
    return CLICommand(
        command_id=command_id or "cmd-vpc-delete",
        service="ec2",
        action="delete-vpc",
        parameters={"vpc-id": vpc_id},
        description=f"Delete VPC {vpc_id}",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_delete_subnet_command(
    subnet_id: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-subnet command."""
    return CLICommand(
        command_id=command_id or "cmd-subnet-delete",
        service="ec2",
        action="delete-subnet",
        parameters={"subnet-id": subnet_id},
        description=f"Delete Subnet {subnet_id}",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_delete_security_group_command(
    group_id: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-security-group command."""
    return CLICommand(
        command_id=command_id or "cmd-sg-delete",
        service="ec2",
        action="delete-security-group",
        parameters={"group-id": group_id},
        description=f"Delete Security Group {group_id}",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_delete_igw_command(
    igw_id: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-internet-gateway command."""
    return CLICommand(
        command_id=command_id or "cmd-igw-delete",
        service="ec2",
        action="delete-internet-gateway",
        parameters={"internet-gateway-id": igw_id},
        description=f"Delete Internet Gateway {igw_id}",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


def build_delete_route_table_command(
    route_table_id: str,
    command_id: Optional[str] = None,
    resource_ref: Optional[str] = None,
) -> CLICommand:
    """Deterministically construct a delete-route-table command."""
    return CLICommand(
        command_id=command_id or "cmd-rt-delete",
        service="ec2",
        action="delete-route-table",
        parameters={"route-table-id": route_table_id},
        description=f"Delete Route Table {route_table_id}",
        operation_category=OperationCategory.DESTRUCTIVE,
        resource_ref=resource_ref,
    )


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
        description="VPC Subnet",
        create_action="create-subnet",
        describe_action="describe-subnets",
        delete_action="delete-subnet",
        list_action="describe-subnets",
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
        description="VPC Internet Gateway",
        create_action="create-internet-gateway",
        describe_action="describe-internet-gateways",
        delete_action="delete-internet-gateway",
        list_action="describe-internet-gateways",
        required_params=[],
        optional_params=["tag-specifications"],
        id_field="InternetGateway.InternetGatewayId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateInternetGateway",
            "ec2:AttachInternetGateway",
            "ec2:DetachInternetGateway",
            "ec2:DeleteInternetGateway",
            "ec2:DescribeInternetGateways",
        ],
    )


def create_route_table_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Route Table."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="route_table",
        cli_service=CLI_SERVICE,
        description="VPC Route Table",
        create_action="create-route-table",
        describe_action="describe-route-tables",
        delete_action="delete-route-table",
        list_action="describe-route-tables",
        required_params=["vpc-id"],
        optional_params=["tag-specifications"],
        id_field="RouteTable.RouteTableId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateRouteTable",
            "ec2:CreateRoute",
            "ec2:AssociateRouteTable",
            "ec2:DescribeRouteTables",
            "ec2:DeleteRouteTable",
        ],
    )


def create_security_group_resource_def() -> ResourceTypeDefinition:
    """Create ResourceTypeDefinition for Security Group."""
    return ResourceTypeDefinition(
        service=SERVICE_NAME,
        resource_type="security_group",
        cli_service=CLI_SERVICE,
        description="EC2 Security Group (Virtual Firewall)",
        create_action="create-security-group",
        describe_action="describe-security-groups",
        delete_action="delete-security-group",
        list_action="describe-security-groups",
        required_params=["group-name", "description"],
        optional_params=["vpc-id", "tag-specifications"],
        id_field="GroupId",
        name_tag_key="Name",
        supports_tags=True,
        cost_warning=None,
        iam_permissions=[
            "ec2:CreateSecurityGroup",
            "ec2:DeleteSecurityGroup",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:DescribeSecurityGroups",
        ],
    )


def get_vpc_service_definition() -> ServiceDefinition:
    """Build and return the VPC ServiceDefinition."""
    service_def = ServiceDefinition(
        service_name=SERVICE_NAME,
        cli_service=CLI_SERVICE,
        description=SERVICE_DESCRIPTION,
        supported_operations=[
            "create-vpc", "describe-vpcs", "delete-vpc",
            "create-subnet", "describe-subnets", "delete-subnet",
            "create-internet-gateway", "attach-internet-gateway",
            "detach-internet-gateway", "delete-internet-gateway",
            "describe-internet-gateways",
            "create-route-table", "describe-route-tables", "delete-route-table",
            "associate-route-table", "create-route", "delete-route",
            "create-security-group", "describe-security-groups", "delete-security-group",
            "authorize-security-group-ingress", "revoke-security-group-ingress",
        ],
    )
    service_def.add_resource_type(create_vpc_resource_def())
    service_def.add_resource_type(create_subnet_resource_def())
    service_def.add_resource_type(create_internet_gateway_resource_def())
    service_def.add_resource_type(create_route_table_resource_def())
    service_def.add_resource_type(create_security_group_resource_def())
    return service_def


def register_vpc_service(registry: AWSServiceRegistry) -> None:
    """Register the VPC service with the registry."""
    if not isinstance(registry, AWSServiceRegistry):
        raise TypeError(f"Expected AWSServiceRegistry, got {type(registry).__name__}")
    service_def = get_vpc_service_definition()
    registry.register_service(service_def)
    logger.info("Registered VPC service")
