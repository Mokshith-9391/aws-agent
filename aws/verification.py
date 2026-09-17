"""
Resource Verification module.

Verifies the actual runtime AWS state of provisioned infrastructure using
explicit resource references, service types, and real describe/head calls.
Does NOT infer service from resource ID suffixes or default unknown types to EC2.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from agent.models import (
    CLICommand,
    LogicalResource,
    OperationCategory,
    VerificationResult,
)
from aws.cli_executor import AWSCLIExecutor

logger = logging.getLogger(__name__)


class ResourceVerifier:
    """Verifies actual live AWS infrastructure state for provisioned logical resources."""

    def __init__(self, executor: Optional[AWSCLIExecutor] = None) -> None:
        self.executor = executor or AWSCLIExecutor()

    def verify_logical_resource(
        self,
        resource: LogicalResource,
        region: str,
        profile: str = "default",
    ) -> VerificationResult:
        """Verify the state of a logical resource using its registered service and type."""
        if not resource.resource_id:
            return VerificationResult(
                resource_ref=resource.resource_ref,
                resource_type=resource.resource_type,
                service=resource.service,
                resource_id="",
                verified=False,
                state="MISSING_ID",
                message="Resource has no AWS resource ID assigned.",
            )

        return self.verify_resource(
            service=resource.service,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            region=region,
            profile=profile,
            resource_ref=resource.resource_ref,
        )

    def verify_resource(
        self,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str,
        profile: str = "default",
        resource_ref: Optional[str] = None,
    ) -> VerificationResult:
        """Verify resource state directly via AWS CLI commands with profile & region."""
        svc = service.lower().strip()
        rtype = resource_type.lower().strip()

        # Route to specific verification strategy based on service & resource_type
        if svc == "ec2" and rtype == "instance":
            return self._verify_ec2_instance(resource_id, region, profile, resource_ref)
        elif svc == "ec2" and rtype == "vpc":
            return self._verify_vpc(resource_id, region, profile, resource_ref)
        elif svc == "ec2" and rtype == "subnet":
            return self._verify_subnet(resource_id, region, profile, resource_ref)
        elif svc == "ec2" and rtype == "security_group":
            return self._verify_security_group(resource_id, region, profile, resource_ref)
        elif svc == "ec2" and rtype in ("internet_gateway", "igw"):
            return self._verify_internet_gateway(resource_id, region, profile, resource_ref)
        elif svc == "ec2" and rtype in ("route_table", "rtb"):
            return self._verify_route_table(resource_id, region, profile, resource_ref)
        elif svc in ("s3", "s3api") and rtype == "bucket":
            return self._verify_s3_bucket(resource_id, region, profile, resource_ref)
        elif svc == "dynamodb" and rtype == "table":
            return self._verify_dynamodb_table(resource_id, region, profile, resource_ref)
        elif svc == "iam" and rtype == "role":
            return self._verify_iam_role(resource_id, region, profile, resource_ref)
        elif svc == "lambda" and rtype == "function":
            return self._verify_lambda_function(resource_id, region, profile, resource_ref)
        elif svc == "rds" and rtype == "db_instance":
            return self._verify_rds_instance(resource_id, region, profile, resource_ref)
        elif svc == "ecs" and rtype == "cluster":
            return self._verify_ecs_cluster(resource_id, region, profile, resource_ref)

        # Critical Fix #16: NEVER default unknown resource types to EC2!
        logger.warning("Unsupported resource type for verification: %s/%s", svc, rtype)
        return VerificationResult(
            resource_ref=resource_ref,
            resource_type=rtype,
            service=svc,
            resource_id=resource_id,
            verified=False,
            state="UNSUPPORTED_TYPE",
            message=f"No automated verification strategy implemented for service '{svc}' and type '{rtype}'.",
        )

    def _verify_ec2_instance(
        self, instance_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ec2",
            action="describe-instances",
            parameters={"instance-ids": [instance_id]},
            description=f"Verify EC2 instance {instance_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if not res.success or not res.parsed_output:
            return VerificationResult(
                resource_ref=resource_ref, resource_type="instance", service="ec2",
                resource_id=instance_id, verified=False, state="ERROR",
                message=f"Describe call failed: {res.error_message}",
            )

        reservations = res.parsed_output.get("Reservations", [])
        if reservations and reservations[0].get("Instances"):
            inst = reservations[0]["Instances"][0]
            state = inst.get("State", {}).get("Name", "unknown")
            verified = state in ("pending", "running")
            return VerificationResult(
                resource_ref=resource_ref, resource_type="instance", service="ec2",
                resource_id=instance_id, verified=verified, state=state,
                details={
                    "InstanceType": inst.get("InstanceType"),
                    "SubnetId": inst.get("SubnetId"),
                    "VpcId": inst.get("VpcId"),
                    "PublicIp": inst.get("PublicIpAddress"),
                },
                message=f"Instance is in '{state}' state.",
            )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="instance", service="ec2",
            resource_id=instance_id, verified=False, state="NOT_FOUND",
            message=f"Instance {instance_id} was not found in describe response.",
        )

    def _verify_s3_bucket(
        self, bucket_name: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="s3api",
            action="head-bucket",
            parameters={"bucket": bucket_name},
            description=f"Verify S3 bucket {bucket_name}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success:
            return VerificationResult(
                resource_ref=resource_ref, resource_type="bucket", service="s3api",
                resource_id=bucket_name, verified=True, state="EXISTS",
                message=f"Bucket '{bucket_name}' verified and accessible.",
            )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="bucket", service="s3api",
            resource_id=bucket_name, verified=False, state="NOT_FOUND",
            message=f"Bucket '{bucket_name}' head check failed: {res.error_message}",
        )

    def _verify_vpc(
        self, vpc_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ec2",
            action="describe-vpcs",
            parameters={"vpc-ids": [vpc_id]},
            description=f"Verify VPC {vpc_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            vpcs = res.parsed_output.get("Vpcs", [])
            if vpcs:
                state = vpcs[0].get("State", "unknown")
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="vpc", service="ec2",
                    resource_id=vpc_id, verified=(state == "available"), state=state,
                    details={"CidrBlock": vpcs[0].get("CidrBlock")},
                    message=f"VPC state is '{state}'.",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="vpc", service="ec2",
            resource_id=vpc_id, verified=False, state="NOT_FOUND",
            message=f"VPC {vpc_id} not found.",
        )

    def _verify_subnet(
        self, subnet_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ec2",
            action="describe-subnets",
            parameters={"subnet-ids": [subnet_id]},
            description=f"Verify Subnet {subnet_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            subnets = res.parsed_output.get("Subnets", [])
            if subnets:
                state = subnets[0].get("State", "unknown")
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="subnet", service="ec2",
                    resource_id=subnet_id, verified=(state == "available"), state=state,
                    details={
                        "VpcId": subnets[0].get("VpcId"),
                        "CidrBlock": subnets[0].get("CidrBlock"),
                        "AvailabilityZone": subnets[0].get("AvailabilityZone"),
                    },
                    message=f"Subnet state is '{state}'.",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="subnet", service="ec2",
            resource_id=subnet_id, verified=False, state="NOT_FOUND",
            message=f"Subnet {subnet_id} not found.",
        )

    def _verify_security_group(
        self, group_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ec2",
            action="describe-security-groups",
            parameters={"group-ids": [group_id]},
            description=f"Verify Security Group {group_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            sgs = res.parsed_output.get("SecurityGroups", [])
            if sgs:
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="security_group", service="ec2",
                    resource_id=group_id, verified=True, state="ACTIVE",
                    details={
                        "GroupName": sgs[0].get("GroupName"),
                        "VpcId": sgs[0].get("VpcId"),
                        "IpPermissions": len(sgs[0].get("IpPermissions", [])),
                    },
                    message=f"Security Group '{sgs[0].get('GroupName')}' verified.",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="security_group", service="ec2",
            resource_id=group_id, verified=False, state="NOT_FOUND",
            message=f"Security Group {group_id} not found.",
        )

    def _verify_internet_gateway(
        self, igw_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ec2",
            action="describe-internet-gateways",
            parameters={"internet-gateway-ids": [igw_id]},
            description=f"Verify Internet Gateway {igw_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            igws = res.parsed_output.get("InternetGateways", [])
            if igws:
                attachments = igws[0].get("Attachments", [])
                attached_vpc = attachments[0].get("VpcId") if attachments else None
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="internet_gateway", service="ec2",
                    resource_id=igw_id, verified=True, state="ATTACHED" if attached_vpc else "DETACHED",
                    details={"AttachedVpc": attached_vpc},
                    message=f"Internet Gateway verified (Attached to {attached_vpc or 'None'}).",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="internet_gateway", service="ec2",
            resource_id=igw_id, verified=False, state="NOT_FOUND",
            message=f"Internet Gateway {igw_id} not found.",
        )

    def _verify_route_table(
        self, rt_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ec2",
            action="describe-route-tables",
            parameters={"route-table-ids": [rt_id]},
            description=f"Verify Route Table {rt_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            rts = res.parsed_output.get("RouteTables", [])
            if rts:
                routes = rts[0].get("Routes", [])
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="route_table", service="ec2",
                    resource_id=rt_id, verified=True, state="ACTIVE",
                    details={"RouteCount": len(routes), "VpcId": rts[0].get("VpcId")},
                    message=f"Route Table verified with {len(routes)} route(s).",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="route_table", service="ec2",
            resource_id=rt_id, verified=False, state="NOT_FOUND",
            message=f"Route Table {rt_id} not found.",
        )

    def _verify_dynamodb_table(
        self, table_name: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="dynamodb",
            action="describe-table",
            parameters={"table-name": table_name},
            description=f"Verify DynamoDB table {table_name}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            tbl = res.parsed_output.get("Table", {})
            status = tbl.get("TableStatus", "unknown")
            return VerificationResult(
                resource_ref=resource_ref, resource_type="table", service="dynamodb",
                resource_id=table_name, verified=status in ("ACTIVE", "CREATING"), state=status,
                details={"ItemCount": tbl.get("ItemCount", 0), "Arn": tbl.get("TableArn")},
                message=f"DynamoDB table status is '{status}'.",
            )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="table", service="dynamodb",
            resource_id=table_name, verified=False, state="NOT_FOUND",
            message=f"Table {table_name} not found.",
        )

    def _verify_iam_role(
        self, role_name: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="iam",
            action="get-role",
            parameters={"role-name": role_name},
            description=f"Verify IAM role {role_name}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            role = res.parsed_output.get("Role", {})
            arn = role.get("Arn", "")
            return VerificationResult(
                resource_ref=resource_ref, resource_type="role", service="iam",
                resource_id=role_name, verified=bool(arn), state="ACTIVE",
                details={"Arn": arn, "RoleId": role.get("RoleId")},
                message=f"IAM role verified: {arn}",
            )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="role", service="iam",
            resource_id=role_name, verified=False, state="NOT_FOUND",
            message=f"IAM role {role_name} not found.",
        )

    def _verify_lambda_function(
        self, func_name: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="lambda",
            action="get-function",
            parameters={"function-name": func_name},
            description=f"Verify Lambda function {func_name}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            conf = res.parsed_output.get("Configuration", {})
            state = conf.get("State", "Active")
            return VerificationResult(
                resource_ref=resource_ref, resource_type="function", service="lambda",
                resource_id=func_name, verified=True, state=state,
                details={"Runtime": conf.get("Runtime"), "FunctionArn": conf.get("FunctionArn")},
                message=f"Lambda function state is '{state}'.",
            )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="function", service="lambda",
            resource_id=func_name, verified=False, state="NOT_FOUND",
            message=f"Lambda function {func_name} not found.",
        )

    def _verify_rds_instance(
        self, db_id: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="rds",
            action="describe-db-instances",
            parameters={"db-instance-identifier": db_id},
            description=f"Verify RDS DB instance {db_id}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            dbs = res.parsed_output.get("DBInstances", [])
            if dbs:
                status = dbs[0].get("DBInstanceStatus", "unknown")
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="db_instance", service="rds",
                    resource_id=db_id, verified=status in ("available", "creating"), state=status,
                    details={"Engine": dbs[0].get("Engine")},
                    message=f"RDS instance status is '{status}'.",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="db_instance", service="rds",
            resource_id=db_id, verified=False, state="NOT_FOUND",
            message=f"RDS instance {db_id} not found.",
        )

    def _verify_ecs_cluster(
        self, cluster_name: str, region: str, profile: str, resource_ref: Optional[str]
    ) -> VerificationResult:
        cmd = CLICommand(
            service="ecs",
            action="describe-clusters",
            parameters={"clusters": [cluster_name]},
            description=f"Verify ECS cluster {cluster_name}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            clusters = res.parsed_output.get("clusters", [])
            if clusters:
                status = clusters[0].get("status", "unknown")
                return VerificationResult(
                    resource_ref=resource_ref, resource_type="cluster", service="ecs",
                    resource_id=cluster_name, verified=status == "ACTIVE", state=status,
                    details={"RegisteredContainerInstancesCount": clusters[0].get("registeredContainerInstancesCount", 0)},
                    message=f"ECS cluster status is '{status}'.",
                )
        return VerificationResult(
            resource_ref=resource_ref, resource_type="cluster", service="ecs",
            resource_id=cluster_name, verified=False, state="NOT_FOUND",
            message=f"ECS cluster {cluster_name} not found.",
        )
