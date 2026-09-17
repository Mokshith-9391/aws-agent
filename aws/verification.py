"""
AWS Resource Verification module.

Verifies the existence and state of AWS resources after provisioning
by executing describe/head commands and inspecting the output.
"""

import logging
from typing import Any

from agent.models import CLICommand, OperationCategory, VerificationResult
from aws.cli_executor import AWSCLIExecutor

logger = logging.getLogger(__name__)


class ResourceVerifier:
    """Verifies AWS resources exist and retrieves their current state."""

    def __init__(self, executor: AWSCLIExecutor) -> None:
        self.executor = executor

    def verify_resource(
        self,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str,
    ) -> VerificationResult:
        """Verify a resource exists and get its state.

        Dispatches to the appropriate verification method based on
        the resource type.

        Args:
            service: AWS service name.
            resource_type: Type of resource (e.g., 'instance', 'VpcId').
            resource_id: The resource identifier.
            region: AWS region.

        Returns:
            VerificationResult with verified status and details.
        """
        # Normalize resource type for lookup
        type_lower = resource_type.lower()

        # Map resource type names to verification methods
        if type_lower in ('instance', 'instanceid'):
            return self._verify_ec2_instance(resource_id, region)
        elif type_lower in ('bucket', 'bucketname'):
            return self._verify_s3_bucket(resource_id, region)
        elif type_lower in ('vpc', 'vpcid'):
            return self._verify_vpc(resource_id, region)
        elif type_lower in ('subnet', 'subnetid'):
            return self._verify_subnet(resource_id, region)
        elif type_lower in ('security_group', 'securitygroup', 'groupid'):
            return self._verify_security_group(resource_id, region)
        elif type_lower in ('internet_gateway', 'internetgateway', 'internetgatewayid'):
            return self._verify_internet_gateway(resource_id, region)
        elif type_lower in ('role', 'rolename', 'rolearn'):
            return self._verify_iam_role(resource_id, region)
        elif type_lower in ('table', 'tablename', 'tablearn'):
            return self._verify_dynamodb_table(resource_id, region)
        elif type_lower in ('route_table', 'routetable', 'routetableid'):
            return self._verify_route_table(resource_id, region)
        else:
            logger.warning(f"No verification strategy for resource type: {resource_type}")
            return VerificationResult(
                resource_type=resource_type,
                resource_id=resource_id,
                verified=False,
                message=f"No verification strategy for resource type: {resource_type}",
            )

    def _verify_ec2_instance(self, instance_id: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='ec2', action='describe-instances',
            parameters={'instance-ids': instance_id},
            description='Verify EC2 instance',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            reservations = res.parsed_output.get('Reservations', [])
            if reservations:
                instances = reservations[0].get('Instances', [])
                if instances:
                    instance = instances[0]
                    state = instance.get('State', {}).get('Name', 'unknown')
                    return VerificationResult(
                        resource_type='instance',
                        resource_id=instance_id,
                        verified=True,
                        state=state,
                        details={"InstanceType": instance.get("InstanceType"),
                                 "PublicIpAddress": instance.get("PublicIpAddress")},
                        message=f"Instance {instance_id} is {state}",
                    )

        return VerificationResult(
            resource_type='instance', resource_id=instance_id,
            verified=False, message=f"Instance not found: {res.error_message or 'unknown error'}",
        )

    def _verify_s3_bucket(self, bucket_name: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='s3api', action='head-bucket',
            parameters={'bucket': bucket_name},
            description='Verify S3 bucket',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success:
            return VerificationResult(
                resource_type='bucket', resource_id=bucket_name,
                verified=True, state="EXISTS",
                message=f"Bucket '{bucket_name}' exists and is accessible",
            )

        return VerificationResult(
            resource_type='bucket', resource_id=bucket_name,
            verified=False, message=f"Bucket verification failed: {res.error_message or 'unknown error'}",
        )

    def _verify_vpc(self, vpc_id: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='ec2', action='describe-vpcs',
            parameters={'vpc-ids': vpc_id},
            description='Verify VPC',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            vpcs = res.parsed_output.get('Vpcs', [])
            if vpcs:
                vpc = vpcs[0]
                state = vpc.get('State', 'unknown')
                return VerificationResult(
                    resource_type='vpc', resource_id=vpc_id,
                    verified=True, state=state,
                    details={"CidrBlock": vpc.get("CidrBlock")},
                    message=f"VPC {vpc_id} is {state}",
                )

        return VerificationResult(
            resource_type='vpc', resource_id=vpc_id,
            verified=False, message=f"VPC not found: {res.error_message or 'unknown error'}",
        )

    def _verify_subnet(self, subnet_id: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='ec2', action='describe-subnets',
            parameters={'subnet-ids': subnet_id},
            description='Verify Subnet',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            subnets = res.parsed_output.get('Subnets', [])
            if subnets:
                subnet = subnets[0]
                state = subnet.get('State', 'unknown')
                return VerificationResult(
                    resource_type='subnet', resource_id=subnet_id,
                    verified=True, state=state,
                    message=f"Subnet {subnet_id} is {state}",
                )

        return VerificationResult(
            resource_type='subnet', resource_id=subnet_id,
            verified=False, message=f"Subnet not found: {res.error_message or 'unknown error'}",
        )

    def _verify_security_group(self, group_id: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='ec2', action='describe-security-groups',
            parameters={'group-ids': group_id},
            description='Verify Security Group',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            sgs = res.parsed_output.get('SecurityGroups', [])
            if sgs:
                return VerificationResult(
                    resource_type='security_group', resource_id=group_id,
                    verified=True, state="EXISTS",
                    details={"GroupName": sgs[0].get("GroupName")},
                    message=f"Security Group {group_id} exists",
                )

        return VerificationResult(
            resource_type='security_group', resource_id=group_id,
            verified=False, message=f"Security Group not found: {res.error_message or 'unknown error'}",
        )

    def _verify_internet_gateway(self, igw_id: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='ec2', action='describe-internet-gateways',
            parameters={'internet-gateway-ids': igw_id},
            description='Verify Internet Gateway',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            igws = res.parsed_output.get('InternetGateways', [])
            if igws:
                return VerificationResult(
                    resource_type='internet_gateway', resource_id=igw_id,
                    verified=True, state="EXISTS",
                    message=f"Internet Gateway {igw_id} exists",
                )

        return VerificationResult(
            resource_type='internet_gateway', resource_id=igw_id,
            verified=False, message=f"Internet Gateway not found: {res.error_message or 'unknown error'}",
        )

    def _verify_iam_role(self, role_name: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='iam', action='get-role',
            parameters={'role-name': role_name},
            description='Verify IAM Role',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            role = res.parsed_output.get('Role', {})
            if role:
                return VerificationResult(
                    resource_type='role', resource_id=role_name,
                    verified=True, state="EXISTS",
                    details={"Arn": role.get("Arn")},
                    message=f"IAM Role '{role_name}' exists",
                )

        return VerificationResult(
            resource_type='role', resource_id=role_name,
            verified=False, message=f"IAM Role not found: {res.error_message or 'unknown error'}",
        )

    def _verify_dynamodb_table(self, table_name: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='dynamodb', action='describe-table',
            parameters={'table-name': table_name},
            description='Verify DynamoDB Table',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            table = res.parsed_output.get('Table', {})
            if table:
                state = table.get('TableStatus', 'unknown')
                return VerificationResult(
                    resource_type='table', resource_id=table_name,
                    verified=True, state=state,
                    message=f"DynamoDB table '{table_name}' is {state}",
                )

        return VerificationResult(
            resource_type='table', resource_id=table_name,
            verified=False, message=f"DynamoDB table not found: {res.error_message or 'unknown error'}",
        )

    def _verify_route_table(self, rt_id: str, region: str) -> VerificationResult:
        cmd = CLICommand(
            service='ec2', action='describe-route-tables',
            parameters={'route-table-ids': rt_id},
            description='Verify Route Table',
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)

        if res.success and res.parsed_output:
            rts = res.parsed_output.get('RouteTables', [])
            if rts:
                return VerificationResult(
                    resource_type='route_table', resource_id=rt_id,
                    verified=True, state="EXISTS",
                    message=f"Route Table {rt_id} exists",
                )

        return VerificationResult(
            resource_type='route_table', resource_id=rt_id,
            verified=False, message=f"Route Table not found: {res.error_message or 'unknown error'}",
        )
