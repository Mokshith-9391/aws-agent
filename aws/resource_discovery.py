"""
AWS Resource Discovery module.

Discovers existing AWS resources for context-aware provisioning.
Allows the agent to reuse existing infrastructure and avoid duplicates.
"""

import logging
from typing import Any, Optional

from agent.models import CLICommand, OperationCategory
from aws.cli_executor import AWSCLIExecutor

logger = logging.getLogger(__name__)


class ResourceDiscovery:
    """Discovers existing AWS resources for context-aware planning."""

    def __init__(self, executor: AWSCLIExecutor) -> None:
        self.executor = executor

    def discover_vpcs(self, region: str) -> list[dict[str, Any]]:
        """List all VPCs in the region."""
        cmd = CLICommand(
            service='ec2', action='describe-vpcs', parameters={},
            description='Discover VPCs', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            return res.parsed_output.get('Vpcs', [])
        return []

    def discover_subnets(self, region: str, vpc_id: Optional[str] = None) -> list[dict[str, Any]]:
        """List subnets, optionally filtered by VPC ID."""
        params: dict[str, Any] = {}
        if vpc_id:
            params['filters'] = f"Name=vpc-id,Values={vpc_id}"

        cmd = CLICommand(
            service='ec2', action='describe-subnets', parameters=params,
            description='Discover subnets', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            return res.parsed_output.get('Subnets', [])
        return []

    def discover_security_groups(self, region: str, vpc_id: Optional[str] = None) -> list[dict[str, Any]]:
        """List security groups, optionally filtered by VPC ID."""
        params: dict[str, Any] = {}
        if vpc_id:
            params['filters'] = f"Name=vpc-id,Values={vpc_id}"

        cmd = CLICommand(
            service='ec2', action='describe-security-groups', parameters=params,
            description='Discover security groups', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            return res.parsed_output.get('SecurityGroups', [])
        return []

    def discover_key_pairs(self, region: str) -> list[dict[str, Any]]:
        """List all EC2 key pairs in the region."""
        cmd = CLICommand(
            service='ec2', action='describe-key-pairs', parameters={},
            description='Discover key pairs', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            return res.parsed_output.get('KeyPairs', [])
        return []

    def discover_default_vpc(self, region: str) -> Optional[dict[str, Any]]:
        """Find the default VPC in a region, if any."""
        cmd = CLICommand(
            service='ec2', action='describe-vpcs',
            parameters={'filters': "Name=isDefault,Values=true"},
            description='Find default VPC', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            vpcs = res.parsed_output.get('Vpcs', [])
            if vpcs:
                return vpcs[0]
        return None

    def discover_internet_gateways(self, region: str, vpc_id: Optional[str] = None) -> list[dict[str, Any]]:
        """List internet gateways, optionally filtered by attached VPC ID."""
        params: dict[str, Any] = {}
        if vpc_id:
            params['filters'] = f"Name=attachment.vpc-id,Values={vpc_id}"

        cmd = CLICommand(
            service='ec2', action='describe-internet-gateways', parameters=params,
            description='Discover internet gateways', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            return res.parsed_output.get('InternetGateways', [])
        return []

    def discover_route_tables(self, region: str, vpc_id: Optional[str] = None) -> list[dict[str, Any]]:
        """List route tables, optionally filtered by VPC ID."""
        params: dict[str, Any] = {}
        if vpc_id:
            params['filters'] = f"Name=vpc-id,Values={vpc_id}"

        cmd = CLICommand(
            service='ec2', action='describe-route-tables', parameters=params,
            description='Discover route tables', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region)
        if res.success and res.parsed_output:
            return res.parsed_output.get('RouteTables', [])
        return []

    def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if an S3 bucket exists and is accessible."""
        cmd = CLICommand(
            service='s3api', action='head-bucket',
            parameters={'bucket': bucket_name},
            description='Check bucket existence', operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, 'us-east-1')
        return res.success

    def check_resource_exists(
        self, service: str, resource_type: str, identifier: str, region: str
    ) -> bool:
        """Check if a specific resource exists using the ResourceVerifier."""
        from aws.verification import ResourceVerifier

        verifier = ResourceVerifier(self.executor)
        result = verifier.verify_resource(service, resource_type, identifier, region)
        return result.verified
