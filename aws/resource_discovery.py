"""
AWS Resource Discovery and Idempotency Evaluation module.

Discovers existing AWS resources with explicit profile and region propagation,
evaluating whether existing resources can be safely reused (EXISTS_AND_REUSABLE),
are incompatible (EXISTS_BUT_INCOMPATIBLE), require clarification (AMBIGUOUS),
or are missing (NOT_FOUND).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from agent.models import (
    CLICommand,
    DiscoveryOutcome,
    OperationCategory,
    ResourceOwnership,
)
from aws.cli_executor import AWSCLIExecutor

logger = logging.getLogger(__name__)


class ResourceDiscovery:
    """Discovers existing AWS resources and assesses reusability for context-aware planning."""

    def __init__(self, executor: Optional[AWSCLIExecutor] = None) -> None:
        self.executor = executor or AWSCLIExecutor()

    def discover_vpcs(self, region: str, profile: str = "default") -> list[dict[str, Any]]:
        """List all VPCs in the specified region and profile."""
        cmd = CLICommand(
            service="ec2",
            action="describe-vpcs",
            parameters={},
            description="Discover all VPCs in region",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            return res.parsed_output.get("Vpcs", [])
        return []

    def discover_default_vpc(
        self, region: str, profile: str = "default"
    ) -> tuple[DiscoveryOutcome, Optional[dict[str, Any]], str]:
        """Find the default VPC in a region and evaluate its availability.

        Returns:
            Tuple of (DiscoveryOutcome, vpc_dict_or_None, rationale_message).
        """
        cmd = CLICommand(
            service="ec2",
            action="describe-vpcs",
            parameters={"filters": [{"Name": "isDefault", "Values": ["true"]}]},
            description="Find default VPC in region",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)

        if not res.success:
            return DiscoveryOutcome.DISCOVERY_FAILED, None, f"Discovery failed: {res.error_message}"

        vpcs = res.parsed_output.get("Vpcs", []) if res.parsed_output else []
        if len(vpcs) == 1:
            vpc = vpcs[0]
            vpc_id = vpc.get("VpcId", "")
            state = vpc.get("State", "")
            if state == "available":
                return (
                    DiscoveryOutcome.EXISTS_AND_REUSABLE,
                    vpc,
                    f"Default VPC {vpc_id} ({vpc.get('CidrBlock', '')}) is available and reusable.",
                )
            else:
                return (
                    DiscoveryOutcome.EXISTS_BUT_INCOMPATIBLE,
                    vpc,
                    f"Default VPC {vpc_id} is in state '{state}' (not available).",
                )
        elif len(vpcs) > 1:
            return (
                DiscoveryOutcome.AMBIGUOUS,
                None,
                f"Multiple default VPCs found in region ({len(vpcs)}). User selection required.",
            )

        return DiscoveryOutcome.NOT_FOUND, None, f"No default VPC found in region {region}."

    def discover_subnets(
        self, region: str, vpc_id: Optional[str] = None, profile: str = "default"
    ) -> list[dict[str, Any]]:
        """List subnets in a region, optionally filtered by VPC ID."""
        params: dict[str, Any] = {}
        if vpc_id:
            params["filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

        cmd = CLICommand(
            service="ec2",
            action="describe-subnets",
            parameters=params,
            description=f"Discover subnets in {vpc_id or region}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            return res.parsed_output.get("Subnets", [])
        return []

    def discover_security_groups(
        self, region: str, vpc_id: Optional[str] = None, profile: str = "default"
    ) -> list[dict[str, Any]]:
        """List security groups, optionally filtered by VPC ID."""
        params: dict[str, Any] = {}
        if vpc_id:
            params["filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

        cmd = CLICommand(
            service="ec2",
            action="describe-security-groups",
            parameters=params,
            description=f"Discover security groups in {vpc_id or region}",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            return res.parsed_output.get("SecurityGroups", [])
        return []

    def discover_key_pairs(
        self, region: str, profile: str = "default"
    ) -> list[dict[str, Any]]:
        """List all EC2 key pairs in the region."""
        cmd = CLICommand(
            service="ec2",
            action="describe-key-pairs",
            parameters={},
            description="Discover key pairs in region",
            operation_category=OperationCategory.READ_ONLY,
        )
        res = self.executor.execute_command(cmd, region=region, profile=profile)
        if res.success and res.parsed_output:
            return res.parsed_output.get("KeyPairs", [])
        return []

    def check_bucket_exists(
        self, bucket_name: str, profile: str = "default"
    ) -> tuple[DiscoveryOutcome, str]:
        """Check if an S3 bucket already exists."""
        cmd = CLICommand(
            service="s3api",
            action="head-bucket",
            parameters={"bucket": bucket_name},
            description=f"Check if bucket '{bucket_name}' exists",
            operation_category=OperationCategory.READ_ONLY,
        )
        # S3 head-bucket can use us-east-1 endpoint or default
        res = self.executor.execute_command(cmd, region="us-east-1", profile=profile)
        if res.success:
            return DiscoveryOutcome.EXISTS_AND_REUSABLE, f"Bucket '{bucket_name}' exists and is accessible."
        if res.exit_code in (254, 255) and "404" in res.stderr:
            return DiscoveryOutcome.NOT_FOUND, f"Bucket '{bucket_name}' does not exist (available to create)."
        if "403" in res.stderr or "Forbidden" in res.stderr:
            return DiscoveryOutcome.EXISTS_BUT_INCOMPATIBLE, f"Bucket '{bucket_name}' exists but is owned by another account."
        return DiscoveryOutcome.DISCOVERY_FAILED, f"Could not verify bucket: {res.error_message or res.stderr}"
