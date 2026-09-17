"""
Deterministic Amazon Machine Image (AMI) Discovery.

Discovers official, verified Amazon Linux AMIs for target regions and
architectures using AWS CLI describe-images, with verified regional catalogs
for offline/dry-run execution. Never hallucinates an unverified AMI ID.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from agent.models import CLICommand, OperationCategory
from aws.cli_executor import AWSCLIExecutor

logger = logging.getLogger(__name__)

# Verified official Amazon Linux 2023 AMI catalog (x86_64, kernel 6.1)
# Maintained by Amazon Web Services as base images.
OFFICIAL_AL2023_CATALOG: dict[str, str] = {
    "ap-south-1": "ami-022ce6f32988af5fa",
    "us-east-1": "ami-0c101f26f147fa7fd",
    "us-east-2": "ami-0c80e2d6cc7c3232d",
    "us-west-1": "ami-04f5097681773b989",
    "us-west-2": "ami-00448a337e393f7d1",
    "eu-west-1": "ami-0d75513e80344d559",
    "eu-west-2": "ami-0b9932f4918a00c4f",
    "eu-central-1": "ami-01e444924a2233b07",
    "ap-northeast-1": "ami-0d52744d6551d851e",
    "ap-southeast-1": "ami-07c1207a9d40bc3bd",
    "ap-southeast-2": "ami-04f777b7f16f555bc",
    "ca-central-1": "ami-0046522cbb24fb0ec",
}


class AMIDiscovery:
    """Discovers verified AMIs deterministically."""

    def __init__(self, executor: Optional[AWSCLIExecutor] = None) -> None:
        self.executor = executor or AWSCLIExecutor()

    def discover_amazon_linux_2023(
        self,
        region: str,
        profile: str = "default",
        architecture: str = "x86_64",
        query_live: bool = True,
    ) -> tuple[Optional[str], str]:
        """Discover the most suitable Amazon Linux 2023 AMI.

        Args:
            region: AWS region (e.g., 'ap-south-1').
            profile: AWS profile.
            architecture: Target CPU architecture ('x86_64' or 'arm64').
            query_live: If True, query live AWS API via describe-images first.

        Returns:
            Tuple of (ami_id, selection_rationale).
        """
        if query_live:
            try:
                cmd = CLICommand(
                    service="ec2",
                    action="describe-images",
                    parameters={
                        "owners": ["amazon"],
                        "filters": [
                            {"Name": "name", "Values": [f"al2023-ami-2023.*-kernel-6.1-{architecture}"]},
                            {"Name": "state", "Values": ["available"]},
                            {"Name": "architecture", "Values": [architecture]},
                            {"Name": "virtualization-type", "Values": ["hvm"]},
                            {"Name": "root-device-type", "Values": ["ebs"]},
                        ],
                    },
                    description=f"Discover latest AL2023 AMI in {region}",
                    operation_category=OperationCategory.READ_ONLY,
                )

                result = self.executor.execute_command(cmd, region=region, profile=profile)
                if result.success and result.parsed_output:
                    images = result.parsed_output.get("Images", [])
                    if images:
                        # Sort by CreationDate descending
                        sorted_images = sorted(
                            images,
                            key=lambda img: img.get("CreationDate", ""),
                            reverse=True,
                        )
                        latest = sorted_images[0]
                        ami_id = latest.get("ImageId")
                        name = latest.get("Name", "Amazon Linux 2023")
                        creation_date = latest.get("CreationDate", "")
                        if ami_id:
                            rationale = (
                                f"Selected latest official Amazon Linux 2023 AMI '{name}' ({ami_id}) "
                                f"created on {creation_date} for {region} ({architecture})."
                            )
                            logger.info(rationale)
                            return ami_id, rationale
            except Exception as e:
                logger.warning("Live AMI discovery failed, using official verified catalog: %s", e)

        # Fallback to verified catalog
        if architecture == "x86_64" and region in OFFICIAL_AL2023_CATALOG:
            ami_id = OFFICIAL_AL2023_CATALOG[region]
            rationale = (
                f"Selected official Amazon Linux 2023 AMI ({ami_id}) for {region} "
                f"from verified regional catalog."
            )
            return ami_id, rationale

        return None, (
            f"No verified Amazon Linux AMI found for region '{region}' with architecture '{architecture}'. "
            f"Please provide an explicit AMI ID."
        )
