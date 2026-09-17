"""
AWS Identity Manager module.

Provides AWS CLI health checks, credential validation, and caller
identity retrieval. Used at startup and for ongoing connection status.
"""

import json
import logging
import subprocess
from typing import Optional

from agent.models import AWSIdentity

logger = logging.getLogger(__name__)


class AWSIdentityManager:
    """Manages AWS caller identity and CLI health checks."""

    def check_cli_installed(self) -> tuple[bool, str]:
        """Check if AWS CLI is installed and return its version.

        Returns:
            Tuple of (installed: bool, version_string: str).
        """
        try:
            result = subprocess.run(
                ['aws', '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=15,
            )
            if result.returncode == 0:
                # AWS CLI version can be in stdout or stderr depending on version
                version_str = (result.stdout.strip() or result.stderr.strip())
                # Extract just the version portion
                version = version_str.split('\n')[0].strip() if version_str else "unknown"
                return True, version
            return False, f"Failed with return code {result.returncode}: {result.stderr.strip()}"
        except FileNotFoundError:
            return False, "AWS CLI not found in PATH. Install from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        except subprocess.TimeoutExpired:
            return False, "AWS CLI version check timed out"
        except Exception as e:
            return False, f"Unexpected error: {e}"

    def get_caller_identity(self, profile: str, region: str) -> AWSIdentity:
        """Retrieve caller identity using aws sts get-caller-identity.

        Args:
            profile: AWS CLI profile name.
            region: AWS region.

        Returns:
            AWSIdentity with account, ARN, and credential status.
        """
        try:
            args = ['aws', 'sts', 'get-caller-identity', '--output', 'json']
            if profile and profile != "default":
                args.extend(['--profile', profile])
            if region:
                args.extend(['--region', region])

            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                timeout=15,
            )

            if result.returncode != 0:
                error_msg = result.stderr.strip()
                logger.error(f"Failed to get caller identity: {error_msg}")
                return AWSIdentity(
                    region=region,
                    profile=profile,
                    credentials_valid=False,
                )

            data = json.loads(result.stdout)
            return AWSIdentity(
                account_id=data.get("Account", ""),
                arn=data.get("Arn", ""),
                user_id=data.get("UserId", ""),
                region=region,
                profile=profile,
                credentials_valid=True,
                cli_installed=True,
            )

        except subprocess.TimeoutExpired:
            logger.error("Timeout getting caller identity")
            return AWSIdentity(region=region, profile=profile, credentials_valid=False)
        except json.JSONDecodeError:
            logger.error("Failed to parse caller identity JSON")
            return AWSIdentity(region=region, profile=profile, credentials_valid=False)
        except Exception as e:
            logger.error(f"Error getting caller identity: {e}")
            return AWSIdentity(region=region, profile=profile, credentials_valid=False)

    def health_check(self, profile: str, region: str) -> AWSIdentity:
        """Perform a full health check: CLI installed + valid credentials.

        Args:
            profile: AWS CLI profile name.
            region: AWS region.

        Returns:
            AWSIdentity with complete health status.
        """
        # Check CLI installation
        installed, version = self.check_cli_installed()

        if not installed:
            logger.error(f"AWS CLI health check failed: {version}")
            return AWSIdentity(
                region=region,
                profile=profile,
                cli_installed=False,
                cli_version=version,
                credentials_valid=False,
            )

        logger.info(f"AWS CLI detected: {version}")

        # Get caller identity
        identity = self.get_caller_identity(profile, region)
        identity.cli_installed = True
        identity.cli_version = version

        if identity.credentials_valid:
            logger.info(
                f"AWS identity verified: account={identity.display_account_id}, "
                f"arn={identity.arn}"
            )
        else:
            logger.warning("AWS credentials are not valid")

        return identity
