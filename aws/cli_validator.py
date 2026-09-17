"""
CLI Command Validator module.

Ensures AWS CLI commands meet security guidelines, required formats,
and authoritative deterministic classification.
The LLM is NEVER trusted for operation categories.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from agent.models import CLICommand, OperationCategory
from aws.cli_executor import ALLOWED_ACTIONS, ALLOWED_SERVICES

logger = logging.getLogger(__name__)

# Deterministic prefixes for operation categories
READ_ONLY_PREFIXES = (
    "describe-", "list-", "get-", "head-", "check-", "lookup-", "select-", "scan", "query"
)

DESTRUCTIVE_PREFIXES = (
    "delete-", "terminate-", "remove-", "revoke-", "deregister-",
    "detach-", "disassociate-", "release-", "purge-", "drop-", "destroy-"
)

# Explicit action overrides where prefix alone is ambiguous
EXPLICIT_CATEGORY_OVERRIDES: dict[tuple[str, str], OperationCategory] = {
    ("s3", "rb"): OperationCategory.DESTRUCTIVE,
    ("s3", "rm"): OperationCategory.DESTRUCTIVE,
    ("s3", "mb"): OperationCategory.WRITE,
    ("s3", "cp"): OperationCategory.WRITE,
    ("s3", "mv"): OperationCategory.WRITE,
    ("s3", "sync"): OperationCategory.WRITE,
    ("s3", "ls"): OperationCategory.READ_ONLY,
    ("s3api", "delete-bucket"): OperationCategory.DESTRUCTIVE,
    ("s3api", "delete-object"): OperationCategory.DESTRUCTIVE,
    ("s3api", "head-bucket"): OperationCategory.READ_ONLY,
    ("s3api", "head-object"): OperationCategory.READ_ONLY,
    ("sts", "get-caller-identity"): OperationCategory.READ_ONLY,
    ("ec2", "stop-instances"): OperationCategory.WRITE,
    ("ec2", "start-instances"): OperationCategory.WRITE,
    ("ec2", "reboot-instances"): OperationCategory.WRITE,
}


def classify_aws_action(service: str, action: str) -> OperationCategory:
    """Deterministically classify an AWS CLI service and action.

    This function is the sole authoritative source of truth for operation classification.
    The LLM's classification must never override this logic.
    """
    service_norm = service.lower().strip()
    action_norm = action.lower().strip()

    # 1. Check explicit overrides
    override = EXPLICIT_CATEGORY_OVERRIDES.get((service_norm, action_norm))
    if override:
        return override

    # 2. Check destructive prefixes
    if any(action_norm.startswith(p) for p in DESTRUCTIVE_PREFIXES):
        return OperationCategory.DESTRUCTIVE

    # 3. Check read-only prefixes
    if any(action_norm.startswith(p) for p in READ_ONLY_PREFIXES):
        return OperationCategory.READ_ONLY

    # 4. Default to WRITE
    return OperationCategory.WRITE


class CLICommandValidator:
    """Validates parameters, formatting, safety, and deterministic classification of CLICommands."""

    def __init__(self) -> None:
        self.cidr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$")
        self.region_regex = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
        self.ami_regex = re.compile(r"^ami-[a-f0-9]{8,17}$")
        self.vpc_regex = re.compile(r"^vpc-[a-f0-9]{8,17}$")
        self.subnet_regex = re.compile(r"^subnet-[a-f0-9]{8,17}$")
        self.sg_regex = re.compile(r"^sg-[a-f0-9]{8,17}$")
        self.igw_regex = re.compile(r"^igw-[a-f0-9]{8,17}$")
        self.rt_regex = re.compile(r"^rtb-[a-f0-9]{8,17}$")
        self.instance_type_regex = re.compile(r"^[a-z0-9]+\.[a-z0-9]+$")
        self.s3_bucket_regex = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")

    def classify_operation(self, service: str, action: str) -> OperationCategory:
        """Expose centralized deterministic classification."""
        return classify_aws_action(service, action)

    def validate_command(self, cmd: CLICommand) -> tuple[bool, list[str]]:
        """Validate a command for security, allowlists, and parameter semantics.

        Enforces deterministic operation category: if the command's
        operation_category differs from the deterministic classification,
        it corrects the category and raises a validation warning.
        """
        issues: list[str] = []

        # ── 1. Authoritative Category Check ────────────────────────
        deterministic_category = self.classify_operation(cmd.service, cmd.action)
        if cmd.operation_category != deterministic_category:
            logger.warning(
                "Command '%s %s' had LLM-declared category '%s', overriding to authoritative '%s'",
                cmd.service, cmd.action, cmd.operation_category, deterministic_category
            )
            # Never allow downgrading a destructive command to WRITE
            cmd.operation_category = deterministic_category

        # ── 2. Allowlist Checks ────────────────────────────────────
        if cmd.service not in ALLOWED_SERVICES:
            issues.append(f"Service '{cmd.service}' not in allowlist.")
            return False, issues

        allowed = ALLOWED_ACTIONS.get(cmd.service, set())
        if cmd.action not in allowed:
            issues.append(f"Action '{cmd.action}' not in allowlist for service '{cmd.service}'.")
            return False, issues

        if not cmd.parameters:
            return len(issues) == 0, issues

        # ── 3. Parameter Safety & Semantic Validations ─────────────
        for key, val in cmd.parameters.items():
            # Check key for shell metacharacters
            if re.search(r"[;|&`$\n\r]", key):
                issues.append(f"Parameter key '{key}' contains illegal shell metacharacters.")

            # Validate string values
            if isinstance(val, str):
                val_str = val.strip()

                # Check for command injection attempts
                if re.search(r"[;|&`\n\r]", val_str) or "$(" in val_str or "||" in val_str or "&&" in val_str:
                    # Allow placeholder syntax {{...}}
                    if not (val_str.startswith("{{") and val_str.endswith("}}")):
                        issues.append(f"Parameter value for '{key}' contains command injection patterns.")

                # If it's an unresolved or resolved template reference, skip strict regex
                if val_str.startswith(("{{", "$")):
                    continue

                # Format & Semantic checks
                if key in ("cidr", "cidr-block"):
                    if not self.cidr_regex.match(val_str):
                        issues.append(f"Invalid CIDR block format: {val_str}")

                elif key == "region":
                    if not self.region_regex.match(val_str):
                        issues.append(f"Invalid AWS region format: {val_str}")

                elif key == "image-id":
                    if not self.ami_regex.match(val_str):
                        issues.append(f"Invalid AMI ID format: {val_str}")

                elif key == "vpc-id":
                    if not self.vpc_regex.match(val_str):
                        issues.append(f"Invalid VPC ID format: {val_str}")

                elif key == "subnet-id":
                    if not self.subnet_regex.match(val_str):
                        issues.append(f"Invalid Subnet ID format: {val_str}")

                elif key in ("group-id", "security-group-ids"):
                    # Could be comma-separated or single
                    for sg_item in val_str.split(","):
                        sg_item = sg_item.strip()
                        if sg_item and not sg_item.startswith(("{{", "$")):
                            if not self.sg_regex.match(sg_item):
                                issues.append(f"Invalid Security Group ID format: {sg_item}")

                elif key == "instance-type":
                    if not self.instance_type_regex.match(val_str):
                        issues.append(f"Invalid instance type format: {val_str}")

                elif key == "bucket":
                    if not self.s3_bucket_regex.match(val_str):
                        issues.append(f"Invalid S3 bucket name format: {val_str}")

                elif key == "port":
                    try:
                        port_num = int(val_str)
                        if not 0 <= port_num <= 65535:
                            issues.append(f"Port number out of range (0-65535): {port_num}")
                    except ValueError:
                        issues.append(f"Invalid port number format: {val_str}")

                elif key == "protocol":
                    if val_str.lower() not in ("tcp", "udp", "icmp", "all", "-1"):
                        issues.append(f"Unsupported IP protocol: {val_str}")

            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and not item.startswith(("{{", "$")):
                        if key in ("security-group-ids", "group-ids"):
                            if not self.sg_regex.match(item.strip()):
                                issues.append(f"Invalid Security Group ID in list: {item}")
                        elif key == "subnet-ids":
                            if not self.subnet_regex.match(item.strip()):
                                issues.append(f"Invalid Subnet ID in list: {item}")

        return len(issues) == 0, issues
