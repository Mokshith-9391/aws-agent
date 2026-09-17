"""
Safety policy engine for evaluating the safety and risk of AWS provisioning plans.

Checks for dangerous patterns, assesses risk levels, determines whether
explicit confirmation is required, and suggests safer alternatives.
"""

import logging
import re
from typing import Optional

from agent.models import ProvisioningPlan, RiskLevel, OperationCategory

logger = logging.getLogger(__name__)

# Plans with more commands than this require additional review
MAX_RESOURCES_WITHOUT_EXTRA_APPROVAL = 5

# Dangerous patterns in command representations
DANGEROUS_PATTERNS = [
    re.compile(r"delete.*--all", re.I),
    re.compile(r"AdministratorAccess"),
    re.compile(r'"Action"\s*:\s*"\*"'),
    re.compile(r"--disable-security-controls", re.I),
]


class SafetyPolicyEngine:
    """Evaluates provisioning plans for safety and risk."""

    def evaluate_plan(
        self, plan: ProvisioningPlan
    ) -> tuple[bool, list[str], list[str]]:
        """Evaluate a provisioning plan for safety issues.

        Args:
            plan: The plan to evaluate.

        Returns:
            Tuple of (is_safe, warnings, blocking_issues).
        """
        warnings: list[str] = []
        blocking_issues: list[str] = []

        try:
            # Check command count
            if len(plan.commands) > MAX_RESOURCES_WITHOUT_EXTRA_APPROVAL:
                warnings.append(
                    f"Plan contains {len(plan.commands)} commands "
                    f"(>{MAX_RESOURCES_WITHOUT_EXTRA_APPROVAL}). Extra review recommended."
                )

            # Check each command for dangerous patterns
            for command in plan.commands:
                cmd_str = command.to_display_string()
                params_str = str(command.parameters)

                # Check for delete-all patterns
                if "delete" in cmd_str.lower() and "--all" in cmd_str.lower():
                    blocking_issues.append(
                        "Deleting all resources of a type is not allowed."
                    )

                # Check for open ports
                if "0.0.0.0/0" in params_str:
                    if any(
                        x in params_str.lower()
                        for x in ["port 0", "all protocols", "-1"]
                    ):
                        blocking_issues.append(
                            "Opening all ports to 0.0.0.0/0 is extremely dangerous."
                        )
                    else:
                        warnings.append(
                            "Security group rule opens access to 0.0.0.0/0. "
                            "Consider restricting to specific IPs."
                        )

                # Check for admin access or wildcard permissions
                if "AdministratorAccess" in params_str:
                    blocking_issues.append(
                        "Creating IAM resources with AdministratorAccess is not recommended. "
                        "Use least-privilege policies."
                    )

                if '"Action": "*"' in params_str or "'Action': '*'" in params_str:
                    blocking_issues.append(
                        "Wildcard (*) IAM actions are not allowed."
                    )

                # Check for disabling security controls
                if "disable" in cmd_str.lower() and "security" in cmd_str.lower():
                    blocking_issues.append(
                        "Disabling security controls is not allowed."
                    )

            # Check for destructive operations flag
            if plan.destructive_operations:
                warnings.append("Plan contains destructive operations.")

        except Exception as e:
            logger.error(f"Error evaluating plan: {e}")
            blocking_issues.append(f"Error evaluating plan safety: {e}")

        is_safe = len(blocking_issues) == 0
        return is_safe, warnings, blocking_issues

    def assess_risk(self, plan: ProvisioningPlan) -> RiskLevel:
        """Assess the risk level of a provisioning plan.

        Args:
            plan: The plan to assess.

        Returns:
            The assessed RiskLevel.
        """
        try:
            category = plan.operation_category
            is_destructive = plan.destructive_operations

            # CRITICAL: bulk destructive, IAM admin changes
            if is_destructive and len(plan.commands) > 1:
                return RiskLevel.CRITICAL

            for cmd in plan.commands:
                params_str = str(cmd.parameters)
                # IAM create/put operations
                if cmd.service == "iam" and cmd.action in (
                    "create-role", "create-policy", "put-role-policy",
                    "attach-role-policy",
                ):
                    if "AdministratorAccess" in params_str or '"*"' in params_str:
                        return RiskLevel.CRITICAL

                # Broad security group rules
                if (
                    cmd.service == "ec2"
                    and "authorize" in cmd.action
                    and "0.0.0.0/0" in params_str
                ):
                    return RiskLevel.HIGH

            # HIGH: destructive ops, IAM changes
            if is_destructive:
                return RiskLevel.HIGH

            if category == OperationCategory.DESTRUCTIVE:
                return RiskLevel.HIGH

            for cmd in plan.commands:
                if cmd.service == "iam":
                    return RiskLevel.HIGH

            # MEDIUM: write operations (compute, networking)
            if category == OperationCategory.WRITE:
                return RiskLevel.MEDIUM

            # LOW: read-only
            return RiskLevel.LOW

        except Exception as e:
            logger.error(f"Error assessing risk: {e}")
            return RiskLevel.HIGH  # Safe default

    def requires_explicit_confirmation(self, plan: ProvisioningPlan) -> bool:
        """Determine if the plan requires explicit typed confirmation.

        Returns True for destructive operations and high/critical risk.

        Args:
            plan: The plan to check.

        Returns:
            True if explicit confirmation (typing CONFIRM DELETE) is required.
        """
        try:
            risk = self.assess_risk(plan)
            is_destructive = plan.destructive_operations
            is_destructive_category = plan.operation_category == OperationCategory.DESTRUCTIVE

            if risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                return True
            if is_destructive or is_destructive_category:
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking explicit confirmation: {e}")
            return True  # Safe default

    def get_safer_alternative(self, plan: ProvisioningPlan) -> Optional[str]:
        """Suggest a safer alternative for dangerous operations.

        Args:
            plan: The plan to analyze.

        Returns:
            A suggestion string, or None if no suggestion.
        """
        try:
            for cmd in plan.commands:
                params_str = str(cmd.parameters)

                if "0.0.0.0/0" in params_str:
                    return (
                        "Consider restricting the CIDR block from 0.0.0.0/0 "
                        "to your specific IP address or internal network range."
                    )
                if "AdministratorAccess" in params_str:
                    return (
                        "Consider using least-privilege policies with specific "
                        "permissions instead of AdministratorAccess."
                    )
                if "delete" in cmd.action.lower():
                    return (
                        "Consider listing resources first to verify what will be "
                        "deleted before proceeding with the deletion."
                    )

            return None

        except Exception as e:
            logger.error(f"Error getting safer alternative: {e}")
            return None
