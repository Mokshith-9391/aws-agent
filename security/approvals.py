"""
Approval manager for determining approval requirements and formatting
approval requests for human review.
"""

import logging
from typing import Any

from agent.models import ProvisioningPlan, OperationCategory, RiskLevel

logger = logging.getLogger(__name__)


class ApprovalManager:
    """Determines approval requirements for provisioning plans."""

    def determine_approval_requirement(self, plan: ProvisioningPlan) -> dict[str, Any]:
        """Determine what kind of approval is required for a plan.

        Rules:
        - READ_ONLY operations: auto-approved
        - WRITE operations: require standard approval (click Execute)
        - DESTRUCTIVE operations: require explicit confirmation (type CONFIRM DELETE)
        - CRITICAL risk: always require explicit confirmation
        - Plans with >5 commands: require standard approval minimum

        Args:
            plan: The plan to evaluate.

        Returns:
            Dict with requires_approval, approval_type, and reason.
        """
        result: dict[str, Any] = {
            "requires_approval": False,
            "approval_type": "auto",
            "reason": "Read-only operations are auto-approved.",
        }

        try:
            category = plan.operation_category
            risk = plan.risk_level
            is_destructive = plan.destructive_operations

            # READ_ONLY operations: auto-approved
            if category == OperationCategory.READ_ONLY:
                return result

            # CRITICAL risk: always require explicit confirmation
            if risk == RiskLevel.CRITICAL:
                return {
                    "requires_approval": True,
                    "approval_type": "explicit_confirmation",
                    "reason": "Plan involves CRITICAL risk operations.",
                }

            # DESTRUCTIVE operations: require explicit confirmation
            if is_destructive or category == OperationCategory.DESTRUCTIVE:
                return {
                    "requires_approval": True,
                    "approval_type": "explicit_confirmation",
                    "reason": "Plan contains destructive operations.",
                }

            # HIGH risk: require explicit confirmation
            if risk == RiskLevel.HIGH:
                return {
                    "requires_approval": True,
                    "approval_type": "explicit_confirmation",
                    "reason": "Plan has HIGH risk level.",
                }

            # Plans with >5 commands: require standard approval minimum
            if len(plan.commands) > 5:
                return {
                    "requires_approval": True,
                    "approval_type": "standard",
                    "reason": f"Plan contains {len(plan.commands)} commands (>5).",
                }

            # WRITE operations: require standard approval
            if category == OperationCategory.WRITE:
                return {
                    "requires_approval": True,
                    "approval_type": "standard",
                    "reason": "Write operations require approval.",
                }

        except Exception as e:
            logger.error(f"Error determining approval requirement: {e}")
            return {
                "requires_approval": True,
                "approval_type": "explicit_confirmation",
                "reason": f"Error evaluating plan: {e}. Failing safe.",
            }

        return result

    def format_approval_request(self, plan: ProvisioningPlan) -> str:
        """Format a provisioning plan for human review.

        Args:
            plan: The plan to format.

        Returns:
            Formatted markdown string.
        """
        try:
            lines = [
                "## Approval Request",
                "",
                f"**Request:** {plan.user_request}",
                f"**Intent:** {plan.intent}",
                f"**Region:** `{plan.aws_region}`",
                f"**Risk Level:** `{plan.risk_level.value}`",
                f"**Destructive:** {'⚠️ Yes' if plan.destructive_operations else '✅ No'}",
                "",
                "**Commands to Execute:**",
            ]

            if plan.commands:
                for i, cmd in enumerate(plan.commands, 1):
                    lines.append(f"{i}. `{cmd.to_display_string()}`")
                    lines.append(f"   _{cmd.description}_")
            else:
                lines.append("- None")

            lines.append("")

            if plan.assumptions:
                lines.append("**Assumptions:**")
                for a in plan.assumptions:
                    lines.append(f"- {a}")
            else:
                lines.append("**Assumptions:** None")

            if plan.cost_warnings:
                lines.append("")
                lines.append("**💰 Cost Warnings:**")
                for w in plan.cost_warnings:
                    lines.append(f"- ⚠️ {w}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"Error formatting approval request: {e}")
            return "Error formatting approval request."
