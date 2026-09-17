"""
Authoritative Approval Manager.

Sole backend authority determining human approval requirements for provisioning plans.
Returns strict approval types (AUTO, STANDARD, EXPLICIT_CONFIRMATION) that the UI
must render without independent re-interpretation.
"""

from __future__ import annotations

import logging
from typing import Any

from agent.models import ApprovalType, OperationCategory, ProvisioningPlan, RiskLevel

logger = logging.getLogger(__name__)


class ApprovalManager:
    """Sole authority determining approval requirements for provisioning plans."""

    def determine_approval_requirement(self, plan: ProvisioningPlan) -> dict[str, Any]:
        """Determine the authoritative approval requirement.

        Rules:
        - If any command is DESTRUCTIVE: always EXPLICIT_CONFIRMATION (typed CONFIRM DELETE).
        - If RiskLevel is CRITICAL or HIGH: always EXPLICIT_CONFIRMATION.
        - If RiskLevel is MEDIUM or has WRITE commands: STANDARD (interactive button click).
        - If all commands are strictly READ_ONLY and RiskLevel is LOW: AUTO (executes automatically).

        Args:
            plan: The plan to evaluate.

        Returns:
            Dict containing:
                - requires_approval: bool
                - approval_type: ApprovalType
                - reason: str
        """
        # 1. Check for any destructive command anywhere in the plan
        has_destructive_cmd = any(
            cmd.operation_category == OperationCategory.DESTRUCTIVE
            for cmd in plan.commands
        )
        if plan.destructive_operations or has_destructive_cmd or plan.operation_category == OperationCategory.DESTRUCTIVE:
            return {
                "requires_approval": True,
                "approval_type": ApprovalType.EXPLICIT_CONFIRMATION,
                "reason": "Plan contains destructive operations that permanently alter or delete resources.",
            }

        # 2. Check for CRITICAL or HIGH risk
        if plan.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            return {
                "requires_approval": True,
                "approval_type": ApprovalType.EXPLICIT_CONFIRMATION,
                "reason": f"Plan is assessed as {plan.risk_level.value} risk, requiring explicit confirmation.",
            }

        # 3. Check for WRITE operations or multiple commands
        has_write_cmd = any(
            cmd.operation_category == OperationCategory.WRITE
            for cmd in plan.commands
        )
        if plan.operation_category == OperationCategory.WRITE or has_write_cmd or len(plan.commands) > 5:
            return {
                "requires_approval": True,
                "approval_type": ApprovalType.STANDARD,
                "reason": "Plan contains infrastructure write operations requiring human review.",
            }

        # 4. Purely READ_ONLY operations
        return {
            "requires_approval": False,
            "approval_type": ApprovalType.AUTO,
            "reason": "Read-only operations are auto-approved for execution.",
        }

    def format_approval_request(self, plan: ProvisioningPlan) -> str:
        """Format a provisioning plan for human review in Markdown.

        Args:
            plan: The plan to format.

        Returns:
            Formatted review text.
        """
        approval_info = self.determine_approval_requirement(plan)
        approval_type: ApprovalType = approval_info["approval_type"]

        lines = [
            "### 📋 Provisioning Plan Review (Approval Required)",
            f"**Intent:** {plan.intent}",
            f"**Target AWS Profile:** `{plan.aws_profile}`",
            f"**Target AWS Region:** `{plan.aws_region}`",
            f"**Risk Level:** `{plan.risk_level.value}`",
            f"**Approval Type Required:** `{approval_type.value}`",
        ]

        if approval_type == ApprovalType.EXPLICIT_CONFIRMATION:
            lines.append("⚠️ **DESTRUCTIVE / HIGH RISK**: Requires explicit confirmation (`CONFIRM DELETE`).")

        lines.extend([
            "",
            "**Planned AWS CLI Commands:**",
        ])

        for idx, cmd in enumerate(plan.commands, 1):
            category_badge = f"[{cmd.operation_category.value}]"
            lines.append(f"{idx}. {category_badge} `{cmd.to_display_string(profile=plan.aws_profile, region=plan.aws_region)}`")
            if cmd.description:
                lines.append(f"   _{cmd.description}_")

        if plan.assumptions:
            lines.extend(["", "**Assumptions Made:**"])
            for assumption in plan.assumptions:
                lines.append(f"- {assumption}")

        if plan.cost_warnings:
            lines.extend(["", "**💰 Cost Warnings:**"])
            for warn in plan.cost_warnings:
                lines.append(f"- ⚠️ {warn}")

        return "\n".join(lines)
