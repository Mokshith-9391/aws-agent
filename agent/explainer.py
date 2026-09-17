"""
Explanation and Response Generator.

Generates detailed human-readable explanations of what the agent did,
including educational content when learning mode is enabled.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from agent.llm_client import LLMClient
from agent.models import (
    ExecutionResult,
    ExecutionStatus,
    ProvisioningPlan,
)
from agent.prompts import (
    build_error_analysis_prompt,
    build_educational_prompt,
    build_explanation_prompt,
)

logger = logging.getLogger(__name__)


class Explainer:
    """
    Generates detailed explanations and educational content
    for AWS operations performed by the agent.
    """

    def __init__(self, llm_client: LLMClient) -> None:
        self._llm = llm_client

    def generate_explanation(
        self,
        plan: ProvisioningPlan,
        result: ExecutionResult,
        learning_mode: bool = False,
    ) -> str:
        """Generate a detailed explanation of the execution.

        Args:
            plan: The provisioning plan that was executed.
            result: The execution results.
            learning_mode: Whether to include educational content.

        Returns:
            Formatted markdown explanation.
        """
        try:
            # Build plan summary
            plan_summary = self._build_plan_summary(plan)
            exec_results = self._build_execution_summary(result)
            verification = self._build_verification_summary(result)

            prompt = build_explanation_prompt(
                user_request=plan.user_request,
                plan_summary=plan_summary,
                execution_results=exec_results,
                verification_results=verification,
            )

            explanation = self._llm.generate(
                system_prompt=(
                    "You are an AWS expert providing clear explanations. "
                    "Format your response in clean markdown. Be thorough but concise."
                ),
                user_prompt=prompt,
                temperature=0.3,
            )

            return explanation

        except Exception as e:
            logger.error(f"LLM explanation generation failed: {e}")
            return self._generate_fallback_explanation(plan, result)

    def generate_educational_content(
        self,
        plan: ProvisioningPlan,
    ) -> str:
        """Generate educational content about the operation.

        Args:
            plan: The provisioning plan.

        Returns:
            Educational markdown content.
        """
        try:
            resources_desc = "\n".join(
                f"- {r.service}/{r.resource_type}: {r.resource_name or 'auto-named'}"
                for r in plan.resources
            )

            prompt = build_educational_prompt(
                operation_description=plan.intent,
                resources=resources_desc,
            )

            content = self._llm.generate(
                system_prompt=(
                    "You are an AWS educator. Provide clear, beginner-friendly "
                    "explanations that are also technically accurate. "
                    "Format in clean markdown."
                ),
                user_prompt=prompt,
                temperature=0.3,
            )
            return content

        except Exception as e:
            logger.error(f"Educational content generation failed: {e}")
            return self._generate_fallback_educational(plan)

    def analyze_error(
        self,
        command_display: str,
        error: str,
        exit_code: int,
    ) -> str:
        """Analyze an AWS CLI error and provide a helpful explanation.

        Args:
            command_display: The command that failed.
            error: Error output.
            exit_code: Exit code.

        Returns:
            Error analysis markdown.
        """
        try:
            prompt = build_error_analysis_prompt(
                command=command_display,
                error=error,
                exit_code=exit_code,
            )
            analysis = self._llm.generate(
                system_prompt="You are an AWS troubleshooting expert. Be specific and actionable.",
                user_prompt=prompt,
                temperature=0.2,
            )
            return analysis
        except Exception as e:
            logger.error(f"Error analysis generation failed: {e}")
            return f"**Error Analysis**\n\nCommand failed with exit code {exit_code}.\n\n**Error:**\n```\n{error}\n```"

    def _build_plan_summary(self, plan: ProvisioningPlan) -> str:
        """Build a text summary of the plan."""
        lines = [
            f"Intent: {plan.intent}",
            f"Operation: {plan.operation_type.value}",
            f"Category: {plan.operation_category.value}",
            f"Region: {plan.aws_region}",
            f"Risk: {plan.risk_level.value}",
            f"Resources: {len(plan.resources)}",
            f"Commands: {len(plan.commands)}",
        ]
        if plan.assumptions:
            lines.append(f"Assumptions: {', '.join(plan.assumptions)}")
        if plan.cost_warnings:
            lines.append(f"Cost Warnings: {', '.join(plan.cost_warnings)}")
        return "\n".join(lines)

    def _build_execution_summary(self, result: ExecutionResult) -> str:
        """Build a text summary of execution results."""
        lines = [
            f"Status: {result.status.value}",
            f"Total Commands: {result.total_commands}",
            f"Successful: {result.successful_commands}",
            f"Failed: {result.failed_commands}",
            f"Duration: {result.duration_seconds:.1f}s",
        ]
        if result.created_resources:
            lines.append("Created Resources:")
            for rtype, rid in result.created_resources.items():
                lines.append(f"  - {rtype}: {rid}")
        if result.failed_resources:
            lines.append(f"Failed Resources: {', '.join(result.failed_resources)}")

        for cr in result.command_results:
            status = "✅" if cr.success else "❌"
            lines.append(f"\n{status} {cr.command_display}")
            if cr.success and cr.resource_ids:
                for k, v in cr.resource_ids.items():
                    lines.append(f"   → {k}: {v}")
            if not cr.success and cr.error_message:
                lines.append(f"   Error: {cr.error_message}")

        return "\n".join(lines)

    def _build_verification_summary(self, result: ExecutionResult) -> str:
        """Build a text summary of verification results."""
        if not result.verification_results:
            return "No verification performed"

        lines = []
        for vr in result.verification_results:
            status = "✅ Verified" if vr.verified else "❌ Not Verified"
            lines.append(f"{status}: {vr.resource_type} ({vr.resource_id})")
            if vr.state:
                lines.append(f"  State: {vr.state}")
            if vr.message:
                lines.append(f"  {vr.message}")
        return "\n".join(lines)

    def _generate_fallback_explanation(
        self, plan: ProvisioningPlan, result: ExecutionResult
    ) -> str:
        """Generate a simple explanation without the LLM."""
        status_emoji = {
            ExecutionStatus.SUCCESS: "✅",
            ExecutionStatus.PARTIAL_SUCCESS: "⚠️",
            ExecutionStatus.FAILED: "❌",
            ExecutionStatus.DRY_RUN: "🔍",
            ExecutionStatus.CANCELLED: "🚫",
        }
        emoji = status_emoji.get(result.status, "ℹ️")

        lines = [
            f"## {emoji} Execution Result: {result.status.value}",
            "",
            f"**Request:** {plan.user_request}",
            f"**Intent:** {plan.intent}",
            f"**Region:** {plan.aws_region}",
            "",
        ]

        if result.created_resources:
            lines.append("### Created Resources")
            for rtype, rid in result.created_resources.items():
                lines.append(f"- **{rtype}:** `{rid}`")
            lines.append("")

        if result.failed_resources:
            lines.append("### Failed Resources")
            for r in result.failed_resources:
                lines.append(f"- {r}")
            lines.append("")

        lines.append("### Commands Executed")
        for cr in result.command_results:
            status = "✅" if cr.success else "❌"
            lines.append(f"{status} `{cr.command_display}`")
            if not cr.success and cr.error_message:
                lines.append(f"  > Error: {cr.error_message}")

        return "\n".join(lines)

    def _generate_fallback_educational(self, plan: ProvisioningPlan) -> str:
        """Generate basic educational content without the LLM."""
        lines = [
            "## 📚 Learning Notes",
            "",
            f"**Operation:** {plan.intent}",
            "",
            "### Resources Involved",
        ]
        for r in plan.resources:
            lines.append(f"- **{r.service.upper()} {r.resource_type}**: {r.resource_name or 'auto-named'}")

        if plan.cost_warnings:
            lines.append("\n### 💰 Cost Considerations")
            for w in plan.cost_warnings:
                lines.append(f"- {w}")

        if plan.educational_notes:
            lines.append("\n### 📖 Notes")
            for note in plan.educational_notes:
                lines.append(f"- {note}")

        return "\n".join(lines)
