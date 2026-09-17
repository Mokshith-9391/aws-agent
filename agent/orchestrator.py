"""
Agent Orchestrator.

The central coordinator that manages the complete lifecycle of a user request:
parse → plan → validate → approve → execute → verify → explain.

This is the main entry point for the agent logic, called by the Streamlit UI.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from agent.explainer import Explainer
from agent.llm_client import LLMClient, create_llm_client
from agent.models import (
    AgentResponse,
    ApprovalStatus,
    CLICommand,
    CommandResult,
    ConversationMessage,
    ExecutionHistoryEntry,
    ExecutionResult,
    ExecutionStatus,
    OperationCategory,
    OperationType,
    ProvisioningPlan,
    VerificationResult,
)
from agent.parser import RequestParser
from agent.planner import Planner
from aws.cli_executor import AWSCLIExecutor
from aws.cli_validator import CLICommandValidator
from aws.identity import AWSIdentityManager
from aws.resource_discovery import ResourceDiscovery
from aws.verification import ResourceVerifier
from config.settings import Settings, get_settings
from history.execution_store import ExecutionStore
from security.approvals import ApprovalManager
from security.policy import SafetyPolicyEngine
from security.sanitizer import OutputSanitizer
from services.registry import AWSServiceRegistry, create_default_registry

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Orchestrates the complete agent workflow.

    Manages the pipeline from user request to final explanation,
    coordinating between all subsystems.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        """Initialize the orchestrator with all subsystems.

        Args:
            settings: Application settings. Uses global if not provided.
        """
        self._settings = settings or get_settings()
        self._initialized = False
        self._init_error: Optional[str] = None

        # Subsystem references (initialized lazily or on init)
        self._llm_client: Optional[LLMClient] = None
        self._parser = RequestParser()
        self._planner: Optional[Planner] = None
        self._explainer: Optional[Explainer] = None
        self._executor = AWSCLIExecutor()
        self._validator = CLICommandValidator()
        self._identity_manager = AWSIdentityManager()
        self._verifier = ResourceVerifier(self._executor)
        self._discovery = ResourceDiscovery(self._executor)
        self._policy_engine = SafetyPolicyEngine()
        self._approval_manager = ApprovalManager()
        self._sanitizer = OutputSanitizer()
        self._history_store = ExecutionStore()
        self._registry: Optional[AWSServiceRegistry] = None

        # Session state
        self._conversation_history: list[dict] = []
        self._session_resources: dict[str, str] = {}

    def initialize(self) -> tuple[bool, str]:
        """Initialize the orchestrator and all subsystems.

        Returns:
            Tuple of (success, message).
        """
        try:
            # Initialize service registry
            self._registry = create_default_registry()

            # Initialize LLM client
            self._llm_client = create_llm_client(self._settings)
            if not self._llm_client.is_available():
                return False, "LLM provider is not available. Check your API key configuration."

            # Initialize planner and explainer
            self._planner = Planner(self._llm_client, self._registry)
            self._explainer = Explainer(self._llm_client)

            self._initialized = True
            logger.info("Agent orchestrator initialized successfully")
            return True, "Agent initialized successfully"

        except Exception as e:
            self._init_error = str(e)
            logger.error(f"Orchestrator initialization failed: {e}", exc_info=True)
            return False, f"Initialization failed: {e}"

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def process_request(
        self,
        user_request: str,
        region: str,
        profile: str = "default",
        dry_run: bool = True,
        learning_mode: bool = False,
        aws_account_id: str = "Unknown",
    ) -> AgentResponse:
        """Process a user request through the complete agent pipeline.

        This is the main entry point called by the Streamlit UI.

        Args:
            user_request: Natural-language user request.
            region: Target AWS region.
            profile: AWS profile name.
            dry_run: Whether to run in dry-run mode.
            learning_mode: Whether to include educational content.
            aws_account_id: AWS account ID for context.

        Returns:
            AgentResponse with the plan, results, and explanations.
        """
        if not self._initialized:
            return AgentResponse(
                message="⚠️ Agent is not initialized. Please check configuration.",
                warnings=["Agent not initialized"],
            )

        logger.info(f"Processing request: {user_request[:100]}... (dry_run={dry_run})")

        # ── Step 1: Validate Input ──────────────────────────────
        is_valid, issues = self._parser.validate_input(user_request)
        if not is_valid:
            return AgentResponse(
                message="❌ " + "\n".join(issues),
                warnings=issues,
            )

        # Sanitize input
        sanitized_request = self._parser.sanitize_for_llm(user_request)

        # Extract quick hints for context
        hints = self._parser.extract_hints(sanitized_request)
        if hints.get("detected_region"):
            region = hints["detected_region"]

        # ── Step 2: Discover Existing Resources (if needed) ─────
        existing_resources_text = "None discovered"
        if hints.get("mentions_existing_resource") or hints.get("detected_operation") == "create":
            existing_resources_text = self._discover_existing_resources(region)

        # Add conversation context
        self._conversation_history.append({
            "role": "user",
            "content": sanitized_request,
        })

        # ── Step 3: Generate Plan ───────────────────────────────
        plan = self._planner.generate_plan(
            user_request=sanitized_request,
            region=region,
            account_id=aws_account_id,
            profile=profile,
            conversation_history=self._conversation_history,
            session_resources=self._session_resources,
            existing_resources=existing_resources_text,
        )

        # ── Step 4: Check for Missing Parameters ────────────────
        if plan.missing_parameters:
            # Check for actual errors vs missing info
            errors = [p for p in plan.missing_parameters if p.startswith("Planning error:")]
            missing = [p for p in plan.missing_parameters if not p.startswith("Planning error:")]

            if errors:
                return AgentResponse(
                    message="❌ " + "\n".join(errors),
                    warnings=errors,
                )

            if missing and not plan.commands:
                msg = self._planner.generate_missing_info_message(sanitized_request, missing)
                return AgentResponse(
                    message=msg,
                    requires_input=True,
                    input_questions=missing,
                    plan=plan,
                )

        # ── Step 5: Validate Commands ───────────────────────────
        validation_issues = self._validate_all_commands(plan)
        if validation_issues:
            plan_warnings = [f"⚠️ Validation: {issue}" for issue in validation_issues]
            # Non-blocking warnings for minor issues
            critical = [i for i in validation_issues if "injection" in i.lower() or "not allowed" in i.lower()]
            if critical:
                return AgentResponse(
                    message="❌ Command validation failed:\n" + "\n".join(critical),
                    plan=plan,
                    warnings=critical,
                )

        # ── Step 6: Safety Policy Check ─────────────────────────
        is_safe, policy_warnings, blocking_issues = self._policy_engine.evaluate_plan(plan)
        if blocking_issues:
            return AgentResponse(
                message="🛑 Safety policy violation:\n" + "\n".join(blocking_issues),
                plan=plan,
                warnings=policy_warnings + blocking_issues,
            )

        # Update risk level from policy engine
        assessed_risk = self._policy_engine.assess_risk(plan)
        plan.risk_level = assessed_risk

        # ── Step 7: Determine Approval Requirements ─────────────
        approval_info = self._approval_manager.determine_approval_requirement(plan)

        # ── Step 8: Generate Educational Content (if needed) ────
        educational_content = None
        if learning_mode and self._explainer:
            educational_content = self._explainer.generate_educational_content(plan)

        # ── Step 9: Handle Dry Run ──────────────────────────────
        if dry_run:
            dry_result = ExecutionResult(
                plan_id=plan.plan_id,
                status=ExecutionStatus.DRY_RUN,
                dry_run=True,
            )

            explanation = self._generate_dry_run_explanation(plan)

            response = AgentResponse(
                message=explanation,
                plan=plan,
                execution_result=dry_result,
                requires_approval=False,
                educational_content=educational_content,
                warnings=policy_warnings,
            )

            self._conversation_history.append({
                "role": "assistant",
                "content": f"[DRY RUN] Plan: {plan.intent}",
            })

            return response

        # ── Step 10: Request Approval ───────────────────────────
        if approval_info["requires_approval"]:
            response = AgentResponse(
                message=self._format_approval_message(plan, approval_info),
                plan=plan,
                requires_approval=True,
                educational_content=educational_content,
                warnings=policy_warnings + plan.cost_warnings,
            )
            return response

        # ── Step 11: Auto-approved (READ_ONLY) - Execute ───────
        return self.execute_approved_plan(plan, region, learning_mode)

    def execute_approved_plan(
        self,
        plan: ProvisioningPlan,
        region: str,
        learning_mode: bool = False,
    ) -> AgentResponse:
        """Execute an approved provisioning plan.

        Called after user approval or for auto-approved operations.

        Args:
            plan: The approved plan to execute.
            region: Target AWS region.
            learning_mode: Whether to include educational content.

        Returns:
            AgentResponse with execution results.
        """
        logger.info(f"Executing plan: {plan.plan_id}")
        start_time = time.time()

        # ── Execute Commands ────────────────────────────────────
        execution_result = ExecutionResult(
            plan_id=plan.plan_id,
            status=ExecutionStatus.EXECUTING,
        )

        command_results = []
        created_resources: dict[str, str] = {}
        failed_resources: list[str] = []
        resource_id_map: dict[str, str] = {}  # Maps output_key refs to actual IDs

        for cmd in plan.commands:
            # Substitute resource IDs from previous commands
            resolved_cmd = self._resolve_command_references(cmd, resource_id_map)

            # Execute
            result = self._executor.execute_command(
                cmd=resolved_cmd,
                region=region,
                dry_run=False,
            )

            # Sanitize output
            result = self._sanitizer.sanitize_command_output(result)
            command_results.append(result)

            if result.success:
                # Track created resource IDs
                if result.resource_ids:
                    created_resources.update(result.resource_ids)
                    resource_id_map.update(result.resource_ids)

                # Also track in session
                self._session_resources.update(result.resource_ids)
            else:
                failed_resources.append(
                    f"{cmd.service}/{cmd.action}: {result.error_message or 'Unknown error'}"
                )
                # Stop execution on failure for dependent commands
                if self._has_dependents(cmd, plan.commands):
                    logger.warning(f"Command {cmd.command_id} failed, skipping dependents")
                    # Add remaining commands as failed
                    remaining = plan.commands[plan.commands.index(cmd) + 1:]
                    for rem_cmd in remaining:
                        if cmd.command_id in rem_cmd.depends_on:
                            failed_resources.append(
                                f"{rem_cmd.service}/{rem_cmd.action}: Skipped (dependency failed)"
                            )
                    break

        execution_result.command_results = command_results
        execution_result.created_resources = created_resources
        execution_result.failed_resources = failed_resources
        execution_result.duration_seconds = time.time() - start_time
        execution_result.update_counts()

        # ── Verify Resources ────────────────────────────────────
        if execution_result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL_SUCCESS):
            verification_results = self._verify_resources(plan, created_resources, region)
            execution_result.verification_results = verification_results

        # ── Generate Explanation ────────────────────────────────
        explanation = ""
        educational_content = None
        if self._explainer:
            explanation = self._explainer.generate_explanation(
                plan=plan,
                result=execution_result,
                learning_mode=learning_mode,
            )
            if learning_mode:
                educational_content = self._explainer.generate_educational_content(plan)

        # ── Save to History ─────────────────────────────────────
        self._save_to_history(plan, execution_result, explanation)

        # ── Update Conversation ─────────────────────────────────
        status_text = execution_result.status.value
        self._conversation_history.append({
            "role": "assistant",
            "content": f"[{status_text}] {plan.intent}. Resources: {json.dumps(created_resources)}",
        })

        # ── Build Response ──────────────────────────────────────
        warnings = plan.cost_warnings.copy()
        if execution_result.status == ExecutionStatus.PARTIAL_SUCCESS:
            warnings.append("Some operations failed. Review the results for details.")
        if execution_result.status == ExecutionStatus.FAILED:
            warnings.append("All operations failed. Check AWS credentials and permissions.")

        return AgentResponse(
            message=explanation or f"Execution completed: {status_text}",
            plan=plan,
            execution_result=execution_result,
            explanation=explanation,
            educational_content=educational_content,
            warnings=warnings,
            resource_summary=created_resources,
        )

    def _validate_all_commands(self, plan: ProvisioningPlan) -> list[str]:
        """Validate all commands in the plan.

        Args:
            plan: The plan to validate.

        Returns:
            List of validation issues.
        """
        all_issues = []
        for cmd in plan.commands:
            is_valid, issues = self._validator.validate_command(cmd)
            if not is_valid:
                all_issues.extend(issues)
        return all_issues

    def _resolve_command_references(
        self, cmd: CLICommand, resource_id_map: dict[str, str]
    ) -> CLICommand:
        """Resolve placeholder references in command parameters.

        Replaces {{Key}} style references with actual resource IDs
        from previously executed commands.

        Args:
            cmd: The command to resolve.
            resource_id_map: Map of resource keys to actual IDs.

        Returns:
            Command with resolved parameters.
        """
        import re
        resolved_params = {}
        for key, value in cmd.parameters.items():
            if isinstance(value, str):
                # Replace {{ResourceKey}} patterns
                def replacer(match):
                    ref_key = match.group(1)
                    return resource_id_map.get(ref_key, match.group(0))

                resolved_value = re.sub(r"\{\{(\w+(?:\.\w+)*)\}\}", replacer, value)
                resolved_params[key] = resolved_value
            else:
                resolved_params[key] = value

        resolved_cmd = cmd.model_copy()
        resolved_cmd.parameters = resolved_params
        return resolved_cmd

    def _has_dependents(self, cmd: CLICommand, all_commands: list[CLICommand]) -> bool:
        """Check if any other commands depend on this one."""
        return any(
            cmd.command_id in other.depends_on
            for other in all_commands
            if other.command_id != cmd.command_id
        )

    def _verify_resources(
        self,
        plan: ProvisioningPlan,
        created_resources: dict[str, str],
        region: str,
    ) -> list[VerificationResult]:
        """Verify created resources.

        Args:
            plan: The executed plan.
            created_resources: Map of created resource types to IDs.
            region: AWS region.

        Returns:
            List of verification results.
        """
        results = []
        for resource_type, resource_id in created_resources.items():
            # Determine the service from the resource type
            service = self._infer_service_from_resource_type(resource_type)
            try:
                vr = self._verifier.verify_resource(
                    service=service,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    region=region,
                )
                results.append(vr)
            except Exception as e:
                logger.error(f"Verification failed for {resource_type}/{resource_id}: {e}")
                results.append(VerificationResult(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    verified=False,
                    message=f"Verification error: {e}",
                ))
        return results

    def _infer_service_from_resource_type(self, resource_type: str) -> str:
        """Infer the AWS service from a resource type name."""
        type_to_service = {
            "VpcId": "ec2",
            "SubnetId": "ec2",
            "InstanceId": "ec2",
            "GroupId": "ec2",
            "InternetGatewayId": "ec2",
            "RouteTableId": "ec2",
            "BucketName": "s3",
            "TableName": "dynamodb",
            "FunctionName": "lambda",
            "RoleName": "iam",
            "DBInstanceIdentifier": "rds",
            "ClusterArn": "ecs",
        }
        return type_to_service.get(resource_type, "ec2")

    def _discover_existing_resources(self, region: str) -> str:
        """Discover existing AWS resources for context.

        Args:
            region: AWS region.

        Returns:
            Text description of existing resources.
        """
        try:
            lines = []

            # Discover default VPC
            default_vpc = self._discovery.discover_default_vpc(region)
            if default_vpc:
                vpc_id = default_vpc.get("VpcId", "unknown")
                lines.append(f"Default VPC: {vpc_id}")

                # Discover subnets in default VPC
                subnets = self._discovery.discover_subnets(region, vpc_id)
                if subnets:
                    subnet_ids = [s.get("SubnetId", "") for s in subnets[:5]]
                    lines.append(f"Subnets in default VPC: {', '.join(subnet_ids)}")

                # Discover security groups in default VPC
                sgs = self._discovery.discover_security_groups(region, vpc_id)
                if sgs:
                    for sg in sgs[:5]:
                        sg_name = sg.get("GroupName", "")
                        sg_id = sg.get("GroupId", "")
                        lines.append(f"Security Group: {sg_name} ({sg_id})")

            # Discover key pairs
            key_pairs = self._discovery.discover_key_pairs(region)
            if key_pairs:
                kp_names = [kp.get("KeyName", "") for kp in key_pairs[:5]]
                lines.append(f"Key Pairs: {', '.join(kp_names)}")

            return "\n".join(lines) if lines else "No existing resources discovered"

        except Exception as e:
            logger.warning(f"Resource discovery failed: {e}")
            return "Resource discovery failed (may need AWS credentials)"

    def _generate_dry_run_explanation(self, plan: ProvisioningPlan) -> str:
        """Generate explanation for dry-run mode."""
        lines = [
            "## 🔍 Dry Run Analysis",
            "",
            f"**Request:** {plan.user_request}",
            f"**Interpreted Intent:** {plan.intent}",
            f"**Region:** {plan.aws_region}",
            f"**Risk Level:** {plan.risk_level.value}",
            "",
        ]

        if plan.resources:
            lines.append("### Resources That Would Be Affected")
            for r in plan.resources:
                name = r.resource_name or "auto-named"
                lines.append(f"- **{r.service.upper()} {r.resource_type}**: {name}")
            lines.append("")

        if plan.commands:
            lines.append("### AWS CLI Commands That Would Be Executed")
            for i, cmd in enumerate(plan.commands, 1):
                lines.append(f"\n**{i}. {cmd.description}** ({cmd.operation_category.value})")
                lines.append(f"```bash\n{cmd.to_display_string()}\n```")
            lines.append("")

        if plan.dependencies:
            lines.append("### Resource Dependencies")
            for dep in plan.dependencies:
                lines.append(f"- {dep.get('from', '?')} → {dep.get('to', '?')}")
            lines.append("")

        if plan.assumptions:
            lines.append("### Assumptions")
            for a in plan.assumptions:
                lines.append(f"- {a}")
            lines.append("")

        if plan.cost_warnings:
            lines.append("### 💰 Cost Warnings")
            for w in plan.cost_warnings:
                lines.append(f"- {w}")
            lines.append("")

        if plan.rollback_strategy:
            lines.append("### 🔄 Rollback Plan")
            for step in sorted(plan.rollback_strategy, key=lambda s: s.order, reverse=True):
                lines.append(f"- {step.resource_description}")
            lines.append("")

        if plan.verification_steps:
            lines.append("### ✅ Verification Commands")
            for v in plan.verification_steps:
                lines.append(f"- `{v.to_display_string()}`")
            lines.append("")

        lines.append("> **ℹ️ This is a dry run.** No changes were made to AWS. "
                      "Switch off Dry Run mode and re-submit to execute.")

        return "\n".join(lines)

    def _format_approval_message(
        self, plan: ProvisioningPlan, approval_info: dict
    ) -> str:
        """Format the approval request message."""
        lines = [
            "## ⏳ Approval Required",
            "",
            f"**Request:** {plan.user_request}",
            f"**Intent:** {plan.intent}",
            "",
            "---",
            "",
            f"**Region:** `{plan.aws_region}`",
            f"**Risk Level:** `{plan.risk_level.value}`",
            f"**Destructive Operations:** {'⚠️ Yes' if plan.destructive_operations else '✅ No'}",
            f"**Approval Type:** {approval_info.get('approval_type', 'standard')}",
            "",
        ]

        if plan.resources:
            lines.append("### Resources")
            for r in plan.resources:
                name = r.resource_name or "auto-named"
                lines.append(f"- **{r.service.upper()} {r.resource_type}**: {name}")
            lines.append("")

        if plan.commands:
            lines.append("### Commands to Execute")
            for i, cmd in enumerate(plan.commands, 1):
                lines.append(f"\n**{i}. {cmd.description}**")
                lines.append(f"```bash\n{cmd.to_display_string()}\n```")
            lines.append("")

        if plan.assumptions:
            lines.append("### Assumptions")
            for a in plan.assumptions:
                lines.append(f"- {a}")
            lines.append("")

        if plan.cost_warnings:
            lines.append("### 💰 Cost Warnings")
            for w in plan.cost_warnings:
                lines.append(f"- ⚠️ {w}")
            lines.append("")

        return "\n".join(lines)

    def _save_to_history(
        self,
        plan: ProvisioningPlan,
        result: ExecutionResult,
        explanation: str,
    ) -> None:
        """Save execution to history store."""
        try:
            entry = ExecutionHistoryEntry(
                execution_id=result.execution_id,
                timestamp=result.timestamp,
                user_request=plan.user_request,
                aws_account_id=plan.aws_account_id,
                aws_region=plan.aws_region,
                intent=plan.intent,
                operation_type=plan.operation_type,
                plan=plan,
                approval_status=ApprovalStatus.APPROVED,
                execution_result=result,
                explanation=explanation,
            )
            self._history_store.save_entry(entry)
        except Exception as e:
            logger.error(f"Failed to save to history: {e}")

    def get_execution_history(self, limit: int = 20) -> list[ExecutionHistoryEntry]:
        """Get recent execution history."""
        return self._history_store.list_entries(limit=limit)

    def get_session_resources(self) -> dict[str, str]:
        """Get resources created in this session."""
        return self._session_resources.copy()

    def clear_session(self) -> None:
        """Clear session state."""
        self._conversation_history.clear()
        self._session_resources.clear()
        logger.info("Session cleared")
