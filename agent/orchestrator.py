"""
Agent Orchestrator.

The central coordinator that manages the complete lifecycle of a user request:
parse → discover → plan → graph sort → validate → policy → approve → execute → verify → explain.

Ensures deterministic execution, profile & region propagation, recursive placeholder
resolution, true DAG execution, and controlled rollback.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from agent.dependency_graph import DependencyGraph, CyclicDependencyError, MissingDependencyError
from agent.explainer import Explainer
from agent.llm_client import LLMClient, create_llm_client
from agent.models import (
    AgentResponse,
    ApprovalStatus,
    ApprovalType,
    CLICommand,
    CommandExecutionStatus,
    CommandResult,
    ConversationMessage,
    DiscoveryOutcome,
    ExecutionHistoryEntry,
    ExecutionResult,
    ExecutionStatus,
    LogicalResource,
    OperationCategory,
    OperationType,
    ProvisioningPlan,
    ResourceOwnership,
    RiskLevel,
    VerificationResult,
)
from agent.parser import RequestParser
from agent.planner import Planner
from agent.resource_context import ResourceContext, UnresolvedReferenceError
from agent.rollback import RollbackEngine
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
    """Orchestrates the complete agent workflow with deterministic safety controls."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._settings = settings or get_settings()
        self._initialized = False
        self._init_error: Optional[str] = None

        # Subsystems
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
        self._rollback_engine = RollbackEngine(self._executor)
        self._registry: Optional[AWSServiceRegistry] = None

        # Session state
        self._conversation_history: list[dict] = []
        self._resource_context = ResourceContext()

    def initialize(self) -> tuple[bool, str]:
        """Initialize the orchestrator and all subsystems."""
        try:
            self._registry = create_default_registry()
            self._llm_client = create_llm_client(self._settings)

            if not self._llm_client.is_available():
                return False, "LLM provider is not available. Check your API key configuration."

            self._planner = Planner(self._llm_client, self._registry)
            self._explainer = Explainer(self._llm_client)

            self._initialized = True
            logger.info("Agent orchestrator initialized successfully")
            return True, "Agent initialized successfully"

        except Exception as e:
            self._init_error = str(e)
            logger.error("Orchestrator initialization failed: %s", e, exc_info=True)
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

        Args:
            user_request: Natural-language user request.
            region: Target AWS region.
            profile: Target AWS CLI profile.
            dry_run: Whether to run in dry-run mode (default True).
            learning_mode: Whether to include educational content.
            aws_account_id: AWS account ID for context.

        Returns:
            AgentResponse with plan, approval state, and explanations.
        """
        if not self._initialized:
            return AgentResponse(
                message="⚠️ Agent is not initialized. Please check configuration.",
                warnings=["Agent not initialized"],
            )

        logger.info("Processing request: '%s' (profile=%s, region=%s, dry_run=%s)", user_request[:80], profile, region, dry_run)

        # ── Step 1: Input Validation & Prompt Injection Defense ──────
        is_valid, issues = self._parser.validate_input(user_request)
        if not is_valid:
            return AgentResponse(
                message="❌ " + "\n".join(issues),
                warnings=issues,
            )

        sanitized_input = self._parser.sanitize_for_llm(user_request)
        hints = self._parser.extract_hints(sanitized_input)

        # Allow region override from prompt if detected
        effective_region = hints.get("detected_region") or region
        effective_profile = profile

        # ── Step 2: Pre-flight Resource Discovery ────────────────────
        discovered_text = self._discover_existing_resources(region=effective_region, profile=effective_profile)

        # ── Step 3: Plan Generation (Reasoning Layer) ─────────────────
        plan = self._planner.generate_plan(
            user_request=sanitized_input,
            region=effective_region,
            account_id=aws_account_id,
            profile=effective_profile,
            conversation_history=self._conversation_history,
            session_resources={r.resource_ref: r.resource_id for r in self._resource_context.list_resources() if r.resource_id},
            existing_resources=discovered_text,
        )

        # Check for planning failure
        if not plan.is_complete and plan.missing_parameters:
            return AgentResponse(
                message=f"I need more information to fulfill your request:\n" + "\n".join(f"- {p}" for p in plan.missing_parameters),
                plan=plan,
                requires_input=True,
                input_questions=plan.missing_parameters,
                warnings=plan.assumptions,
            )

        # ── Step 4: Topological Dependency Graph Ordering ────────────
        try:
            dep_graph = DependencyGraph(plan.commands)
            plan.commands = dep_graph.topological_sort()
        except CyclicDependencyError as cde:
            return AgentResponse(
                message=f"❌ Circular dependency detected in plan: {cde}",
                plan=plan,
                warnings=[str(cde)],
            )
        except MissingDependencyError as mde:
            return AgentResponse(
                message=f"❌ Missing dependency in plan: {mde}",
                plan=plan,
                warnings=[str(mde)],
            )

        # ── Step 5: Deterministic Command Validation & Category Check ─
        validation_issues = self._validate_all_commands(plan)
        if validation_issues:
            return AgentResponse(
                message="❌ Command validation failed:\n" + "\n".join(f"- {issue}" for issue in validation_issues),
                plan=plan,
                warnings=validation_issues,
            )

        # ── Step 6: Security & Safety Policy Evaluation ──────────────
        is_safe, policy_warnings, blocking_issues = self._policy_engine.evaluate_plan(plan)
        if not is_safe:
            return AgentResponse(
                message="🚫 **Operation Blocked by Safety Policy:**\n" + "\n".join(f"- 🛑 {issue}" for issue in blocking_issues),
                plan=plan,
                warnings=blocking_issues + policy_warnings,
            )

        # ── Step 7: Deterministic Risk & Approval Evaluation ──────────
        plan.risk_level = self._policy_engine.assess_risk(plan)
        approval_info = self._approval_manager.determine_approval_requirement(plan)
        plan.approval_type = approval_info["approval_type"]
        plan.requires_approval = approval_info["requires_approval"]

        # ── Step 8: Educational Content (if requested) ────────────────
        educational_content = None
        if learning_mode and self._explainer:
            educational_content = self._explainer.generate_educational_content(plan)

        # ── Step 9: Dry Run Mode (Default) ────────────────────────────
        if dry_run:
            dry_results = []
            for cmd in plan.commands:
                cmd_res = self._executor.execute_command(
                    cmd=cmd,
                    region=effective_region,
                    profile=effective_profile,
                    dry_run=True,
                )
                dry_results.append(cmd_res)

            dry_execution = ExecutionResult(
                plan_id=plan.plan_id,
                status=ExecutionStatus.DRY_RUN,
                dry_run=True,
                command_results=dry_results,
            )
            dry_execution.update_counts()

            explanation = self._generate_dry_run_explanation(plan, effective_profile, effective_region)

            return AgentResponse(
                message=explanation,
                plan=plan,
                execution_result=dry_execution,
                requires_approval=False,
                approval_type=plan.approval_type,
                educational_content=educational_content,
                warnings=policy_warnings + plan.cost_warnings,
            )

        # ── Step 10: Human Approval Required ─────────────────────────
        if plan.requires_approval:
            approval_msg = self._approval_manager.format_approval_request(plan)
            return AgentResponse(
                message=approval_msg,
                plan=plan,
                requires_approval=True,
                approval_type=plan.approval_type,
                educational_content=educational_content,
                warnings=policy_warnings + plan.cost_warnings,
            )

        # ── Step 11: Auto-Approved (READ_ONLY) -> Execute ─────────────
        return self.execute_approved_plan(
            plan=plan,
            region=effective_region,
            profile=effective_profile,
            learning_mode=learning_mode,
        )

    def execute_approved_plan(
        self,
        plan: ProvisioningPlan,
        region: str,
        profile: str = "default",
        learning_mode: bool = False,
    ) -> AgentResponse:
        """Execute an approved provisioning plan using the effective profile and region.

        Executes commands in topological dependency order, resolves placeholders
        recursively via ResourceContext, captures live results, halts dependent
        operations on failure, verifies actual AWS state, and generates technical explanations.
        """
        logger.info("Executing approved plan: %s (profile=%s, region=%s)", plan.plan_id, profile, region)
        start_time = time.time()

        execution_result = ExecutionResult(
            plan_id=plan.plan_id,
            status=ExecutionStatus.EXECUTING,
        )

        # Build Dependency Graph to enable smart skipping on failure
        dep_graph = DependencyGraph(plan.commands)
        topological_commands = dep_graph.topological_sort()

        command_results: list[CommandResult] = []
        created_resources: dict[str, str] = {}
        failed_resources: list[str] = []
        skipped_command_ids: set[str] = set()

        for cmd in topological_commands:
            # Check if this command must be skipped because an upstream dependency failed
            if cmd.command_id in skipped_command_ids:
                logger.warning("Skipping command '%s' due to failed upstream dependency", cmd.command_id)
                skipped_res = CommandResult(
                    command_id=cmd.command_id,
                    command_display=cmd.to_display_string(profile=profile, region=region),
                    exit_code=-1,
                    status=CommandExecutionStatus.SKIPPED,
                    success=False,
                    error_message="Skipped: required upstream dependency failed.",
                )
                command_results.append(skipped_res)
                execution_result.skipped_commands.append(f"{cmd.service}/{cmd.action} (dependency failed)")
                continue

            # ── Resolve Placeholders Recursively (Critical Fix #5) ───
            try:
                resolved_params = self._resource_context.resolve_placeholders_recursively(cmd.parameters)
                resolved_cmd = cmd.model_copy()
                resolved_cmd.parameters = resolved_params

                # Check for unresolved placeholders before reaching AWS
                unresolved = self._resource_context.find_unresolved_placeholders(resolved_params)
                if unresolved:
                    raise UnresolvedReferenceError(unresolved, cmd.description or cmd.action)

            except UnresolvedReferenceError as ure:
                logger.error("Unresolved reference in command %s: %s", cmd.command_id, ure)
                err_res = CommandResult(
                    command_id=cmd.command_id,
                    command_display=cmd.to_display_string(profile=profile, region=region),
                    exit_code=1,
                    status=CommandExecutionStatus.FAILED,
                    success=False,
                    error_type="UnresolvedReference",
                    error_message=str(ure),
                )
                command_results.append(err_res)
                failed_resources.append(f"{cmd.service}/{cmd.action}: {ure}")
                # Mark downstream dependents as skipped
                downstream = dep_graph.get_transitive_dependents(cmd.command_id)
                skipped_command_ids.update(downstream)
                continue

            # ── Execute Command with Explicit Profile & Region ────────
            result = self._executor.execute_command(
                cmd=resolved_cmd,
                region=region,
                profile=profile,
                dry_run=False,
            )
            result = self._sanitizer.sanitize_command_output(result)
            command_results.append(result)

            if result.success:
                # Register created resource in ResourceContext with CREATED_BY_THIS_PLAN ownership
                ref = cmd.resource_ref or f"{cmd.service}.{cmd.action.split('-')[-1]}"
                res_id = None
                if result.resource_ids:
                    # Pick primary ID
                    res_id = next(iter(result.resource_ids.values()))
                    created_resources[ref] = res_id

                self._resource_context.register_resource(
                    resource_ref=ref,
                    resource_type=cmd.service,
                    service=cmd.service,
                    resource_id=res_id,
                    ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
                    attributes=result.resource_ids,
                )
            else:
                failed_msg = f"{cmd.service}/{cmd.action}: {result.error_message or 'Command returned non-zero exit code'}"
                failed_resources.append(failed_msg)
                # Smart skipping: mark all downstream dependents to skip
                downstream = dep_graph.get_transitive_dependents(cmd.command_id)
                skipped_command_ids.update(downstream)

        execution_result.command_results = command_results
        execution_result.created_resources = created_resources
        execution_result.failed_resources = failed_resources
        execution_result.duration_seconds = time.time() - start_time
        execution_result.update_counts()

        # ── Step 12: Live Resource Verification (Critical Fix #15/16) ─
        if execution_result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL_SUCCESS):
            verification_results = self._verify_created_resources(region=region, profile=profile)
            execution_result.verification_results = verification_results
            execution_result.update_counts()

        # ── Step 13: Post-Execution Technical Explanation ─────────────
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

        # ── Step 14: Save Sanitized Record to History Store ───────────
        self._save_to_history(plan, execution_result, explanation, profile=profile, region=region)

        # ── Step 15: Build Consolidated Response ──────────────────────
        warnings = plan.cost_warnings.copy()
        if execution_result.status == ExecutionStatus.PARTIAL_SUCCESS:
            warnings.append("⚠️ Some operations failed. Dependent operations were safely skipped.")
        elif execution_result.status == ExecutionStatus.FAILED:
            warnings.append("❌ All operations failed. Check credentials, permissions, and parameters.")
        elif execution_result.status == ExecutionStatus.VERIFICATION_FAILED:
            warnings.append("⚠️ Commands executed, but AWS state verification failed for one or more resources.")

        return AgentResponse(
            message=explanation or f"Execution finished with status: {execution_result.status.value}",
            plan=plan,
            execution_result=execution_result,
            approval_type=plan.approval_type,
            explanation=explanation,
            educational_content=educational_content,
            warnings=warnings,
            resource_summary=created_resources,
        )

    def _verify_created_resources(self, region: str, profile: str) -> list[VerificationResult]:
        """Verify only resources created by the current plan using logical references."""
        results: list[VerificationResult] = []
        for resource in self._resource_context.get_created_resources():
            vr = self._verifier.verify_logical_resource(resource, region=region, profile=profile)
            results.append(vr)
        return results

    def _validate_all_commands(self, plan: ProvisioningPlan) -> list[str]:
        """Validate all commands in the plan."""
        issues = []
        for cmd in plan.commands:
            is_valid, cmd_issues = self._validator.validate_command(cmd)
            if not is_valid:
                issues.extend(cmd_issues)
        return issues

    def _discover_existing_resources(self, region: str, profile: str) -> str:
        """Inspect region for existing default VPC, subnets, and security groups."""
        try:
            lines = []
            outcome, vpc, msg = self._discovery.discover_default_vpc(region=region, profile=profile)
            if outcome == DiscoveryOutcome.EXISTS_AND_REUSABLE and vpc:
                vpc_id = vpc.get("VpcId", "")
                cidr = vpc.get("CidrBlock", "")
                lines.append(f"Default VPC: {vpc_id} ({cidr}) [Available]")
                # Register in context as DISCOVERED_ONLY so rollback never touches it
                self._resource_context.register_resource(
                    resource_ref="vpc.default",
                    resource_type="vpc",
                    service="ec2",
                    resource_id=vpc_id,
                    ownership=ResourceOwnership.DISCOVERED_ONLY,
                    attributes={"CidrBlock": cidr},
                )
                subnets = self._discovery.discover_subnets(region=region, vpc_id=vpc_id, profile=profile)
                if subnets:
                    subnet_strs = [f"{s.get('SubnetId')}({s.get('CidrBlock')})" for s in subnets[:3]]
                    lines.append(f"Subnets in Default VPC: {', '.join(subnet_strs)}")

            return "\n".join(lines) if lines else "None discovered"
        except Exception as e:
            logger.warning("Resource discovery encountered error: %s", e)
            return "Discovery skipped or unavailable"

    def _generate_dry_run_explanation(
        self, plan: ProvisioningPlan, profile: str, region: str
    ) -> str:
        """Format the dry run explanation."""
        lines = [
            "### 🔍 Dry Run Analysis (No Changes Made)",
            f"**Intent:** {plan.intent}",
            f"**Target AWS Profile:** `{profile}`",
            f"**Target AWS Region:** `{region}`",
            f"**Risk Level:** `{plan.risk_level.value}`",
            f"**Destructive Operations:** {'⚠️ Yes' if plan.destructive_operations else '✅ No'}",
            f"**Required Approval Type:** `{plan.approval_type.value}`",
            "",
            "**Planned AWS CLI Commands:**",
        ]
        for idx, cmd in enumerate(plan.commands, 1):
            badge = f"[{cmd.operation_category.value}]"
            lines.append(f"{idx}. {badge} `{cmd.to_display_string(profile=profile, region=region)}`")
            if cmd.description:
                lines.append(f"   _{cmd.description}_")

        if plan.assumptions:
            lines.extend(["", "**Assumptions:**"])
            for a in plan.assumptions:
                lines.append(f"- {a}")

        if plan.cost_warnings:
            lines.extend(["", "**💰 Cost Warnings:**"])
            for w in plan.cost_warnings:
                lines.append(f"- ⚠️ {w}")

        lines.extend([
            "",
            "ℹ️ _This was a dry run. Uncheck 'Dry Run' in the sidebar and click Execute to apply these changes to AWS._"
        ])
        return "\n".join(lines)

    def _save_to_history(
        self,
        plan: ProvisioningPlan,
        result: ExecutionResult,
        explanation: str,
        profile: str,
        region: str,
    ) -> None:
        """Save sanitized execution record to persistent history."""
        try:
            entry = ExecutionHistoryEntry(
                execution_id=result.execution_id,
                timestamp=datetime.now(timezone.utc),
                user_request=plan.user_request,
                aws_account_id=plan.aws_account_id,
                aws_profile=profile,
                aws_region=region,
                intent=plan.intent,
                operation_type=plan.operation_type,
                plan=plan,
                approval_status=ApprovalStatus.APPROVED if result.status != ExecutionStatus.DRY_RUN else ApprovalStatus.AUTO_APPROVED,
                execution_result=result,
                explanation=explanation,
            )
            self._history_store.save_entry(entry)
        except Exception as e:
            logger.error("Failed to save execution history: %s", e)
