"""
AWS Resource Planner.

The core planning engine that takes user requests, interacts with the LLM
to produce structured provisioning plans, and validates/enriches the plans
with service registry metadata and existing resource context.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from agent.llm_client import LLMClient
from agent.models import (
    CLICommand,
    ExecutionStatus,
    OperationCategory,
    OperationType,
    ProvisioningPlan,
    ResourceConfig,
    RiskLevel,
    RollbackStep,
)
from agent.prompts import build_plan_prompt, build_system_prompt, build_missing_info_prompt
from services.registry import AWSServiceRegistry

logger = logging.getLogger(__name__)


class Planner:
    """
    Generates structured provisioning plans from natural-language requests.

    Uses the LLM for reasoning and the service registry for validation.
    The plan is always a structured Pydantic model, never raw LLM text.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        service_registry: AWSServiceRegistry,
    ) -> None:
        self._llm = llm_client
        self._registry = service_registry

    def generate_plan(
        self,
        user_request: str,
        region: str,
        account_id: str = "Unknown",
        profile: str = "default",
        conversation_history: list[dict] = None,
        session_resources: dict[str, str] = None,
        existing_resources: str = "None discovered",
    ) -> ProvisioningPlan:
        """Generate a provisioning plan from a natural-language request.

        Args:
            user_request: The user's natural-language request.
            region: Target AWS region.
            account_id: AWS account ID for context.
            profile: AWS profile name.
            conversation_history: Previous conversation messages.
            session_resources: Previously created resource IDs.
            existing_resources: Description of existing AWS resources.

        Returns:
            A validated ProvisioningPlan.
        """
        logger.info(f"Generating plan for request: {user_request[:100]}...")

        # Build context
        services_context = json.dumps(self._registry.get_service_summary(), indent=2)

        history_text = ""
        if conversation_history:
            history_text = "\n".join(
                f"{msg.get('role', 'user')}: {msg.get('content', '')[:200]}"
                for msg in conversation_history[-10:]  # Last 10 messages
            )

        resources_text = "None"
        if session_resources:
            resources_text = "\n".join(
                f"- {k}: {v}" for k, v in session_resources.items()
            )

        # Build prompts
        system_prompt = build_system_prompt(
            services_context=services_context,
            account_id=account_id,
            region=region,
            profile=profile,
            existing_resources=existing_resources,
        )

        user_prompt = build_plan_prompt(
            user_request=user_request,
            region=region,
            conversation_history=history_text,
            session_resources=resources_text,
        )

        # Call LLM
        try:
            raw_response = self._llm.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.1,
                response_format="json",
            )
            logger.debug(f"LLM raw response length: {len(raw_response)}")
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return self._create_error_plan(user_request, region, str(e))

        # Parse LLM response into structured plan
        plan = self._parse_llm_response(raw_response, user_request, region, account_id)

        # Enrich and validate the plan
        plan = self._enrich_plan(plan, region)
        plan = self._validate_plan(plan)

        logger.info(
            f"Plan generated: {plan.plan_id} | "
            f"intent={plan.intent} | "
            f"commands={len(plan.commands)} | "
            f"risk={plan.risk_level}"
        )

        return plan

    def _parse_llm_response(
        self,
        raw_response: str,
        user_request: str,
        region: str,
        account_id: str,
    ) -> ProvisioningPlan:
        """Parse the LLM JSON response into a ProvisioningPlan.

        Args:
            raw_response: Raw JSON string from the LLM.
            user_request: Original user request.
            region: Target AWS region.
            account_id: AWS account ID.

        Returns:
            Parsed ProvisioningPlan.
        """
        try:
            # Clean the response - remove markdown code blocks if present
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                # Remove opening ``` line
                cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
                # Remove closing ```
                cleaned = re.sub(r"\n?```\s*$", "", cleaned)

            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}")
            logger.debug(f"Raw response: {raw_response[:500]}")
            return self._create_error_plan(
                user_request, region,
                f"Failed to parse the AI response. Please try rephrasing your request."
            )

        # Map LLM output to Pydantic model
        try:
            # Parse operation type
            op_type_str = data.get("operation_type", "create").lower()
            try:
                operation_type = OperationType(op_type_str)
            except ValueError:
                operation_type = OperationType.CREATE

            # Parse operation category
            op_cat_str = data.get("operation_category", "WRITE").upper()
            try:
                operation_category = OperationCategory(op_cat_str)
            except ValueError:
                operation_category = OperationCategory.WRITE

            # Parse risk level
            risk_str = data.get("risk_level", "MEDIUM").upper()
            try:
                risk_level = RiskLevel(risk_str)
            except ValueError:
                risk_level = RiskLevel.MEDIUM

            # Parse resources
            resources = []
            for r in data.get("resources", []):
                resources.append(ResourceConfig(
                    service=r.get("service", ""),
                    resource_type=r.get("resource_type", ""),
                    resource_name=r.get("resource_name"),
                    configuration=r.get("configuration", {}),
                    dependencies=r.get("dependencies", []),
                    tags=r.get("tags", {}),
                ))

            # Parse commands
            commands = []
            for i, c in enumerate(data.get("commands", [])):
                cmd_cat_str = c.get("operation_category", "WRITE").upper()
                try:
                    cmd_category = OperationCategory(cmd_cat_str)
                except ValueError:
                    cmd_category = OperationCategory.WRITE

                cmd = CLICommand(
                    command_id=c.get("command_id", str(uuid.uuid4())[:8]),
                    service=c.get("service", ""),
                    action=c.get("action", ""),
                    parameters=c.get("parameters", {}),
                    region=c.get("region", region),
                    description=c.get("description", ""),
                    operation_category=cmd_category,
                    resource_ref=c.get("resource_ref"),
                    depends_on=c.get("depends_on", []),
                    output_key=c.get("output_key"),
                )
                commands.append(cmd)

            # Parse verification commands
            verification_steps = []
            for v in data.get("verification_commands", []):
                ver_cmd = CLICommand(
                    command_id=f"verify-{uuid.uuid4().hex[:6]}",
                    service=v.get("service", ""),
                    action=v.get("action", ""),
                    parameters=v.get("parameters", {}),
                    region=region,
                    description=v.get("description", "Verify resource"),
                    operation_category=OperationCategory.READ_ONLY,
                )
                verification_steps.append(ver_cmd)

            # Parse rollback commands
            rollback_strategy = []
            for i, rb in enumerate(data.get("rollback_commands", [])):
                rb_cat_str = rb.get("operation_category", "DESTRUCTIVE").upper()
                try:
                    rb_category = OperationCategory(rb_cat_str)
                except ValueError:
                    rb_category = OperationCategory.DESTRUCTIVE

                rb_cmd = CLICommand(
                    service=rb.get("service", ""),
                    action=rb.get("action", ""),
                    parameters=rb.get("parameters", {}),
                    region=region,
                    description=rb.get("description", "Rollback"),
                    operation_category=rb_category,
                )
                rollback_strategy.append(RollbackStep(
                    order=len(data.get("rollback_commands", [])) - i,
                    resource_description=rb.get("description", ""),
                    command=rb_cmd,
                ))

            plan = ProvisioningPlan(
                user_request=user_request,
                intent=data.get("intent", "Unknown intent"),
                operation_type=operation_type,
                operation_category=operation_category,
                aws_region=data.get("aws_region", region),
                aws_account_id=account_id,
                resources=resources,
                dependencies=data.get("dependencies", []),
                commands=commands,
                risk_level=risk_level,
                destructive_operations=data.get("destructive_operations", False),
                missing_parameters=data.get("missing_parameters", []),
                assumptions=data.get("assumptions", []),
                requires_approval=data.get("requires_approval", True),
                rollback_strategy=rollback_strategy,
                verification_steps=verification_steps,
                cost_warnings=data.get("cost_warnings", []),
                educational_notes=data.get("educational_notes", []),
            )

            return plan

        except Exception as e:
            logger.error(f"Failed to construct plan from parsed data: {e}", exc_info=True)
            return self._create_error_plan(
                user_request, region,
                f"Failed to construct the provisioning plan: {e}"
            )

    def _enrich_plan(self, plan: ProvisioningPlan, region: str) -> ProvisioningPlan:
        """Enrich the plan with service registry metadata.

        Adds cost warnings, IAM permissions info, and validates
        service/resource types against the registry.

        Args:
            plan: The plan to enrich.
            region: Target AWS region.

        Returns:
            Enriched plan.
        """
        # Ensure region is set on all commands
        for cmd in plan.commands:
            if not cmd.region:
                cmd.region = region

        # Add cost warnings from service registry
        for resource in plan.resources:
            rt_def = self._registry.get_resource_type(resource.service, resource.resource_type)
            if rt_def and rt_def.cost_warning:
                if rt_def.cost_warning not in plan.cost_warnings:
                    plan.cost_warnings.append(rt_def.cost_warning)

        # Ensure destructive_operations flag is accurate
        if plan.has_destructive_commands:
            plan.destructive_operations = True
            if plan.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM):
                plan.risk_level = RiskLevel.HIGH

        # Set approval requirements
        if plan.operation_category == OperationCategory.READ_ONLY:
            plan.requires_approval = False
        elif plan.operation_category == OperationCategory.DESTRUCTIVE:
            plan.requires_approval = True
            if plan.risk_level == RiskLevel.LOW:
                plan.risk_level = RiskLevel.MEDIUM
        elif plan.operation_category == OperationCategory.WRITE:
            plan.requires_approval = True

        return plan

    def _validate_plan(self, plan: ProvisioningPlan) -> ProvisioningPlan:
        """Validate the plan for correctness.

        Args:
            plan: The plan to validate.

        Returns:
            Validated plan (may have updated missing_parameters).
        """
        # Check that all commands have a service and action
        for cmd in plan.commands:
            if not cmd.service:
                plan.missing_parameters.append(f"Command missing service: {cmd.description}")
            if not cmd.action:
                plan.missing_parameters.append(f"Command missing action: {cmd.description}")

        # Check that S3 buckets in non-us-east-1 have LocationConstraint
        for cmd in plan.commands:
            if (
                cmd.service == "s3api"
                and cmd.action == "create-bucket"
                and plan.aws_region != "us-east-1"
            ):
                params = cmd.parameters
                if "create-bucket-configuration" not in params:
                    params["create-bucket-configuration"] = f"LocationConstraint={plan.aws_region}"

        return plan

    def _create_error_plan(
        self, user_request: str, region: str, error_msg: str
    ) -> ProvisioningPlan:
        """Create an error plan when planning fails.

        Args:
            user_request: Original user request.
            region: Target region.
            error_msg: Error message.

        Returns:
            A plan with the error in missing_parameters.
        """
        return ProvisioningPlan(
            user_request=user_request,
            intent="Error during planning",
            operation_type=OperationType.READ,
            operation_category=OperationCategory.READ_ONLY,
            aws_region=region,
            missing_parameters=[f"Planning error: {error_msg}"],
            requires_approval=False,
        )

    def generate_missing_info_message(
        self, user_request: str, missing_params: list[str]
    ) -> str:
        """Generate a friendly message asking for missing information.

        Args:
            user_request: Original user request.
            missing_params: List of missing parameters.

        Returns:
            Friendly message string.
        """
        try:
            prompt = build_missing_info_prompt(user_request, missing_params)
            response = self._llm.generate(
                system_prompt="You are a helpful AWS assistant. Generate a friendly, concise message.",
                user_prompt=prompt,
                temperature=0.3,
            )
            return response
        except Exception as e:
            logger.error(f"Failed to generate missing info message: {e}")
            # Fallback to a simple message
            params_text = "\n".join(f"  - {p}" for p in missing_params)
            return (
                f"I need a bit more information to proceed:\n\n{params_text}\n\n"
                f"Could you please provide these details?"
            )
