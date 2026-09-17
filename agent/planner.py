"""
AWS Resource Planner.

The core planning engine that takes user requests, interacts with the LLM
to produce structured desired-state provisioning plans, and deterministically
builds and enriches commands, logical resource references, and dependencies.
Never trusts LLM for operation categories or arbitrary AMI IDs.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from agent.compiler import (
    PlanCompiler,
    UnsupportedConfigurationError,
    UnsupportedResourceTypeError,
)
from agent.llm_client import LLMClient
from agent.models import (
    ApprovalType,
    CLICommand,
    DesiredResource,
    DesiredStatePlan,
    ExecutionStatus,
    LogicalResource,
    OperationCategory,
    OperationType,
    ProvisioningPlan,
    ResourceConfig,
    ResourceOwnership,
    RiskLevel,
    RollbackStep,
)
from agent.prompts import build_missing_info_prompt, build_plan_prompt, build_system_prompt
from aws.ami_discovery import AMIDiscovery
from aws.cli_validator import classify_aws_action
from services.registry import AWSServiceRegistry

logger = logging.getLogger(__name__)


class Planner:
    """Generates structured provisioning plans from natural-language requests.

    Uses the LLM for high-level reasoning and desired-state definition,
    and deterministic application code for command construction, category
    classification, and AMI discovery.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        service_registry: AWSServiceRegistry,
    ) -> None:
        self._llm = llm_client
        self._registry = service_registry
        self._ami_discovery = AMIDiscovery()
        self._compiler = PlanCompiler(self._registry, self._ami_discovery)

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
            user_request: Natural language request.
            region: Target AWS region.
            account_id: AWS account ID for context.
            profile: Target AWS CLI profile.
            conversation_history: Prior conversation turns.
            session_resources: Known session resource IDs.
            existing_resources: Summary of discovered resources.

        Returns:
            A validated ProvisioningPlan with deterministic command classifications.
        """
        logger.info("Generating plan for request: %s (profile=%s, region=%s)", user_request[:100], profile, region)

        # Build context
        services_context = json.dumps(self._registry.get_service_summary(), indent=2)

        history_text = ""
        if conversation_history:
            history_text = "\n".join(
                f"{msg.get('role', 'user')}: {msg.get('content', '')[:200]}"
                for msg in conversation_history[-10:]
            )

        resources_text = "None"
        if session_resources:
            resources_text = "\n".join(
                f"- {k}: {v}" for k, v in session_resources.items()
            )

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

        try:
            raw_response = self._llm.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.1,
                response_format="json",
            )
            logger.debug("LLM raw response length: %d", len(raw_response))
        except Exception as e:
            logger.error("LLM call failed: %s", e)
            return self._create_error_plan(user_request, region, profile, str(e))

        # Parse LLM response into structured plan
        plan = self._parse_llm_response(raw_response, user_request, region, profile, account_id)

        # Enrich and validate deterministically
        plan = self._enrich_plan(plan, region, profile)
        plan = self._validate_plan(plan)
        plan.plan_hash = plan.compute_plan_fingerprint()

        logger.info(
            "Plan generated: %s | intent=%s | commands=%d | risk=%s | category=%s",
            plan.plan_id, plan.intent, len(plan.commands), plan.risk_level.value, plan.operation_category.value
        )
        return plan

    def _parse_llm_response(
        self,
        raw_response: str,
        user_request: str,
        region: str,
        profile: str,
        account_id: str,
    ) -> ProvisioningPlan:
        """Parse the LLM JSON response into a ProvisioningPlan."""
        try:
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
                cleaned = re.sub(r"\n?```\s*$", "", cleaned)

            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM JSON response: %s", e)
            return self._create_error_plan(
                user_request, region, profile,
                "Failed to parse the AI response as JSON. Please rephrase your request."
            )

        try:
            op_type_str = data.get("operation_type", "create").lower()
            try:
                operation_type = OperationType(op_type_str)
            except ValueError:
                operation_type = OperationType.CREATE

            # Parse desired resources from LLM output (desired-state intent)
            desired_resources: list[DesiredResource] = []
            for r in data.get("resources", []):
                svc = r.get("service")
                rtype = r.get("resource_type", "")
                rname = r.get("resource_name")
                ref = r.get("logical_ref") or f"{svc or 'res'}.{rtype}"
                cfg = r.get("configuration", {})
                deps = r.get("dependencies", [])
                tags = r.get("tags", {})
                desired_resources.append(
                    DesiredResource(
                        logical_ref=ref,
                        resource_type=rtype,
                        service=svc,
                        resource_name=rname,
                        configuration=cfg,
                        dependencies=deps,
                        tags=tags,
                    )
                )

            # Fallback for read-only queries if LLM emitted no explicit resources
            if not desired_resources:
                req_lower = user_request.lower()
                if operation_type in (OperationType.LIST, OperationType.DESCRIBE) or any(w in req_lower for w in ("list", "show", "describe", "find", "get")):
                    if any(w in req_lower for w in ("instance", "ec2", "vm")):
                        desired_resources.append(DesiredResource(logical_ref="ec2.instance", resource_type="instance", service="ec2"))
                    elif any(w in req_lower for w in ("bucket", "s3")):
                        desired_resources.append(DesiredResource(logical_ref="s3.bucket", resource_type="bucket", service="s3"))
                    elif "vpc" in req_lower:
                        desired_resources.append(DesiredResource(logical_ref="vpc.main", resource_type="vpc", service="vpc"))

            desired_plan = DesiredStatePlan(
                intent=data.get("intent", user_request),
                operation_type=operation_type,
                aws_region=region,
                resources=desired_resources,
                missing_parameters=data.get("missing_parameters", []),
                assumptions=data.get("assumptions", []),
            )

            # Compile into authoritative ProvisioningPlan using deterministic Python builders
            plan = self._compiler.compile(
                desired=desired_plan,
                user_request=user_request,
                region=region,
                profile=profile,
                account_id=account_id,
            )
            return plan

        except (UnsupportedResourceTypeError, UnsupportedConfigurationError) as ure:
            logger.error("Unsupported resource type or configuration: %s", ure)
            return self._create_error_plan(user_request, region, profile, str(ure))
        except Exception as e:
            logger.error("Error creating plan from parsed JSON: %s", e, exc_info=True)
            return self._create_error_plan(user_request, region, profile, f"Plan creation error: {e}")

    def _enrich_plan(self, plan: ProvisioningPlan, region: str, profile: str) -> ProvisioningPlan:
        """Deterministically enrich the plan: resolve AMIs, cost warnings, and tags."""
        # 1. Deterministic Live AMI Discovery for EC2 instances
        for cmd in plan.commands:
            if cmd.service == "ec2" and cmd.action == "run-instances":
                curr_ami = cmd.parameters.get("image-id")
                # If AMI is missing, or looks like a placeholder, or user requested Amazon Linux
                if not curr_ami or "ami-" not in curr_ami or "placeholder" in curr_ami.lower() or "012345" in curr_ami:
                    discovered_ami, rationale = self._ami_discovery.discover_amazon_linux_2023(
                        region=region, profile=profile, query_live=True
                    )
                    if discovered_ami:
                        cmd.parameters["image-id"] = discovered_ami
                        if rationale not in plan.assumptions:
                            plan.assumptions.append(rationale)

        # 2. Enrich Cost Warnings from Service Registry
        for res in plan.resources:
            rt_def = self._registry.get_resource_type(res.service, res.resource_type)
            if rt_def and rt_def.cost_warning:
                if rt_def.cost_warning not in plan.cost_warnings:
                    plan.cost_warnings.append(rt_def.cost_warning)

        # 3. Propagate profile and region to all commands
        for cmd in plan.commands:
            cmd.profile = profile
            if not cmd.region:
                cmd.region = region

        return plan

    def _validate_plan(self, plan: ProvisioningPlan) -> ProvisioningPlan:
        """Validate logical completeness and assign missing parameters."""
        # Read-only and delete operations do not require resource creation parameters
        if plan.operation_type in (OperationType.LIST, OperationType.DESCRIBE, OperationType.READ) or plan.operation_category == OperationCategory.READ_ONLY:
            return plan
        if plan.operation_type == OperationType.DELETE or plan.operation_category == OperationCategory.DESTRUCTIVE:
            return plan

        for res in plan.resources:
            rt_def = self._registry.get_resource_type(res.service, res.resource_type)
            if not rt_def:
                continue

            for req_param in rt_def.required_params:
                # Check if param appears in resource config or associated command
                param_found = req_param in res.configuration
                if not param_found:
                    for cmd in plan.commands:
                        if cmd.service == rt_def.cli_service and req_param in cmd.parameters:
                            param_found = True
                            break

                if not param_found:
                    missing_msg = f"Missing required parameter '{req_param}' for {res.service} {res.resource_type}"
                    if missing_msg not in plan.missing_parameters:
                        plan.missing_parameters.append(missing_msg)

        return plan

    def _create_error_plan(
        self, user_request: str, region: str, profile: str, error_message: str
    ) -> ProvisioningPlan:
        """Create a safe fallback plan containing diagnostic error info."""
        return ProvisioningPlan(
            user_request=user_request,
            intent=f"Error planning request: {user_request[:50]}",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.READ_ONLY,
            aws_profile=profile,
            aws_region=region,
            missing_parameters=[f"Planning error: {error_message}"],
            assumptions=["An error occurred during plan generation. Please rephrase your request."],
            requires_approval=False,
        )
