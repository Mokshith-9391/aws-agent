"""
Controlled Infrastructure Rollback Engine.

Executes undo operations in reverse dependency order strictly for resources
marked as CREATED_BY_THIS_PLAN. Never deletes discovered or reused resources.
Rollback operations are DESTRUCTIVE and require explicit user authorization.
"""

from __future__ import annotations

import logging
from typing import Optional

from agent.models import (
    CLICommand,
    CommandResult,
    ExecutionResult,
    ExecutionStatus,
    OperationCategory,
    ProvisioningPlan,
    ResourceOwnership,
)
from agent.resource_context import ResourceContext
from aws.cli_executor import AWSCLIExecutor

logger = logging.getLogger(__name__)


class RollbackEngine:
    """Manages ordered undo operations for failed or aborted provisioning plans."""

    def __init__(self, executor: Optional[AWSCLIExecutor] = None) -> None:
        self.executor = executor or AWSCLIExecutor()

    def generate_rollback_commands(
        self,
        plan: ProvisioningPlan,
        execution_result: ExecutionResult,
        context: ResourceContext,
    ) -> list[CLICommand]:
        """Generate an ordered list of rollback commands to undo successfully created resources.

        Requirements:
        1. Only targets resources created by this plan (ResourceOwnership.CREATED_BY_THIS_PLAN).
        2. Executes in strict REVERSE topological / execution order.
        3. Resolves all resource IDs from context before execution.
        4. Rejects commands with unresolved placeholders.
        """
        # Find which commands actually succeeded during execution
        succeeded_command_ids = {
            r.command_id for r in execution_result.command_results if r.success
        }

        # Identify resources created by this plan
        created_refs = {
            r.resource_ref: r for r in context.get_created_resources()
        }

        rollback_commands: list[CLICommand] = []

        # Iterate through plan commands in REVERSE order
        for cmd in reversed(plan.commands):
            if cmd.command_id not in succeeded_command_ids:
                continue

            # Check if this command created a resource tracked in context
            ref = cmd.resource_ref
            if ref and ref in created_refs:
                created_res = created_refs[ref]
                if created_res.ownership != ResourceOwnership.CREATED_BY_THIS_PLAN:
                    logger.info("Skipping rollback for resource '%s' with ownership '%s'", ref, created_res.ownership)
                    continue

            # Generate or use defined rollback command
            rb_cmd: Optional[CLICommand] = cmd.rollback_command

            # If no explicit rollback command, attempt to deduce one based on action
            if not rb_cmd:
                rb_cmd = self._deduce_rollback_command(cmd, ref, context)

            if rb_cmd:
                # Ensure it is marked as DESTRUCTIVE
                rb_cmd.operation_category = OperationCategory.DESTRUCTIVE
                # Recursively resolve any {{ref}} in rollback parameters
                resolved_params = context.resolve_placeholders_recursively(rb_cmd.parameters)
                resolved_cmd = rb_cmd.model_copy()
                resolved_cmd.parameters = resolved_params

                # Check for unresolved placeholders
                unresolved = context.find_unresolved_placeholders(resolved_params)
                if unresolved:
                    logger.warning(
                        "Skipping rollback command for '%s': unresolved placeholder(s) %s",
                        cmd.command_id, unresolved
                    )
                    continue

                rollback_commands.append(resolved_cmd)

        return rollback_commands

    def _deduce_rollback_command(
        self,
        cmd: CLICommand,
        resource_ref: Optional[str],
        context: ResourceContext,
    ) -> Optional[CLICommand]:
        """Deduce a rollback command for common create operations if not explicitly provided."""
        svc = cmd.service.lower()
        act = cmd.action.lower()

        # EC2 run-instances -> terminate-instances
        if svc == "ec2" and act == "run-instances":
            res_id = context.resolve_value(f"{resource_ref}.id") if resource_ref else None
            if res_id:
                return CLICommand(
                    service="ec2",
                    action="terminate-instances",
                    parameters={"instance-ids": [res_id]},
                    description=f"Terminate instance {res_id}",
                    operation_category=OperationCategory.DESTRUCTIVE,
                )

        # S3 create-bucket -> delete-bucket
        if svc == "s3api" and act == "create-bucket":
            bucket = cmd.parameters.get("bucket")
            if bucket:
                return CLICommand(
                    service="s3api",
                    action="delete-bucket",
                    parameters={"bucket": bucket},
                    description=f"Delete S3 bucket '{bucket}'",
                    operation_category=OperationCategory.DESTRUCTIVE,
                )

        # EC2 create-security-group -> delete-security-group
        if svc == "ec2" and act == "create-security-group":
            sg_id = context.resolve_value(f"{resource_ref}.id") if resource_ref else None
            if sg_id:
                return CLICommand(
                    service="ec2",
                    action="delete-security-group",
                    parameters={"group-id": sg_id},
                    description=f"Delete security group {sg_id}",
                    operation_category=OperationCategory.DESTRUCTIVE,
                )

        # EC2 create-vpc -> delete-vpc
        if svc == "ec2" and act == "create-vpc":
            vpc_id = context.resolve_value(f"{resource_ref}.id") if resource_ref else None
            if vpc_id:
                return CLICommand(
                    service="ec2",
                    action="delete-vpc",
                    parameters={"vpc-id": vpc_id},
                    description=f"Delete VPC {vpc_id}",
                    operation_category=OperationCategory.DESTRUCTIVE,
                )

        # EC2 create-subnet -> delete-subnet
        if svc == "ec2" and act == "create-subnet":
            subnet_id = context.resolve_value(f"{resource_ref}.id") if resource_ref else None
            if subnet_id:
                return CLICommand(
                    service="ec2",
                    action="delete-subnet",
                    parameters={"subnet-id": subnet_id},
                    description=f"Delete Subnet {subnet_id}",
                    operation_category=OperationCategory.DESTRUCTIVE,
                )

        return None

    def execute_rollback(
        self,
        rollback_commands: Optional[list[CLICommand]] = None,
        region: str = "ap-south-1",
        profile: str = "default",
        plan: Optional[ProvisioningPlan] = None,
        resource_context: Optional[ResourceContext] = None,
        dry_run: bool = False,
    ) -> Any:
        """Execute rollback steps or commands sequentially.

        Supports both direct CLICommand lists and structured ProvisioningPlan rollback steps.
        """
        results: list[CommandResult] = []
        all_succeeded = True

        plan_steps = (getattr(plan, "rollback_strategy", None) or getattr(plan, "rollback_steps", None)) if plan else None
        if plan_steps:
            # Sort rollback steps by order descending (reverse order)
            sorted_steps = sorted(plan_steps, key=lambda s: s.order, reverse=True)
            for step in sorted_steps:
                ref = step.resource_ref
                # Scoping check: only roll back resources created by this plan
                if resource_context and ref and not resource_context.is_resource_owned_by_plan(ref):
                    logger.info("Skipping rollback for '%s': not created by this plan", ref)
                    skipped_res = CommandResult(
                        command_id=step.command.command_id,
                        stdout="",
                        stderr="",
                        exit_code=0,
                        success=False,
                        error_message=f"Resource '{ref}' was not created by this plan; skipped rollback.",
                    )
                    results.append(skipped_res)
                    continue

                # Resolve placeholders if context available
                cmd_to_run = step.command.model_copy(deep=True)
                if resource_context:
                    try:
                        cmd_to_run.parameters = resource_context.resolve_placeholders_recursively(cmd_to_run.parameters)
                    except Exception as e:
                        logger.error("Failed resolving placeholders in rollback command: %s", e)

                result = self.executor.execute_command(
                    cmd=cmd_to_run,
                    region=region,
                    profile=profile,
                    dry_run=dry_run,
                )
                results.append(result)
                if not result.success:
                    all_succeeded = False
                    logger.error("Rollback step failed: %s | %s", cmd_to_run.to_display_string(), result.error_message)

            return results

        # Fallback to direct list of commands
        cmds = rollback_commands or []
        logger.warning("Initiating rollback of %d resources in %s (profile=%s)", len(cmds), region, profile)

        for cmd in cmds:
            result = self.executor.execute_command(
                cmd=cmd,
                region=region,
                profile=profile,
                dry_run=dry_run,
            )
            results.append(result)
            if not result.success:
                all_succeeded = False
                logger.error("Rollback step failed: %s | %s", cmd.to_display_string(), result.error_message)

        if plan is not None:
            return results
        return all_succeeded, results
