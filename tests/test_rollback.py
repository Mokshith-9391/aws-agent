from unittest.mock import MagicMock
import pytest
from agent.models import (
    CLICommand,
    CommandResult,
    LogicalResource,
    OperationCategory,
    OperationType,
    ProvisioningPlan,
    ResourceOwnership,
    RollbackStep,
)
from agent.resource_context import ResourceContext
from agent.rollback import RollbackEngine


class TestRollbackEngine:
    def setup_method(self):
        self.mock_executor = MagicMock()
        self.rollback_engine = RollbackEngine(self.mock_executor)
        self.context = ResourceContext()

    def test_rollback_only_created_by_this_plan(self):
        # Resource 1: Created by this plan -> MUST be rolled back
        self.context.register_resource(
            LogicalResource(
                resource_ref="vpc.created",
                service="ec2",
                resource_type="vpc",
                resource_id="vpc-new-123",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )
        # Resource 2: Reused from existing -> MUST NOT be rolled back
        self.context.register_resource(
            LogicalResource(
                resource_ref="vpc.existing",
                service="ec2",
                resource_type="vpc",
                resource_id="vpc-existing-999",
                ownership=ResourceOwnership.REUSED_FROM_EXISTING,
            )
        )

        plan = ProvisioningPlan(
            user_request="Test rollback scoping",
            intent="Test rollback",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            rollback_steps=[
                RollbackStep(
                    order=1,
                    resource_description="Delete created VPC",
                    command=CLICommand(
                        service="ec2",
                        action="delete-vpc",
                        parameters={"vpc-id": "{{vpc.created.id}}"},
                        description="Delete created VPC",
                        operation_category=OperationCategory.DESTRUCTIVE,
                    ),
                    resource_ref="vpc.created",
                ),
                RollbackStep(
                    order=2,
                    resource_description="Delete existing VPC",
                    command=CLICommand(
                        service="ec2",
                        action="delete-vpc",
                        parameters={"vpc-id": "{{vpc.existing.id}}"},
                        description="Delete existing VPC",
                        operation_category=OperationCategory.DESTRUCTIVE,
                    ),
                    resource_ref="vpc.existing",
                ),
            ],
        )

        # Mock successful execution of the command that actually runs
        self.mock_executor.execute_command.return_value = CommandResult(
            command_id="test",
            stdout="{}",
            stderr="",
            exit_code=0,
            success=True,
        )

        results = self.rollback_engine.execute_rollback(
            plan=plan,
            resource_context=self.context,
            region="ap-south-1",
            profile="default",
            dry_run=False,
        )

        # Check that execute_command was called ONLY ONCE (for the created VPC, NOT the existing one)
        assert self.mock_executor.execute_command.call_count == 1
        executed_cmd = self.mock_executor.execute_command.call_args[1]["cmd"]
        assert executed_cmd.parameters["vpc-id"] == "vpc-new-123"

        # Results should have 2 entries: 1 SUCCESS, 1 SKIPPED
        assert len(results) == 2
        success_steps = [r for r in results if r.success]
        skipped_steps = [r for r in results if not r.success and "not created by this plan" in (r.error_message or "")]
        assert len(success_steps) == 1
        assert len(skipped_steps) == 1

    def test_rollback_reverse_order(self):
        # Register both resources
        self.context.register_resource(
            LogicalResource(
                resource_ref="res.first",
                service="ec2",
                resource_type="vpc",
                resource_id="vpc-1",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )
        self.context.register_resource(
            LogicalResource(
                resource_ref="res.second",
                service="ec2",
                resource_type="subnet",
                resource_id="sub-2",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )

        plan = ProvisioningPlan(
            user_request="Test ordering",
            intent="Test ordering",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            rollback_steps=[
                RollbackStep(
                    order=1,
                    resource_description="Step 1",
                    command=CLICommand(
                        service="ec2", action="delete-vpc", parameters={"vpc-id": "vpc-1"},
                        description="Delete vpc", operation_category=OperationCategory.DESTRUCTIVE,
                    ),
                    resource_ref="res.first",
                ),
                RollbackStep(
                    order=2,
                    resource_description="Step 2",
                    command=CLICommand(
                        service="ec2", action="delete-subnet", parameters={"subnet-id": "sub-2"},
                        description="Delete subnet", operation_category=OperationCategory.DESTRUCTIVE,
                    ),
                    resource_ref="res.second",
                ),
            ],
        )

        executed_actions = []

        def fake_exec(cmd, **kwargs):
            executed_actions.append(cmd.action)
            return CommandResult(command_id=cmd.command_id, stdout="{}", stderr="", exit_code=0, success=True)

        self.mock_executor.execute_command.side_effect = fake_exec

        self.rollback_engine.execute_rollback(
            plan=plan,
            resource_context=self.context,
            region="ap-south-1",
            profile="default",
            dry_run=False,
        )

        # Higher order executed first
        assert executed_actions == ["delete-subnet", "delete-vpc"]

    def test_generate_rollback_commands_midflight_failure(self):
        """Test rollback command generation when plan partially fails at step 3."""
        # Setup resources in context
        self.context.register_resource(
            LogicalResource(
                resource_ref="vpc.main",
                service="vpc",
                cli_service="ec2",
                resource_type="vpc",
                resource_id="vpc-11111",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )
        self.context.register_resource(
            LogicalResource(
                resource_ref="subnet.main",
                service="vpc",
                cli_service="ec2",
                resource_type="subnet",
                resource_id="subnet-22222",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )

        cmd1 = CLICommand(
            command_id="cmd-1",
            service="ec2",
            action="create-vpc",
            parameters={"cidr-block": "10.0.0.0/16"},
            resource_ref="vpc.main",
            rollback_command=CLICommand(
                command_id="rb-1",
                service="ec2",
                action="delete-vpc",
                parameters={"vpc-id": "{{vpc.main.id}}"},
                operation_category=OperationCategory.DESTRUCTIVE,
            ),
        )
        cmd2 = CLICommand(
            command_id="cmd-2",
            service="ec2",
            action="create-subnet",
            parameters={"vpc-id": "{{vpc.main.id}}", "cidr-block": "10.0.1.0/24"},
            resource_ref="subnet.main",
            rollback_command=CLICommand(
                command_id="rb-2",
                service="ec2",
                action="delete-subnet",
                parameters={"subnet-id": "{{subnet.main.id}}"},
                operation_category=OperationCategory.DESTRUCTIVE,
            ),
        )
        cmd3 = CLICommand(
            command_id="cmd-3",
            service="ec2",
            action="run-instances",
            parameters={"subnet-id": "{{subnet.main.id}}"},
            resource_ref="ec2.instance",
        )

        plan = ProvisioningPlan(
            user_request="Build VPC, subnet and EC2",
            intent="Build VPC, subnet and EC2",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            commands=[cmd1, cmd2, cmd3],
        )

        from agent.models import ExecutionResult, CommandExecutionStatus
        exec_result = ExecutionResult(
            plan_id=plan.plan_id,
            command_results=[
                CommandResult(command_id="cmd-1", exit_code=0, success=True, status=CommandExecutionStatus.SUCCESS),
                CommandResult(command_id="cmd-2", exit_code=0, success=True, status=CommandExecutionStatus.SUCCESS),
                CommandResult(command_id="cmd-3", exit_code=1, success=False, status=CommandExecutionStatus.FAILED, error_message="InsufficientCapacity"),
            ],
        )

        rb_cmds = self.rollback_engine.generate_rollback_commands(
            plan=plan,
            execution_result=exec_result,
            context=self.context,
        )

        # Only succeeded commands with rollback definitions are rolled back (cmd2, then cmd1)
        assert len(rb_cmds) == 2
        assert rb_cmds[0].action == "delete-subnet"
        assert rb_cmds[0].parameters["subnet-id"] == "subnet-22222"
        assert rb_cmds[1].action == "delete-vpc"
        assert rb_cmds[1].parameters["vpc-id"] == "vpc-11111"

    def test_rollback_skips_unresolved_placeholders(self):
        """Test that rollback commands with unresolvable placeholders are skipped safely."""
        cmd1 = CLICommand(
            command_id="cmd-1",
            service="ec2",
            action="create-vpc",
            parameters={"cidr-block": "10.0.0.0/16"},
            resource_ref="vpc.orphan",
            rollback_command=CLICommand(
                command_id="rb-1",
                service="ec2",
                action="delete-vpc",
                parameters={"vpc-id": "{{unregistered_ref.id}}"},
                operation_category=OperationCategory.DESTRUCTIVE,
            ),
        )
        plan = ProvisioningPlan(
            user_request="Build orphaned vpc",
            intent="Build orphaned vpc",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            commands=[cmd1],
        )
        from agent.models import ExecutionResult, CommandExecutionStatus
        exec_result = ExecutionResult(
            plan_id=plan.plan_id,
            command_results=[
                CommandResult(command_id="cmd-1", exit_code=0, success=True, status=CommandExecutionStatus.SUCCESS),
            ],
        )

        rb_cmds = self.rollback_engine.generate_rollback_commands(
            plan=plan,
            execution_result=exec_result,
            context=self.context,
        )
        # Should be empty because placeholder cannot be resolved
        assert len(rb_cmds) == 0

