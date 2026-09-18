"""
Tests for Part B Hardening (B1 - B6).

Proves the boundaries for:
- B1: Mandatory ApprovalToken for ALL non-AUTO plans
- B2: Missing / empty / malformed plan_hash fails closed
- B3: Raw AWS resource IDs rejected for CREATE plans
- B4: Two-pass dependency resolution (forward deps, duplicates, missing refs)
- B5: Ambiguous registry lookup rejection
- B6: True compiler capability safety gate validation
"""

import pytest
from unittest.mock import MagicMock

from agent.compiler import (
    PlanCompiler,
    RawAwsIdRejectionError,
    DuplicateLogicalRefError,
    MissingLogicalRefError,
    UnsupportedResourceTypeError,
    UnsupportedConfigurationError,
)
from agent.compiler_capability import (
    CompilerCapability,
    COMPILER_CAPABILITIES,
    validate_manifest_completeness,
)
from agent.models import (
    ApprovalToken,
    ApprovalType,
    CLICommand,
    CommandResult,
    DesiredResource,
    DesiredStatePlan,
    ExecutionStatus,
    OperationType,
    ProvisioningPlan,
)
from agent.orchestrator import AgentOrchestrator
from agent.safety_gate import LiveModeSafetyGate
from config.settings import Settings, ExecutionMode
from services.registry import (
    AWSServiceRegistry,
    AmbiguousResourceTypeError,
    ResourceTypeDefinition,
    ServiceDefinition,
    create_default_registry,
)


def _build_test_plan(operation_type=OperationType.CREATE, service="s3", resource_type="bucket", cfg=None) -> ProvisioningPlan:
    compiler = PlanCompiler(create_default_registry())
    if cfg is None:
        cfg = {} if operation_type in (OperationType.LIST, OperationType.DESCRIBE) else {"bucket": "my-test-bucket-123"}
    desired = DesiredStatePlan(
        intent="Test plan",
        operation_type=operation_type,
        aws_region="ap-south-1",
        resources=[
            DesiredResource(
                logical_ref=f"{service}.{resource_type}",
                resource_type=resource_type,
                service=service,
                configuration=cfg,
            )
        ],
    )
    return compiler.compile(desired=desired, user_request="test request", region="ap-south-1")


class TestB1MandatoryApprovalToken:
    def setup_method(self):
        self.settings = Settings(DEFAULT_EXECUTION_MODE=ExecutionMode.DRY_RUN)
        self.orchestrator = AgentOrchestrator(self.settings)
        self.orchestrator._initialized = True
        self.mock_exec = MagicMock()
        self.mock_exec.execute_command.return_value = CommandResult(
            command_id="cmd-1", stdout="{}", parsed_output={}, stderr="", exit_code=0, success=True
        )
        self.orchestrator._executor = self.mock_exec

    def test_standard_write_plan_without_token_rejected(self):
        plan = _build_test_plan(operation_type=OperationType.CREATE)
        assert plan.approval_type == ApprovalType.STANDARD
        assert plan.plan_hash is not None

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
            approval_token=None,
        )
        assert resp.execution_result is None
        assert "ApprovalToken Required" in resp.message
        assert self.mock_exec.execute_command.call_count == 0

    def test_destructive_plan_without_token_rejected(self):
        plan = _build_test_plan(operation_type=OperationType.DELETE, cfg={"bucket": "my-test-bucket-123"})
        assert plan.approval_type == ApprovalType.EXPLICIT_CONFIRMATION
        assert plan.plan_hash is not None

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
            approval_token=None,
            confirmation_token="CONFIRM DELETE",
        )
        assert resp.execution_result is None
        assert "ApprovalToken Required" in resp.message
        assert self.mock_exec.execute_command.call_count == 0

    def test_valid_token_accepted(self):
        plan = _build_test_plan(operation_type=OperationType.CREATE)
        token = self.orchestrator._approval_manager.create_approval_token(plan)

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
            approval_token=token,
        )
        assert resp.execution_result is not None
        assert resp.execution_result.status == ExecutionStatus.SUCCESS

    def test_token_from_another_plan_rejected(self):
        plan_a = _build_test_plan(operation_type=OperationType.CREATE, cfg={"bucket": "bucket-aaa"})
        plan_b = _build_test_plan(operation_type=OperationType.CREATE, cfg={"bucket": "bucket-bbb"})
        token_a = self.orchestrator._approval_manager.create_approval_token(plan_a)

        resp = self.orchestrator.execute_approved_plan(
            plan=plan_b,
            region="ap-south-1",
            profile="default",
            approval_token=token_a,
        )
        assert resp.execution_result is None
        assert "Invalid Approval Token" in resp.message
        assert any("bound to plan" in w for w in resp.warnings)

    def test_token_from_stale_plan_hash_rejected(self):
        plan = _build_test_plan(operation_type=OperationType.CREATE)
        token = self.orchestrator._approval_manager.create_approval_token(plan)

        plan.commands[0].parameters["bucket"] = "tampered-bucket-target"
        plan.plan_hash = plan.compute_plan_fingerprint()

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
            approval_token=token,
        )
        assert resp.execution_result is None
        assert "Invalid Approval Token" in resp.message
        assert any("mutated" in w for w in resp.warnings)

    def test_read_only_auto_plan_executes_without_token(self):
        plan = _build_test_plan(operation_type=OperationType.LIST, cfg={})
        assert plan.approval_type == ApprovalType.AUTO

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
            approval_token=None,
        )
        assert resp.execution_result is not None
        assert resp.execution_result.status == ExecutionStatus.SUCCESS


class TestB2PlanHashFailClosed:
    def setup_method(self):
        self.settings = Settings(DEFAULT_EXECUTION_MODE=ExecutionMode.DRY_RUN)
        self.orchestrator = AgentOrchestrator(self.settings)
        self.orchestrator._initialized = True
        self.mock_exec = MagicMock()
        self.orchestrator._executor = self.mock_exec

    def test_plan_hash_none_fails_closed(self):
        plan = _build_test_plan(operation_type=OperationType.LIST, cfg={})
        plan.plan_hash = None

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
        )
        assert resp.execution_result is None
        assert "plan_hash Missing" in resp.message
        assert self.mock_exec.execute_command.call_count == 0

    def test_plan_hash_empty_string_fails_closed(self):
        plan = _build_test_plan(operation_type=OperationType.LIST, cfg={})
        plan.plan_hash = "   "

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
        )
        assert resp.execution_result is None
        assert "plan_hash Missing" in resp.message
        assert self.mock_exec.execute_command.call_count == 0

    def test_plan_hash_mismatch_fails_closed(self):
        plan = _build_test_plan(operation_type=OperationType.LIST, cfg={})
        plan.plan_hash = "deadbeef" * 8

        resp = self.orchestrator.execute_approved_plan(
            plan=plan,
            region="ap-south-1",
            profile="default",
        )
        assert resp.execution_result is None
        assert "Fingerprint Mismatch" in resp.message
        assert self.mock_exec.execute_command.call_count == 0


class TestB3RawAwsIdRejection:
    def setup_method(self):
        self.compiler = PlanCompiler(create_default_registry())

    def test_raw_ami_id_in_create_rejected(self):
        desired = DesiredStatePlan(
            intent="Create instance with hardcoded AMI",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="inst.1",
                    resource_type="instance",
                    service="ec2",
                    configuration={
                        "instance_type": "t3.micro",
                        "image_id": "ami-0123456789abcdef0",
                    },
                )
            ],
        )
        with pytest.raises((RawAwsIdRejectionError, UnsupportedConfigurationError)):
            self.compiler.compile(desired, user_request="create instance", region="ap-south-1")

    def test_raw_vpc_id_in_create_rejected(self):
        desired = DesiredStatePlan(
            intent="Create subnet with hardcoded VPC ID",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="subnet.1",
                    resource_type="subnet",
                    service="vpc",
                    configuration={
                        "cidr_block": "10.0.1.0/24",
                        "vpc_id": "vpc-0123456789abcdef0",
                    },
                )
            ],
        )
        with pytest.raises(RawAwsIdRejectionError) as excinfo:
            self.compiler.compile(desired, user_request="create subnet", region="ap-south-1")
        assert "VPC ID" in str(excinfo.value)
        assert "B3 Violation" in str(excinfo.value)

    def test_raw_security_group_id_in_create_rejected(self):
        desired = DesiredStatePlan(
            intent="Create instance with hardcoded SG ID",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="inst.1",
                    resource_type="instance",
                    service="ec2",
                    configuration={
                        "instance_type": "t3.micro",
                        "security_group_ids": ["sg-0123456789abcdef0"],
                    },
                )
            ],
        )
        with pytest.raises(RawAwsIdRejectionError) as excinfo:
            self.compiler.compile(desired, user_request="create instance", region="ap-south-1")
        assert "Security Group ID" in str(excinfo.value)

    def test_logical_ref_placeholder_allowed_in_create(self):
        desired = DesiredStatePlan(
            intent="Create VPC and subnet using logical ref",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="vpc.main",
                    resource_type="vpc",
                    service="vpc",
                    configuration={"cidr_block": "10.0.0.0/16"},
                ),
                DesiredResource(
                    logical_ref="subnet.public",
                    resource_type="subnet",
                    service="vpc",
                    configuration={
                        "cidr_block": "10.0.1.0/24",
                        "vpc_id": "{{vpc.main.id}}",
                    },
                    dependencies=["vpc.main"],
                ),
            ],
        )
        plan = self.compiler.compile(desired, user_request="create vpc and subnet", region="ap-south-1")
        assert len(plan.commands) >= 2

    def test_raw_id_allowed_in_delete_operation(self):
        desired = DesiredStatePlan(
            intent="Delete existing VPC",
            operation_type=OperationType.DELETE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="vpc.target",
                    resource_type="vpc",
                    service="vpc",
                    configuration={"vpc_id": "vpc-0123456789abcdef0"},
                )
            ],
        )
        plan = self.compiler.compile(desired, user_request="delete vpc", region="ap-south-1")
        assert len(plan.commands) == 1
        assert "delete-vpc" in plan.commands[0].action


class TestB4TwoPassDependencyResolution:
    def setup_method(self):
        self.compiler = PlanCompiler(create_default_registry())

    def test_forward_dependency_preserved(self):
        desired = DesiredStatePlan(
            intent="Forward dependency: subnet defined before VPC",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="subnet.pub",
                    resource_type="subnet",
                    service="vpc",
                    configuration={"cidr_block": "10.0.1.0/24", "vpc_id": "{{vpc.main.id}}"},
                    dependencies=["vpc.main"],
                ),
                DesiredResource(
                    logical_ref="vpc.main",
                    resource_type="vpc",
                    service="vpc",
                    configuration={"cidr_block": "10.0.0.0/16"},
                    dependencies=[],
                ),
            ],
        )
        plan = self.compiler.compile(desired, user_request="create subnet and vpc", region="ap-south-1")
        assert len(plan.commands) >= 2

        subnet_cmd = next(c for c in plan.commands if c.action == "create-subnet")
        vpc_cmd = next(c for c in plan.commands if c.action == "create-vpc")
        assert vpc_cmd.command_id in subnet_cmd.depends_on

    def test_duplicate_logical_ref_rejected(self):
        desired = DesiredStatePlan(
            intent="Duplicate logical refs",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="vpc.main",
                    resource_type="vpc",
                    service="vpc",
                    configuration={"cidr_block": "10.0.0.0/16"},
                ),
                DesiredResource(
                    logical_ref="vpc.main",
                    resource_type="vpc",
                    service="vpc",
                    configuration={"cidr_block": "10.1.0.0/16"},
                ),
            ],
        )
        with pytest.raises(DuplicateLogicalRefError) as excinfo:
            self.compiler.compile(desired, user_request="duplicate refs", region="ap-south-1")
        assert "Duplicate logical_ref 'vpc.main'" in str(excinfo.value)

    def test_missing_dependency_ref_rejected(self):
        desired = DesiredStatePlan(
            intent="Missing dependency ref",
            operation_type=OperationType.CREATE,
            aws_region="ap-south-1",
            resources=[
                DesiredResource(
                    logical_ref="subnet.pub",
                    resource_type="subnet",
                    service="vpc",
                    configuration={"cidr_block": "10.0.1.0/24"},
                    dependencies=["vpc.nonexistent"],
                ),
            ],
        )
        with pytest.raises(MissingLogicalRefError) as excinfo:
            self.compiler.compile(desired, user_request="missing dep", region="ap-south-1")
        assert "vpc.nonexistent" in str(excinfo.value)


class TestB5AmbiguousRegistryLookup:
    def test_unique_match_succeeds(self):
        registry = create_default_registry()
        lookup = registry.find_resource_type("bucket")
        assert lookup is not None
        assert lookup[0] == "s3"
        assert lookup[1].resource_type == "bucket"

    def test_exact_service_hint_disambiguates(self):
        registry = AWSServiceRegistry()
        svc1 = ServiceDefinition(service_name="ecs", cli_service="ecs", description="ECS")
        svc1.add_resource_type(ResourceTypeDefinition(service="ecs", resource_type="cluster", cli_service="ecs", description="ECS Cluster"))
        svc2 = ServiceDefinition(service_name="eks", cli_service="eks", description="EKS")
        svc2.add_resource_type(ResourceTypeDefinition(service="eks", resource_type="cluster", cli_service="eks", description="EKS Cluster"))
        registry.register_service(svc1)
        registry.register_service(svc2)

        res = registry.find_resource_type("cluster", service="ecs")
        assert res is not None
        assert res[0] == "ecs"

    def test_ambiguous_type_without_service_hint_raises(self):
        registry = AWSServiceRegistry()
        svc1 = ServiceDefinition(service_name="ecs", cli_service="ecs", description="ECS")
        svc1.add_resource_type(ResourceTypeDefinition(service="ecs", resource_type="cluster", cli_service="ecs", description="ECS Cluster"))
        svc2 = ServiceDefinition(service_name="eks", cli_service="eks", description="EKS")
        svc2.add_resource_type(ResourceTypeDefinition(service="eks", resource_type="cluster", cli_service="eks", description="EKS Cluster"))
        registry.register_service(svc1)
        registry.register_service(svc2)

        with pytest.raises(AmbiguousResourceTypeError) as excinfo:
            registry.find_resource_type("cluster")
        assert "ambiguous" in str(excinfo.value).lower()
        assert "ecs" in excinfo.value.matching_services
        assert "eks" in excinfo.value.matching_services

    def test_unknown_type_returns_none(self):
        registry = create_default_registry()
        res = registry.find_resource_type("nonexistent_quantum_gadget")
        assert res is None


class TestB6CompilerCompletenessSafetyGate:
    def test_manifest_completeness_passes(self):
        issues = validate_manifest_completeness()
        assert len(issues) == 0, f"Manifest issues found: {issues}"

    def test_safety_gate_passes_with_mock_executor(self):
        registry = create_default_registry()
        mock_exec = MagicMock()
        gate = LiveModeSafetyGate(registry=registry, executor=mock_exec)
        report = gate.check_readiness(check_credentials=False)
        assert report.is_live_ready is True
        assert len(report.issues) == 0

    def test_incomplete_capability_detected_by_gate(self, monkeypatch):
        flawed_cap = CompilerCapability(
            service="test_svc",
            resource_type="broken_resource",
            cli_service="nonexistent_cli_svc",
            supports_create=True,
            create_cli_action="create-broken",
            has_create_schema=True,
        )
        monkeypatch.setattr(
            "agent.safety_gate.COMPILER_CAPABILITIES",
            COMPILER_CAPABILITIES + [flawed_cap],
        )

        mock_exec = MagicMock()
        gate = LiveModeSafetyGate(executor=mock_exec)
        report = gate.check_readiness(check_credentials=False)
        assert report.is_live_ready is False
        assert any("test_svc.broken_resource" in issue for issue in report.issues)