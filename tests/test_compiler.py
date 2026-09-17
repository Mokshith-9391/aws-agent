"""
Comprehensive Unit Tests for the PlanCompiler Layer.

Tests desired-state compilation across S3, EC2, VPC networking, IAM,
DynamoDB, and validates error handling for unsupported resource types.
"""

import pytest
from agent.compiler import PlanCompiler, UnsupportedResourceTypeError
from agent.models import (
    ApprovalType,
    DesiredResource,
    DesiredStatePlan,
    OperationCategory,
    OperationType,
    ResourceOwnership,
    RiskLevel,
)
from services.registry import create_default_registry


class TestPlanCompiler:
    def setup_method(self):
        self.registry = create_default_registry()
        self.compiler = PlanCompiler(registry=self.registry)

    def test_s3_bucket_non_us_east_1(self):
        """Test compiling S3 bucket in ap-south-1 sets LocationConstraint."""
        desired = DesiredStatePlan(
            intent="Create an S3 bucket in Mumbai",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="s3.my_bucket",
                    resource_type="bucket",
                    service="s3",
                    resource_name="my-cool-bucket-12345",
                    configuration={"bucket": "my-cool-bucket-12345"},
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Create an S3 bucket in Mumbai",
            region="ap-south-1",
            profile="test-profile",
        )

        assert len(plan.commands) == 1
        create_cmd = plan.commands[0]
        assert create_cmd.service == "s3api"
        assert create_cmd.action == "create-bucket"
        assert create_cmd.parameters["bucket"] == "my-cool-bucket-12345"
        assert create_cmd.parameters["create-bucket-configuration"] == "LocationConstraint=ap-south-1"
        assert create_cmd.operation_category == OperationCategory.WRITE
        assert create_cmd.profile == "test-profile"
        assert create_cmd.region == "ap-south-1"

        # Verification step
        assert len(plan.verification_steps) == 1
        ver_cmd = plan.verification_steps[0]
        assert ver_cmd.service == "s3api"
        assert ver_cmd.action == "head-bucket"
        assert ver_cmd.parameters["bucket"] == "my-cool-bucket-12345"

        # Rollback strategy
        assert len(plan.rollback_strategy) == 1
        rb_step = plan.rollback_strategy[0]
        assert rb_step.command.action == "delete-bucket"
        assert rb_step.command.parameters["bucket"] == "my-cool-bucket-12345"

    def test_s3_bucket_us_east_1(self):
        """Test compiling S3 bucket in us-east-1 omits LocationConstraint."""
        desired = DesiredStatePlan(
            intent="Create an S3 bucket in us-east-1",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="s3.bucket_east",
                    resource_type="bucket",
                    service="s3",
                    resource_name="east-bucket-999",
                    configuration={"bucket": "east-bucket-999"},
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Create an S3 bucket in us-east-1",
            region="us-east-1",
            profile="default",
        )

        assert len(plan.commands) == 1
        create_cmd = plan.commands[0]
        assert "create-bucket-configuration" not in create_cmd.parameters
        assert create_cmd.parameters["bucket"] == "east-bucket-999"

    def test_ec2_instance_compilation(self):
        """Test compiling EC2 instance with deterministic AMI discovery and parameter mapping."""
        desired = DesiredStatePlan(
            intent="Launch EC2 web instance",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="ec2.web",
                    resource_type="instance",
                    service="ec2",
                    resource_name="web-server",
                    configuration={
                        "instance_type": "t3.small",
                        "subnet_id": "subnet-12345",
                        "security_group_ids": ["sg-12345"],
                    },
                    tags={"Name": "web-server", "Env": "test"},
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Launch t3.small EC2 web server in subnet-12345",
            region="us-west-2",
            profile="prod",
        )

        assert len(plan.commands) == 1
        cmd = plan.commands[0]
        assert cmd.service == "ec2"
        assert cmd.action == "run-instances"
        assert cmd.parameters["instance-type"] == "t3.small"
        assert cmd.parameters["subnet-id"] == "subnet-12345"
        assert cmd.parameters["security-group-ids"] == ["sg-12345"]
        assert cmd.parameters["image-id"].startswith("ami-")
        assert plan.risk_level == RiskLevel.MEDIUM
        assert plan.approval_type == ApprovalType.STANDARD

        # Logical resource checks
        assert len(plan.logical_resources) == 1
        lr = plan.logical_resources[0]
        assert lr.resource_ref == "ec2.web"
        assert lr.domain_service == "ec2"
        assert lr.resource_type == "instance"
        assert lr.ownership == ResourceOwnership.CREATED_BY_THIS_PLAN

        # Rollback command
        assert cmd.rollback_command is not None
        assert cmd.rollback_command.action == "terminate-instances"

    def test_custom_vpc_chain_compilation(self):
        """Test compiling a multi-resource VPC chain: VPC -> Subnet -> SG -> EC2."""
        desired = DesiredStatePlan(
            intent="Create VPC infrastructure with EC2",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="vpc.main",
                    resource_type="vpc",
                    service="vpc",
                    configuration={"cidr_block": "10.0.0.0/16"},
                    tags={"Name": "Production-VPC"},
                ),
                DesiredResource(
                    logical_ref="subnet.public",
                    resource_type="subnet",
                    service="vpc",
                    configuration={
                        "vpc_id": "{{vpc.main.id}}",
                        "cidr_block": "10.0.1.0/24",
                        "availability_zone": "ap-south-1a",
                    },
                    dependencies=["vpc.main"],
                ),
                DesiredResource(
                    logical_ref="sg.web",
                    resource_type="security_group",
                    service="vpc",
                    configuration={
                        "group_name": "web-sg",
                        "description": "Allow web traffic",
                        "vpc_id": "{{vpc.main.id}}",
                        "ports": [80, 443],
                    },
                    dependencies=["vpc.main"],
                ),
                DesiredResource(
                    logical_ref="ec2.app",
                    resource_type="instance",
                    service="ec2",
                    configuration={
                        "subnet_id": "{{subnet.public.id}}",
                        "security_group_ids": ["{{sg.web.id}}"],
                    },
                    dependencies=["subnet.public", "sg.web"],
                ),
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Build full VPC with EC2",
            region="ap-south-1",
        )

        actions = [c.action for c in plan.commands]
        assert "create-vpc" in actions
        assert "create-subnet" in actions
        assert "create-security-group" in actions
        assert actions.count("authorize-security-group-ingress") == 2
        assert "run-instances" in actions

        sg_cmds = [c for c in plan.commands if c.action == "authorize-security-group-ingress"]
        for sg_c in sg_cmds:
            assert sg_c.parameters["group-id"] == "{{sg.web.id}}"

        ec2_cmd = next(c for c in plan.commands if c.action == "run-instances")
        assert ec2_cmd.parameters["subnet-id"] == "{{subnet.public.id}}"
        assert ec2_cmd.parameters["security-group-ids"] == ["{{sg.web.id}}"]

        assert len(plan.rollback_strategy) >= 4

    def test_iam_role_compilation(self):
        """Test compiling IAM role with assume-role policy document."""
        desired = DesiredStatePlan(
            intent="Create IAM Role for EC2",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="iam.role",
                    resource_type="role",
                    service="iam",
                    resource_name="AppExecutionRole",
                    configuration={"description": "Execution role for app"},
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Create IAM Role for EC2",
            region="us-east-1",
        )

        assert len(plan.commands) == 1
        cmd = plan.commands[0]
        assert cmd.service == "iam"
        assert cmd.action == "create-role"
        assert cmd.parameters["role-name"] == "AppExecutionRole"
        assert "assume-role-policy-document" in cmd.parameters
        assert plan.risk_level == RiskLevel.HIGH
        assert plan.approval_type == ApprovalType.EXPLICIT_CONFIRMATION

    def test_dynamodb_table_compilation(self):
        """Test compiling DynamoDB table."""
        desired = DesiredStatePlan(
            intent="Create DynamoDB table for orders",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="dynamodb.orders",
                    resource_type="table",
                    service="dynamodb",
                    resource_name="OrdersTable",
                    configuration={
                        "table_name": "OrdersTable",
                        "billing_mode": "PAY_PER_REQUEST",
                    },
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Create DynamoDB OrdersTable",
            region="ap-south-1",
        )

        assert len(plan.commands) == 1
        cmd = plan.commands[0]
        assert cmd.service == "dynamodb"
        assert cmd.action == "create-table"
        assert cmd.parameters["table-name"] == "OrdersTable"
        assert cmd.parameters["billing-mode"] == "PAY_PER_REQUEST"

    def test_unsupported_resource_type_raises_error(self):
        """Test that unknown or malicious resource types raise UnsupportedResourceTypeError."""
        desired = DesiredStatePlan(
            intent="Create illegal resource",
            operation_type=OperationType.CREATE,
            resources=[
                DesiredResource(
                    logical_ref="bad.resource",
                    resource_type="bitcoin_miner",
                    service="unknown_svc",
                )
            ],
        )

        with pytest.raises(UnsupportedResourceTypeError) as excinfo:
            self.compiler.compile(
                desired=desired,
                user_request="Deploy bitcoin miner",
                region="ap-south-1",
            )
        assert "Unsupported resource type 'bitcoin_miner'" in str(excinfo.value)

    def test_read_only_operation_compilation(self):
        """Test compiling describe-instances read-only operation."""
        desired = DesiredStatePlan(
            intent="List EC2 instances",
            operation_type=OperationType.LIST,
            resources=[
                DesiredResource(
                    logical_ref="ec2.query",
                    resource_type="instance",
                    service="ec2",
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Show me all running EC2 instances",
            region="ap-south-1",
        )

        assert len(plan.commands) == 1
        cmd = plan.commands[0]
        assert cmd.service == "ec2"
        assert cmd.action == "describe-instances"
        assert cmd.operation_category == OperationCategory.READ_ONLY
        assert plan.operation_category == OperationCategory.READ_ONLY
        assert plan.requires_approval is False
        assert plan.approval_type == ApprovalType.AUTO

    def test_destructive_delete_operation_compilation(self):
        """Test compiling delete-bucket operation."""
        desired = DesiredStatePlan(
            intent="Delete an S3 bucket",
            operation_type=OperationType.DELETE,
            resources=[
                DesiredResource(
                    logical_ref="s3.delete_target",
                    resource_type="bucket",
                    service="s3",
                    resource_name="old-unused-bucket",
                )
            ],
        )

        plan = self.compiler.compile(
            desired=desired,
            user_request="Delete old-unused-bucket",
            region="ap-south-1",
        )

        assert len(plan.commands) == 1
        cmd = plan.commands[0]
        assert cmd.service == "s3api"
        assert cmd.action == "delete-bucket"
        assert cmd.operation_category == OperationCategory.DESTRUCTIVE
        assert plan.operation_category == OperationCategory.DESTRUCTIVE
        assert plan.destructive_operations is True
        assert plan.requires_approval is True
        assert plan.approval_type == ApprovalType.EXPLICIT_CONFIRMATION
