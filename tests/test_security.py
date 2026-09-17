import pytest
from agent.models import (
    ProvisioningPlan, OperationType, OperationCategory, 
    RiskLevel, CLICommand, CommandResult
)
from security.policy import SafetyPolicyEngine
from security.sanitizer import OutputSanitizer
from security.approvals import ApprovalManager

class TestSafetyPolicy:
    def setup_method(self):
        self.engine = SafetyPolicyEngine()
    
    def test_read_only_is_safe(self):
        plan = ProvisioningPlan(
            user_request='List EC2 instances',
            intent='List instances',
            operation_type=OperationType.LIST,
            operation_category=OperationCategory.READ_ONLY,
            aws_region='ap-south-1',
        )
        is_safe, warnings, blocking = self.engine.evaluate_plan(plan)
        assert is_safe
        assert len(blocking) == 0
    
    def test_risk_assessment_read_only(self):
        plan = ProvisioningPlan(
            user_request='Describe VPC',
            intent='Describe VPC',
            operation_type=OperationType.DESCRIBE,
            operation_category=OperationCategory.READ_ONLY,
            aws_region='ap-south-1',
        )
        risk = self.engine.assess_risk(plan)
        assert risk == RiskLevel.LOW
    
    def test_destructive_requires_confirmation(self):
        plan = ProvisioningPlan(
            user_request='Delete all EC2 instances',
            intent='Delete all instances',
            operation_type=OperationType.DELETE,
            operation_category=OperationCategory.DESTRUCTIVE,
            aws_region='ap-south-1',
            destructive_operations=True,
            commands=[
                CLICommand(
                    service='ec2', action='terminate-instances',
                    parameters={'instance-ids': 'i-123'},
                    description='Terminate instance',
                    operation_category=OperationCategory.DESTRUCTIVE
                )
            ]
        )
        assert self.engine.requires_explicit_confirmation(plan)

    def test_iam_wildcard_policy_blocked(self):
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        plan = ProvisioningPlan(
            user_request="Create admin policy",
            intent="Create policy",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            commands=[
                CLICommand(
                    service="iam",
                    action="create-policy",
                    parameters={"policy-name": "BadAdmin", "policy-document": policy_doc},
                    description="Wildcard policy",
                    operation_category=OperationCategory.WRITE,
                )
            ]
        )
        is_safe, warnings, blocking = self.engine.evaluate_plan(plan)
        assert not is_safe
        assert any("wildcard" in b.lower() for b in blocking)

    def test_iam_admin_access_blocked(self):
        plan = ProvisioningPlan(
            user_request="Attach admin",
            intent="Attach admin",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            commands=[
                CLICommand(
                    service="iam",
                    action="attach-role-policy",
                    parameters={"role-name": "TestRole", "policy-arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                    description="Admin attach",
                    operation_category=OperationCategory.WRITE,
                )
            ]
        )
        is_safe, warnings, blocking = self.engine.evaluate_plan(plan)
        assert not is_safe
        assert any("administratoraccess" in b.lower() for b in blocking)

    def test_open_all_ports_blocked(self):
        plan = ProvisioningPlan(
            user_request="Open all ports",
            intent="Open all ports",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            commands=[
                CLICommand(
                    service="ec2",
                    action="authorize-security-group-ingress",
                    parameters={"group-name": "open-sg", "protocol": "-1", "cidr": "0.0.0.0/0"},
                    description="Open everything",
                    operation_category=OperationCategory.WRITE,
                )
            ]
        )
        is_safe, warnings, blocking = self.engine.evaluate_plan(plan)
        assert not is_safe
        assert any("opening all ports" in b.lower() for b in blocking)

    def test_ssh_port_warning(self):
        plan = ProvisioningPlan(
            user_request="Open SSH to world",
            intent="Open SSH",
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region="ap-south-1",
            commands=[
                CLICommand(
                    service="ec2",
                    action="authorize-security-group-ingress",
                    parameters={"group-name": "ssh-sg", "protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
                    description="Open SSH",
                    operation_category=OperationCategory.WRITE,
                )
            ]
        )
        is_safe, warnings, blocking = self.engine.evaluate_plan(plan)
        assert is_safe  # SSH to world is warned, not blocked
        assert any("ssh (port 22)" in w.lower() for w in warnings)

    def test_max_commands_per_plan_exceeded_blocked(self):
        commands = [
            CLICommand(
                command_id=f"cmd-{i}",
                service="ec2",
                action="describe-instances",
                parameters={},
                description=f"Cmd {i}",
                operation_category=OperationCategory.READ_ONLY,
            )
            for i in range(30)  # Default limit is 25
        ]
        plan = ProvisioningPlan(
            user_request="Too many commands",
            intent="Run 30 commands",
            operation_type=OperationType.DESCRIBE,
            operation_category=OperationCategory.READ_ONLY,
            aws_region="ap-south-1",
            commands=commands,
        )
        is_safe, warnings, blocking = self.engine.evaluate_plan(plan)
        assert not is_safe
        assert any("exceeding the maximum allowed limit" in b.lower() for b in blocking)

class TestSanitizer:
    def setup_method(self):
        self.sanitizer = OutputSanitizer()
    
    def test_redact_access_key(self):
        text = 'Key: AKIAIOSFODNN7EXAMPLE'
        result = self.sanitizer.sanitize(text)
        assert 'AKIAIOSFODNN7EXAMPLE' not in result
    
    def test_safe_text_unchanged(self):
        text = 'VPC vpc-12345 created successfully'
        result = self.sanitizer.sanitize(text)
        assert 'vpc-12345' in result
    
    def test_sanitize_command_output(self):
        cr = CommandResult(
            command_id='test',
            stdout='AccessKey: AKIAIOSFODNN7EXAMPLE',
            stderr='',
            success=True,
            exit_code=0,
        )
        sanitized = self.sanitizer.sanitize_command_output(cr)
        assert 'AKIAIOSFODNN7EXAMPLE' not in sanitized.stdout

class TestApprovalManager:
    def setup_method(self):
        self.manager = ApprovalManager()
    
    def test_read_only_auto_approved(self):
        plan = ProvisioningPlan(
            user_request='List buckets',
            intent='List S3 buckets',
            operation_type=OperationType.LIST,
            operation_category=OperationCategory.READ_ONLY,
            aws_region='ap-south-1',
        )
        result = self.manager.determine_approval_requirement(plan)
        assert result['requires_approval'] is False
        assert result['approval_type'] == 'auto'
    
    def test_write_requires_standard_approval(self):
        plan = ProvisioningPlan(
            user_request='Create bucket',
            intent='Create S3 bucket',
            operation_type=OperationType.CREATE,
            operation_category=OperationCategory.WRITE,
            aws_region='ap-south-1',
        )
        result = self.manager.determine_approval_requirement(plan)
        assert result['requires_approval'] is True
        assert result['approval_type'] == 'standard'
    
    def test_destructive_requires_explicit(self):
        plan = ProvisioningPlan(
            user_request='Delete bucket',
            intent='Delete S3 bucket',
            operation_type=OperationType.DELETE,
            operation_category=OperationCategory.DESTRUCTIVE,
            aws_region='ap-south-1',
            destructive_operations=True,
            risk_level=RiskLevel.HIGH,
        )
        result = self.manager.determine_approval_requirement(plan)
        assert result['requires_approval'] is True
        assert result['approval_type'] == 'explicit_confirmation'
