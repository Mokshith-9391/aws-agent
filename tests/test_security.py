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
