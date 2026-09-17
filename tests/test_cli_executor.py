import json
import pytest
from unittest.mock import patch, MagicMock
import subprocess

from agent.models import CLICommand, OperationCategory, CommandResult
from aws.cli_executor import AWSCLIExecutor


class TestAWSCLIExecutor:
    def setup_method(self):
        self.executor = AWSCLIExecutor(timeout=10)

    def test_dry_run_execution(self):
        cmd = CLICommand(
            service="ec2",
            action="describe-instances",
            parameters={},
            description="Test describe",
            operation_category=OperationCategory.READ_ONLY,
        )
        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=True)
        assert result.success is True
        assert "dry run" in result.stdout

    def test_disallowed_service(self):
        cmd = CLICommand(
            service="unauthorized_service",
            action="hack",
            parameters={},
            description="Bad service",
            operation_category=OperationCategory.READ_ONLY,
        )
        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "ServiceNotAllowed"

    def test_disallowed_action(self):
        cmd = CLICommand(
            service="ec2",
            action="non-existent-action",
            parameters={},
            description="Bad action",
            operation_category=OperationCategory.READ_ONLY,
        )
        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "ActionNotAllowed"

    @patch("subprocess.run")
    def test_profile_and_region_propagation(self, mock_run):
        """Critical Fix #1: Prove selected profile & region propagate to subprocess args and env."""
        mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")

        cmd = CLICommand(
            service="ec2",
            action="describe-vpcs",
            parameters={},
            description="Test profile propagation",
            operation_category=OperationCategory.READ_ONLY,
        )

        result = self.executor.execute_command(
            cmd=cmd,
            region="us-west-2",
            profile="my-dev-profile",
            dry_run=False,
        )
        assert result.success is True

        args_called = mock_run.call_args[0][0]
        # Verify --profile was explicitly included in arguments array
        assert "--profile" in args_called
        profile_idx = args_called.index("--profile")
        assert args_called[profile_idx + 1] == "my-dev-profile"

        # Verify --region was explicitly included in arguments array
        assert "--region" in args_called
        region_idx = args_called.index("--region")
        assert args_called[region_idx + 1] == "us-west-2"

        # Verify environment variables match
        env_called = mock_run.call_args.kwargs.get("env", {})
        assert env_called.get("AWS_PROFILE") == "my-dev-profile"
        assert env_called.get("AWS_DEFAULT_REGION") == "us-west-2"

    def test_unresolved_placeholder_rejected(self):
        """Critical Fix #5: An unresolved placeholder must block execution."""
        cmd = CLICommand(
            service="ec2",
            action="create-subnet",
            parameters={"vpc-id": "{{vpc.main.id}}", "cidr-block": "10.0.1.0/24"},
            description="Subnet with unresolved placeholder",
            operation_category=OperationCategory.WRITE,
        )

        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "UnresolvedPlaceholder"
        assert "unresolved" in result.stderr.lower()

    @patch("subprocess.run")
    def test_successful_command_execution(self, mock_run):
        mock_output = json.dumps({"Vpc": {"VpcId": "vpc-0123456789abcdef0"}})
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=mock_output,
            stderr="",
        )

        cmd = CLICommand(
            service="ec2",
            action="create-vpc",
            parameters={"cidr-block": "10.0.0.0/16"},
            description="Create test VPC",
            operation_category=OperationCategory.WRITE,
        )

        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=False)
        assert result.success is True
        assert result.exit_code == 0
        assert result.resource_ids.get("VpcId") == "vpc-0123456789abcdef0"
        # Verify shell=False was enforced
        assert mock_run.call_args.kwargs.get("shell") is False

    @patch("subprocess.run")
    def test_command_failure_handling(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=254,
            stdout="",
            stderr="An error occurred (UnauthorizedOperation) when calling the RunInstances operation: You are not authorized to perform this operation.",
        )

        cmd = CLICommand(
            service="ec2",
            action="run-instances",
            parameters={"image-id": "ami-12345678", "instance-type": "t3.micro"},
            description="Launch instance",
            operation_category=OperationCategory.WRITE,
        )

        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=False)
        assert result.success is False
        assert result.exit_code == 254
        assert result.error_type == "UnauthorizedOperation"

    @patch("subprocess.run")
    def test_command_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="aws", timeout=10)

        cmd = CLICommand(
            service="ec2",
            action="describe-instances",
            parameters={},
            description="Timeout test",
            operation_category=OperationCategory.READ_ONLY,
        )

        result = self.executor.execute_command(cmd, region="ap-south-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "Timeout"

    def test_extract_resource_ids(self):
        sample_json = {
            "Instances": [{"InstanceId": "i-0123456789abcdef0"}],
            "Vpc": {"VpcId": "vpc-0987654321fedcba0"},
            "Role": {"RoleName": "MyTestRole", "Arn": "arn:aws:iam::123456789012:role/MyTestRole"},
        }
        ids = self.executor._extract_resource_ids(sample_json)
        assert ids.get("InstanceId") == "i-0123456789abcdef0"
        assert ids.get("VpcId") == "vpc-0987654321fedcba0"
        assert ids.get("RoleName") == "MyTestRole"
        assert ids.get("Arn") == "arn:aws:iam::123456789012:role/MyTestRole"

    def test_unlisted_service_route53_rejected(self):
        """Verify unmaintained/unregistered service route53 is strictly rejected."""
        cmd = CLICommand(
            service="route53",
            action="list-hosted-zones",
            parameters={},
            description="List hosted zones",
            operation_category=OperationCategory.READ_ONLY,
        )
        result = self.executor.execute_command(cmd, region="us-east-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "ServiceNotAllowed"
        assert "not in the allowlist" in result.stderr

    def test_unlisted_service_fake_rejected(self):
        """Verify arbitrary unknown service is strictly rejected."""
        cmd = CLICommand(
            service="fake_svc",
            action="pwn",
            parameters={},
            description="Exploit attempt",
            operation_category=OperationCategory.READ_ONLY,
        )
        result = self.executor.execute_command(cmd, region="us-east-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "ServiceNotAllowed"

    def test_unregistered_action_rejected(self):
        """Verify unapproved action on allowed service ec2 is strictly rejected."""
        cmd = CLICommand(
            service="ec2",
            action="delete-account",
            parameters={},
            description="Non-existent/disallowed ec2 action",
            operation_category=OperationCategory.DESTRUCTIVE,
        )
        result = self.executor.execute_command(cmd, region="us-east-1", dry_run=False)
        assert result.success is False
        assert result.error_type == "ActionNotAllowed"

    def test_complex_parameter_serialization_tag_specifications(self):
        """Verify complex parameters like tag specifications serialize to valid JSON strings in CLI args."""
        tags = [
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "WebServer"}, {"Key": "Env", "Value": "Prod"}],
            }
        ]
        cmd = CLICommand(
            service="ec2",
            action="run-instances",
            parameters={
                "image-id": "ami-12345678",
                "instance-type": "t3.micro",
                "tag-specifications": tags,
            },
            description="Launch instance with tags",
            operation_category=OperationCategory.WRITE,
        )

        args = cmd.to_cli_args(profile="default", region="ap-south-1")
        assert "--tag-specifications" in args
        idx = args.index("--tag-specifications")
        json_val = args[idx + 1]

        # Must parse as valid JSON matching the input structure
        parsed = json.loads(json_val)
        assert parsed == tags
        assert parsed[0]["ResourceType"] == "instance"
        assert parsed[0]["Tags"][0]["Key"] == "Name"

    def test_dict_parameter_serialization(self):
        """Verify dict parameters serialize to valid JSON strings."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}
            ]
        }
        cmd = CLICommand(
            service="iam",
            action="create-policy",
            parameters={
                "policy-name": "TestPolicy",
                "policy-document": policy_doc,
            },
            description="Create policy",
            operation_category=OperationCategory.WRITE,
        )

        args = cmd.to_cli_args()
        assert "--policy-document" in args
        idx = args.index("--policy-document")
        json_val = args[idx + 1]

        parsed = json.loads(json_val)
        assert parsed["Statement"][0]["Action"] == "s3:ListBucket"

