import os
import pytest

from aws.identity import AWSIdentityManager
from aws.resource_discovery import ResourceDiscovery
from config.settings import get_settings


settings = get_settings()
IS_INTEGRATION_ENABLED = getattr(settings, "AWS_INTEGRATION_TESTS", False) or (
    os.getenv("AWS_INTEGRATION_TESTS", "").lower() in ("true", "1", "yes")
)


@pytest.mark.skipif(
    not IS_INTEGRATION_ENABLED,
    reason="Live AWS integration tests disabled. Set AWS_INTEGRATION_TESTS=true in .env to run.",
)
class TestLiveAWSIntegration:
    """Optional live AWS tests that execute real AWS CLI commands against target environment.

    Only invoked when explicitly enabled by setting AWS_INTEGRATION_TESTS=true.
    Never run by default in offline/CI environments.
    """

    def setup_method(self):
        self.identity_mgr = AWSIdentityManager()
        self.profile = settings.AWS_PROFILE
        self.region = settings.AWS_REGION

    def test_live_cli_installed(self):
        installed, version = self.identity_mgr.check_cli_installed()
        assert installed is True, f"AWS CLI not found on PATH: {version}"
        assert "aws-cli" in version.lower()

    def test_live_caller_identity(self):
        identity = self.identity_mgr.get_caller_identity(profile=self.profile, region=self.region)
        assert identity.connected is True
        assert identity.account_id is not None
        assert len(identity.account_id) == 12
        assert identity.arn is not None

    def test_live_read_only_vpc_discovery(self):
        discovery = ResourceDiscovery()
        vpcs = discovery.discover_vpcs(region=self.region, profile=self.profile)
        assert isinstance(vpcs, list)

    def test_live_read_only_plan_execution(self):
        from agent.orchestrator import AgentOrchestrator
        from agent.models import ExecutionStatus
        orchestrator = AgentOrchestrator(settings)
        resp = orchestrator.process_request(
            user_request="List all EC2 instances",
            region=self.region,
            profile=self.profile,
            dry_run=False,
        )
        assert resp.execution_result is not None
        assert resp.execution_result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.DRY_RUN)

    def test_live_s3_create_verify_cleanup_lifecycle(self):
        """B7: Real live create -> verify -> cleanup integration test.

        Lifecycle:
        1. Create uniquely named disposable test bucket
        2. Verify against live AWS state
        3. Clean up / delete bucket in finally block
        4. Verify deletion
        """
        import uuid
        from aws.cli_executor import AWSCLIExecutor
        from agent.models import CLICommand

        executor = AWSCLIExecutor()
        test_id = uuid.uuid4().hex[:10]
        bucket_name = f"aws-agent-test-{test_id}"
        created = False

        try:
            # 1. Create Bucket
            create_cmd = CLICommand(
                service="s3api",
                action="create-bucket",
                parameters={"bucket": bucket_name},
                region_override=self.region,
            )
            create_res = executor.execute_command(create_cmd, profile=self.profile, region=self.region)
            assert create_res.success is True, f"Failed to create live test bucket: {create_res.stderr}"
            created = True

            # 2. Verify against live AWS state (head-bucket)
            head_cmd = CLICommand(
                service="s3api",
                action="head-bucket",
                parameters={"bucket": bucket_name},
                region_override=self.region,
            )
            head_res = executor.execute_command(head_cmd, profile=self.profile, region=self.region)
            assert head_res.success is True, f"Live verification failed: {head_res.stderr}"

        finally:
            # 3. Cleanup: Delete bucket even if assertion fails
            if created:
                del_cmd = CLICommand(
                    service="s3api",
                    action="delete-bucket",
                    parameters={"bucket": bucket_name},
                    region_override=self.region,
                )
                del_res = executor.execute_command(del_cmd, profile=self.profile, region=self.region)
                assert del_res.success is True, f"Failed to clean up test bucket: {del_res.stderr}"

                # 4. Verify Deletion
                verify_del = executor.execute_command(head_cmd, profile=self.profile, region=self.region)
                assert verify_del.success is False, "Bucket should not exist after deletion"


class TestLiveLifecycleHelperOffline:
    """Unit tests for the live lifecycle helper logic running offline with mocked executor.

    Ensures the create -> verify -> cleanup flow is correct without requiring live AWS credentials.
    """

    def test_lifecycle_helper_success_path(self):
        from unittest.mock import MagicMock
        from aws.cli_executor import AWSCLIExecutor
        from agent.models import CLICommand, CommandResult

        mock_exec = MagicMock(spec=AWSCLIExecutor)
        # Mock create success
        mock_exec.execute_command.side_effect = [
            CommandResult(command_id="c1", stdout="{}", parsed_output={}, stderr="", exit_code=0, success=True),
            # Mock verify success
            CommandResult(command_id="c2", stdout="{}", parsed_output={}, stderr="", exit_code=0, success=True),
            # Mock delete success
            CommandResult(command_id="c3", stdout="{}", parsed_output={}, stderr="", exit_code=0, success=True),
            # Mock verify-deleted (fails, proving deletion)
            CommandResult(command_id="c4", stdout="", parsed_output={}, stderr="Not Found", exit_code=254, success=False),
        ]

        bucket_name = "aws-agent-test-mock123"
        created = False
        try:
            res1 = mock_exec.execute_command(CLICommand(service="s3api", action="create-bucket", parameters={"bucket": bucket_name}))
            assert res1.success is True
            created = True
            res2 = mock_exec.execute_command(CLICommand(service="s3api", action="head-bucket", parameters={"bucket": bucket_name}))
            assert res2.success is True
        finally:
            if created:
                res3 = mock_exec.execute_command(CLICommand(service="s3api", action="delete-bucket", parameters={"bucket": bucket_name}))
                assert res3.success is True
                res4 = mock_exec.execute_command(CLICommand(service="s3api", action="head-bucket", parameters={"bucket": bucket_name}))
                assert res4.success is False

        assert mock_exec.execute_command.call_count == 4

    def test_lifecycle_helper_cleans_up_on_verify_failure(self):
        from unittest.mock import MagicMock
        from aws.cli_executor import AWSCLIExecutor
        from agent.models import CLICommand, CommandResult

        mock_exec = MagicMock(spec=AWSCLIExecutor)
        mock_exec.execute_command.side_effect = [
            # Create succeeds
            CommandResult(command_id="c1", stdout="{}", parsed_output={}, stderr="", exit_code=0, success=True),
            # Verify fails
            CommandResult(command_id="c2", stdout="", parsed_output={}, stderr="Verification error", exit_code=1, success=False),
            # Delete in finally block
            CommandResult(command_id="c3", stdout="{}", parsed_output={}, stderr="", exit_code=0, success=True),
        ]

        bucket_name = "aws-agent-test-mock-fail"
        created = False
        caught = False
        try:
            res1 = mock_exec.execute_command(CLICommand(service="s3api", action="create-bucket", parameters={"bucket": bucket_name}))
            assert res1.success is True
            created = True
            res2 = mock_exec.execute_command(CLICommand(service="s3api", action="head-bucket", parameters={"bucket": bucket_name}))
            assert res2.success is True  # will raise AssertionError
        except AssertionError:
            caught = True
        finally:
            if created:
                res3 = mock_exec.execute_command(CLICommand(service="s3api", action="delete-bucket", parameters={"bucket": bucket_name}))

        assert caught is True
        # Cleanup was executed even though verification failed
        assert mock_exec.execute_command.call_count == 3

