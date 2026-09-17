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

