import json
from unittest.mock import MagicMock
import pytest
from aws.ami_discovery import AMIDiscovery, OFFICIAL_AL2023_CATALOG
from agent.models import CommandResult


class TestAMIDiscovery:
    def setup_method(self):
        self.mock_executor = MagicMock()
        self.ami_discovery = AMIDiscovery(self.mock_executor)

    def test_live_discovery_success(self):
        # Mock describe-images returning images
        fake_images_output = json.dumps({
            "Images": [
                {
                    "ImageId": "ami-older",
                    "CreationDate": "2023-01-01T00:00:00.000Z",
                    "Description": "Amazon Linux 2023 Older",
                },
                {
                    "ImageId": "ami-latest",
                    "CreationDate": "2024-01-01T00:00:00.000Z",
                    "Description": "Amazon Linux 2023 Latest",
                },
            ]
        })
        self.mock_executor.execute_command.return_value = CommandResult(
            command_id="test",
            stdout=fake_images_output,
            parsed_output=json.loads(fake_images_output),
            stderr="",
            exit_code=0,
            success=True,
        )

        ami_id, rationale = self.ami_discovery.discover_amazon_linux_2023(
            region="ap-south-1", profile="default"
        )
        assert ami_id == "ami-latest"
        assert "Selected latest official Amazon Linux 2023 AMI" in rationale

    def test_fallback_catalog_when_live_search_fails(self):
        # Mock describe-images failing (e.g. no AWS CLI credentials)
        self.mock_executor.execute_command.return_value = CommandResult(
            command_id="test",
            stdout="",
            stderr="Unable to locate credentials",
            exit_code=254,
            success=False,
        )

        ami_id, rationale = self.ami_discovery.discover_amazon_linux_2023(
            region="ap-south-1", profile="default"
        )
        assert ami_id == "ami-022ce6f32988af5fa"
        assert "verified regional catalog" in rationale

    def test_fallback_catalog_when_no_executor(self):
        standalone = AMIDiscovery(None)
        ami_id, rationale = standalone.discover_amazon_linux_2023(region="us-east-1", query_live=False)
        assert ami_id == "ami-0c101f26f147fa7fd"
        assert "verified regional catalog" in rationale

    def test_regional_fallbacks_are_valid_format(self):
        for region, ami in OFFICIAL_AL2023_CATALOG.items():
            assert ami.startswith("ami-")
            assert len(ami) >= 12

    def test_unsupported_region_behavior(self):
        # If executor fails and region not in catalog, returns None and explicit warning
        standalone = AMIDiscovery(None)
        ami_id, rationale = standalone.discover_amazon_linux_2023(region="unsupported-region-1", query_live=False)
        assert ami_id is None
        assert "No verified Amazon Linux AMI found" in rationale
