import json
import pytest
from unittest.mock import MagicMock

from agent.llm_client import LLMClient
from agent.models import OperationCategory, OperationType, RiskLevel
from agent.planner import Planner
from services.registry import create_default_registry


class MockLLMClient(LLMClient):
    def __init__(self, mock_response: str):
        self.mock_response = mock_response

    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.1, max_tokens: int = 8192, response_format: str = None) -> str:
        return self.mock_response

    def is_available(self) -> bool:
        return True


class TestPlanner:
    def setup_method(self):
        self.registry = create_default_registry()

    def test_plan_generation_valid_json(self):
        plan_json = json.dumps({
            "intent": "Create an S3 bucket named my-demo-bucket in ap-south-1",
            "operation_type": "create",
            "operation_category": "WRITE",
            "aws_region": "ap-south-1",
            "resources": [
                {
                    "service": "s3",
                    "resource_type": "bucket",
                    "resource_name": "my-demo-bucket",
                    "configuration": {},
                    "dependencies": [],
                }
            ],
            "dependencies": [],
            "commands": [
                {
                    "service": "s3api",
                    "action": "create-bucket",
                    "parameters": {
                        "bucket": "my-demo-bucket",
                        "create-bucket-configuration": "LocationConstraint=ap-south-1",
                    },
                    "description": "Create S3 bucket",
                    "operation_category": "WRITE",
                }
            ],
            "risk_level": "LOW",
            "destructive_operations": False,
            "missing_parameters": [],
            "assumptions": ["Bucket name is globally unique"],
            "requires_approval": True,
            "cost_warnings": [],
            "educational_notes": ["S3 bucket in ap-south-1"],
            "verification_commands": [
                {
                    "service": "s3api",
                    "action": "head-bucket",
                    "parameters": {"bucket": "my-demo-bucket"},
                    "description": "Verify bucket",
                }
            ],
            "rollback_commands": [
                {
                    "service": "s3api",
                    "action": "delete-bucket",
                    "parameters": {"bucket": "my-demo-bucket"},
                    "description": "Delete bucket on rollback",
                    "operation_category": "DESTRUCTIVE",
                }
            ],
        })

        client = MockLLMClient(plan_json)
        planner = Planner(llm_client=client, service_registry=self.registry)

        plan = planner.generate_plan(
            user_request="Create an S3 bucket named my-demo-bucket in ap-south-1",
            region="ap-south-1",
        )

        assert plan.intent == "Create an S3 bucket named my-demo-bucket in ap-south-1"
        assert plan.operation_type == OperationType.CREATE
        assert plan.operation_category == OperationCategory.WRITE
        assert len(plan.commands) == 1
        assert plan.commands[0].service == "s3api"
        assert plan.commands[0].action == "create-bucket"
        assert len(plan.verification_steps) == 1
        assert len(plan.rollback_strategy) == 1

    def test_plan_generation_markdown_wrapped_json(self):
        raw_json = json.dumps({
            "intent": "List EC2 instances",
            "operation_type": "list",
            "operation_category": "READ_ONLY",
            "aws_region": "us-east-1",
            "resources": [],
            "dependencies": [],
            "commands": [
                {
                    "service": "ec2",
                    "action": "describe-instances",
                    "parameters": {},
                    "description": "List all EC2 instances",
                    "operation_category": "READ_ONLY",
                }
            ],
            "risk_level": "LOW",
            "destructive_operations": False,
            "missing_parameters": [],
            "assumptions": [],
            "requires_approval": False,
            "cost_warnings": [],
            "educational_notes": [],
            "verification_commands": [],
            "rollback_commands": [],
        })
        wrapped_response = f"```json\n{raw_json}\n```"

        client = MockLLMClient(wrapped_response)
        planner = Planner(llm_client=client, service_registry=self.registry)

        plan = planner.generate_plan(
            user_request="Show me what EC2 instances exist",
            region="us-east-1",
        )

        assert plan.operation_category == OperationCategory.READ_ONLY
        assert plan.requires_approval is False
        assert len(plan.commands) == 1

    def test_plan_generation_invalid_json_fallback(self):
        client = MockLLMClient("Sorry, I cannot produce JSON right now.")
        planner = Planner(llm_client=client, service_registry=self.registry)

        plan = planner.generate_plan(
            user_request="Do something random",
            region="ap-south-1",
        )

        assert len(plan.missing_parameters) > 0
        assert "Planning error" in plan.missing_parameters[0]

    def test_llm_category_downgrade_overridden_by_compiler(self):
        """Prove LLM cannot downgrade a destructive delete operation to READ_ONLY."""
        deceptive_json = json.dumps({
            "intent": "Delete S3 bucket",
            "operation_type": "delete",
            "operation_category": "READ_ONLY",  # Deceptive LLM attempt
            "risk_level": "LOW",                 # Deceptive LLM attempt
            "resources": [
                {
                    "service": "s3",
                    "resource_type": "bucket",
                    "resource_name": "target-bucket",
                    "logical_ref": "s3.target",
                }
            ],
            "commands": [],
        })
        client = MockLLMClient(deceptive_json)
        planner = Planner(llm_client=client, service_registry=self.registry)

        plan = planner.generate_plan(
            user_request="Delete target-bucket",
            region="ap-south-1",
        )

        # Compiler must enforce DESTRUCTIVE, HIGH risk, and EXPLICIT_CONFIRMATION
        assert plan.operation_category == OperationCategory.DESTRUCTIVE
        assert plan.risk_level == RiskLevel.HIGH
        assert plan.destructive_operations is True
        assert plan.approval_type.value == "explicit_confirmation"
        assert len(plan.commands) == 1
        assert plan.commands[0].action == "delete-bucket"

    def test_llm_unsupported_resource_type_caught(self):
        """Prove LLM hallucinated/unsupported resource type is safely caught."""
        bad_json = json.dumps({
            "intent": "Mine crypto",
            "operation_type": "create",
            "resources": [
                {
                    "service": "unknown",
                    "resource_type": "quantum_miner",
                    "logical_ref": "crypto.miner",
                }
            ],
        })
        client = MockLLMClient(bad_json)
        planner = Planner(llm_client=client, service_registry=self.registry)

        plan = planner.generate_plan(
            user_request="Deploy quantum miner",
            region="ap-south-1",
        )

        assert not plan.is_complete
        assert any("quantum_miner" in p for p in plan.missing_parameters)

    def test_llm_executable_cli_commands_ignored_and_discarded(self):
        """Prove that executable CLI commands emitted in LLM output are strictly discarded.

        The compiler must construct commands solely from authoritative DesiredResource specifications.
        """
        malicious_json = json.dumps({
            "intent": "Create a legitimate S3 bucket",
            "operation_type": "create",
            "resources": [
                {
                    "service": "s3",
                    "resource_type": "bucket",
                    "resource_name": "legit-safe-bucket",
                    "logical_ref": "s3.safe_bucket",
                    "configuration": {"bucket": "legit-safe-bucket"},
                }
            ],
            # Malicious/hallucinated command injection in LLM output:
            "commands": [
                {
                    "service": "ec2",
                    "action": "terminate-instances",
                    "parameters": {"instance-ids": "i-critical123"},
                    "description": "Terminate critical instance sneakily",
                    "operation_category": "READ_ONLY",  # Falsified
                },
                {
                    "service": "s3api",
                    "action": "delete-bucket",
                    "parameters": {"bucket": "production-database-backup"},
                    "description": "Delete production backup",
                    "operation_category": "READ_ONLY",
                }
            ],
            "verification_commands": [
                {"service": "curl", "action": "exfiltrate", "parameters": {}}
            ],
            "rollback_commands": [
                {"service": "iam", "action": "delete-role", "parameters": {"role-name": "AdminRole"}}
            ],
        })

        client = MockLLMClient(malicious_json)
        planner = Planner(llm_client=client, service_registry=self.registry)

        plan = planner.generate_plan(
            user_request="Create a legitimate S3 bucket",
            region="ap-south-1",
        )

        # Invariant: None of the injected commands exist in the compiled plan!
        for cmd in plan.commands:
            assert cmd.action != "terminate-instances"
            assert cmd.action != "delete-bucket"
            assert cmd.service != "curl"
            assert "i-critical123" not in str(cmd.parameters)
            assert "production-database-backup" not in str(cmd.parameters)

        # Plan contains strictly the single create-bucket command built by Python builder
        assert len(plan.commands) == 1
        assert plan.commands[0].service == "s3api"
        assert plan.commands[0].action == "create-bucket"
        assert plan.commands[0].parameters["bucket"] == "legit-safe-bucket"
        assert plan.plan_hash is not None


