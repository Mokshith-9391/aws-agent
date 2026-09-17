import json
import pytest

from agent.llm_client import LLMClient
from agent.models import (
    AgentResponse,
    ExecutionStatus,
    OperationCategory,
    OperationType,
    RiskLevel,
)
from agent.orchestrator import AgentOrchestrator
from config.settings import Settings, ExecutionMode


class MockWebserverLLM(LLMClient):
    """Mock LLM returning a realistic plan for an EC2 webserver with HTTP access."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        response_format: str = None,
    ) -> str:
        # Check if this is an explanation prompt or plan prompt
        if "Generate a detailed explanation" in user_prompt or "Provide educational" in user_prompt:
            return "### Web Server Provisioning Complete\nProvisioned a t3.micro instance in ap-south-1 with port 80 access."

        return json.dumps({
            "intent": "Create a simple web server in Mumbai using an EC2 t3.micro instance with HTTP access",
            "operation_type": "create",
            "operation_category": "WRITE",
            "aws_region": "ap-south-1",
            "resources": [
                {
                    "service": "ec2",
                    "resource_type": "security_group",
                    "resource_name": "ai-agent-web-sg",
                    "configuration": {"description": "Allow HTTP port 80 ingress"},
                    "dependencies": [],
                },
                {
                    "service": "ec2",
                    "resource_type": "instance",
                    "resource_name": "ai-agent-web-server",
                    "configuration": {"instance_type": "t3.micro", "image_id": "ami-0123456789abcdef0"},
                    "dependencies": ["ai-agent-web-sg"],
                },
            ],
            "dependencies": [
                {"from": "security_group", "to": "instance"}
            ],
            "commands": [
                {
                    "command_id": "cmd-sg-1",
                    "service": "ec2",
                    "action": "create-security-group",
                    "parameters": {
                        "group-name": "ai-agent-web-sg",
                        "description": "Allow HTTP port 80",
                    },
                    "description": "Create security group for web server",
                    "operation_category": "WRITE",
                    "output_key": "GroupId",
                },
                {
                    "command_id": "cmd-sg-rule-1",
                    "service": "ec2",
                    "action": "authorize-security-group-ingress",
                    "parameters": {
                        "group-name": "ai-agent-web-sg",
                        "protocol": "tcp",
                        "port": "80",
                        "cidr": "0.0.0.0/0",
                    },
                    "description": "Authorize inbound HTTP traffic on port 80",
                    "operation_category": "WRITE",
                    "depends_on": ["cmd-sg-1"],
                },
                {
                    "command_id": "cmd-ec2-1",
                    "service": "ec2",
                    "action": "run-instances",
                    "parameters": {
                        "image-id": "ami-0123456789abcdef0",
                        "instance-type": "t3.micro",
                        "count": "1",
                    },
                    "description": "Launch t3.micro EC2 web server instance",
                    "operation_category": "WRITE",
                    "depends_on": ["cmd-sg-rule-1"],
                    "output_key": "Instances[0].InstanceId",
                },
            ],
            "risk_level": "MEDIUM",
            "destructive_operations": False,
            "missing_parameters": [],
            "assumptions": ["Using default VPC for Mumbai region", "Using Amazon Linux 2023 AMI"],
            "requires_approval": True,
            "cost_warnings": ["EC2 instances incur charges while running. Remember to terminate when not in use."],
            "educational_notes": ["Security group acts as a virtual firewall for the instance controlling inbound traffic on port 80."],
            "verification_commands": [
                {
                    "service": "ec2",
                    "action": "describe-instances",
                    "parameters": {},
                    "description": "Verify EC2 web server state",
                }
            ],
            "rollback_commands": [
                {
                    "service": "ec2",
                    "action": "terminate-instances",
                    "parameters": {},
                    "description": "Terminate instance on rollback",
                    "operation_category": "DESTRUCTIVE",
                }
            ],
        })

    def is_available(self) -> bool:
        return True


class TestEndToEndScenario:
    def setup_method(self):
        self.settings = Settings(
            AWS_REGION="ap-south-1",
            AWS_PROFILE="default",
            DEFAULT_EXECUTION_MODE=ExecutionMode.DRY_RUN,
        )
        self.orchestrator = AgentOrchestrator(self.settings)
        # Manually inject our mock client
        self.orchestrator._registry = self.orchestrator._registry or __import__("services.registry", fromlist=["create_default_registry"]).create_default_registry()
        self.mock_client = MockWebserverLLM()
        self.orchestrator._llm_client = self.mock_client
        self.orchestrator._planner = __import__("agent.planner", fromlist=["Planner"]).Planner(
            self.mock_client, self.orchestrator._registry
        )
        self.orchestrator._explainer = __import__("agent.explainer", fromlist=["Explainer"]).Explainer(
            self.mock_client
        )
        self.orchestrator._initialized = True

    def test_dry_run_workflow(self):
        user_prompt = "Create a simple web server in Mumbai using an EC2 t3.micro instance with HTTP access."

        response = self.orchestrator.process_request(
            user_request=user_prompt,
            region="ap-south-1",
            dry_run=True,
            learning_mode=True,
        )

        assert response is not None
        assert response.plan is not None
        assert response.plan.aws_region == "ap-south-1"
        assert len(response.plan.commands) == 3
        assert response.execution_result is not None
        assert response.execution_result.status == ExecutionStatus.DRY_RUN
        assert "Dry Run Analysis" in response.message
        assert "ai-agent-web-sg" in response.message
        assert "run-instances" in response.message
        assert len(response.plan.cost_warnings) > 0
        assert response.educational_content is not None

    def test_live_approval_required(self):
        user_prompt = "Create a simple web server in Mumbai using an EC2 t3.micro instance with HTTP access."

        response = self.orchestrator.process_request(
            user_request=user_prompt,
            region="ap-south-1",
            dry_run=False,
            learning_mode=False,
        )

        # In live mode with WRITE operations, requires_approval should be True
        assert response.requires_approval is True
        assert "Approval Required" in response.message
        assert response.plan is not None
