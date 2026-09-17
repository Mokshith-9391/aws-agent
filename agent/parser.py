"""
Request Parser.

Parses natural-language user requests and validates input
before passing to the planning stage. Includes prompt injection
protection and input sanitization.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from config.settings import get_settings

logger = logging.getLogger(__name__)

# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|prompts?)",
    r"(?i)forget\s+(all\s+)?(previous|above|prior)",
    r"(?i)disregard\s+(all\s+)?(safety|security|rules?|instructions?)",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)new\s+instructions?:\s",
    r"(?i)override\s+(safety|security|policy)",
    r"(?i)bypass\s+(safety|security|validation|approval)",
    r"(?i)execute\s+(this\s+)?(shell|bash|powershell|cmd)\s+command",
    r"(?i)run\s+(this\s+)?(shell|bash|powershell|cmd|python)\s+",
    r"(?i)system\s*\(",
    r"(?i)subprocess\s*\.",
    r"(?i)os\s*\.\s*system",
    r"(?i)eval\s*\(",
    r"(?i)exec\s*\(",
]

# Shell metacharacters that should not appear in AWS resource requests
SHELL_METACHARACTERS = ["|", ";", "&&", "||", "$(", "`", ">>", "<<", ">", "<"]

# Region name pattern
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")

# Service keywords the parser looks for to understand intent
AWS_SERVICE_KEYWORDS = {
    "ec2": ["ec2", "instance", "server", "virtual machine", "vm", "compute"],
    "s3": ["s3", "bucket", "storage", "object storage"],
    "vpc": ["vpc", "virtual private cloud", "network", "subnet", "cidr"],
    "iam": ["iam", "role", "policy", "user", "permission", "access"],
    "lambda": ["lambda", "function", "serverless"],
    "dynamodb": ["dynamodb", "dynamo", "nosql", "table"],
    "rds": ["rds", "database", "mysql", "postgres", "sql", "db instance"],
    "ecs": ["ecs", "container", "fargate", "docker", "task"],
    "cloudwatch": ["cloudwatch", "monitoring", "alarm", "logs", "metric"],
    "security_group": ["security group", "firewall", "ingress", "egress", "port"],
    "internet_gateway": ["internet gateway", "igw", "internet access"],
    "route_table": ["route table", "routing"],
}

# Operation keywords
OPERATION_KEYWORDS = {
    "create": ["create", "make", "launch", "start", "provision", "set up", "setup", "spin up", "deploy", "build", "new", "add", "give me"],
    "delete": ["delete", "remove", "destroy", "terminate", "tear down", "teardown", "kill", "drop", "clean up"],
    "describe": ["describe", "show", "display", "get", "what is", "tell me about", "info", "details", "status"],
    "list": ["list", "show all", "show me", "what", "which", "how many", "enumerate", "find"],
    "update": ["update", "modify", "change", "edit", "alter", "adjust"],
    "stop": ["stop", "pause", "halt", "suspend"],
    "start": ["start", "resume", "restart", "begin"],
    "attach": ["attach", "connect", "associate", "link"],
    "detach": ["detach", "disconnect", "disassociate", "unlink"],
}


class RequestParser:
    """
    Parses and validates user natural-language requests.

    Provides input sanitization, prompt injection detection,
    and basic intent extraction for pre-processing before LLM analysis.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._injection_patterns = [re.compile(p) for p in INJECTION_PATTERNS]

    def validate_input(self, user_input: str) -> tuple[bool, list[str]]:
        """Validate user input for safety and basic correctness.

        Args:
            user_input: Raw user input string.

        Returns:
            Tuple of (is_valid, list_of_issues).
        """
        issues: list[str] = []

        # Check length
        if not user_input or not user_input.strip():
            issues.append("Empty input. Please describe what you want to do with AWS.")
            return False, issues

        if len(user_input) > self._settings.MAX_INPUT_LENGTH:
            issues.append(
                f"Input too long ({len(user_input)} chars). "
                f"Maximum is {self._settings.MAX_INPUT_LENGTH} characters."
            )
            return False, issues

        # Check for prompt injection
        if self._settings.ENABLE_PROMPT_INJECTION_PROTECTION:
            injection_detected = self._check_prompt_injection(user_input)
            if injection_detected:
                issues.append(
                    "Your request appears to contain instructions that could bypass "
                    "safety controls. Please rephrase your AWS request."
                )
                logger.warning(f"Prompt injection attempt detected in input: {user_input[:100]}...")
                return False, issues

        # Check for shell metacharacters in suspicious positions
        for meta in SHELL_METACHARACTERS:
            if meta in user_input:
                # Allow semicolons in natural language but flag suspicious patterns
                if meta == ";" and not re.search(r";\s*(rm|del|curl|wget|bash|sh|cmd|powershell)", user_input, re.I):
                    continue
                if meta in (">", "<") and not re.search(r"[><]\s*/", user_input):
                    continue
                # For other metacharacters, warn but don't block
                logger.info(f"Shell metacharacter '{meta}' found in input (may be benign)")

        return True, issues

    def _check_prompt_injection(self, text: str) -> bool:
        """Check for prompt injection patterns.

        Args:
            text: Input text to check.

        Returns:
            True if injection is detected.
        """
        for pattern in self._injection_patterns:
            if pattern.search(text):
                return True
        return False

    def extract_hints(self, user_input: str) -> dict:
        """Extract quick hints from the input for pre-processing.

        This is NOT the main intent parser (that's the LLM's job).
        This provides lightweight hints to help set context.

        Args:
            user_input: The user's input text.

        Returns:
            Dictionary with extracted hints.
        """
        text = user_input.lower()
        hints: dict = {
            "detected_services": [],
            "detected_operation": None,
            "detected_region": None,
            "mentions_existing_resource": False,
        }

        # Detect services
        for service, keywords in AWS_SERVICE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    if service not in hints["detected_services"]:
                        hints["detected_services"].append(service)
                    break

        # Detect operation type
        for operation, keywords in OPERATION_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text:
                    hints["detected_operation"] = operation
                    break
            if hints["detected_operation"]:
                break

        # Detect region mentions (explicit region codes like us-east-1)
        region_match = re.search(r'\b([a-z]{2}-[a-z]+-\d+)\b', user_input)
        if region_match:
            hints["detected_region"] = region_match.group(0)

        # Check for common region aliases
        region_aliases = {
            "mumbai": "ap-south-1",
            "virginia": "us-east-1",
            "n. virginia": "us-east-1",
            "ohio": "us-east-2",
            "oregon": "us-west-2",
            "ireland": "eu-west-1",
            "london": "eu-west-2",
            "frankfurt": "eu-central-1",
            "tokyo": "ap-northeast-1",
            "singapore": "ap-southeast-1",
            "sydney": "ap-southeast-2",
            "seoul": "ap-northeast-2",
            "canada": "ca-central-1",
            "são paulo": "sa-east-1",
            "sao paulo": "sa-east-1",
        }
        for alias, region in region_aliases.items():
            if alias in text:
                hints["detected_region"] = region
                break

        # Check for references to existing resources
        existing_patterns = [
            r"(?i)(the|that|my|existing)\s+(vpc|subnet|bucket|instance|server|security group)",
            r"(?i)vpc-[a-z0-9]+",
            r"(?i)subnet-[a-z0-9]+",
            r"(?i)sg-[a-z0-9]+",
            r"(?i)i-[a-z0-9]+",
        ]
        for pattern in existing_patterns:
            if re.search(pattern, user_input):
                hints["mentions_existing_resource"] = True
                break

        return hints

    def sanitize_for_llm(self, user_input: str) -> str:
        """Sanitize user input before sending to the LLM.

        Removes potentially dangerous content while preserving
        the user's intent.

        Args:
            user_input: Raw user input.

        Returns:
            Sanitized input string.
        """
        # Strip leading/trailing whitespace
        sanitized = user_input.strip()

        # Remove any embedded null bytes
        sanitized = sanitized.replace("\x00", "")

        # Limit consecutive whitespace
        sanitized = re.sub(r"\s{3,}", "  ", sanitized)

        return sanitized
