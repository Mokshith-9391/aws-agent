"""
AWS CLI Executor module.

Securely executes AWS CLI commands via subprocess with
argument arrays (never shell=True), timeouts, secret redaction,
explicit AWS profile and region propagation, and structured result capture.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
import uuid
from typing import Any, Optional

from agent.models import CLICommand, CommandExecutionStatus, CommandResult
from config.settings import get_settings

logger = logging.getLogger(__name__)

# Allowed actions per service (comprehensive CRUD)
ALLOWED_ACTIONS: dict[str, set[str]] = {
    "ec2": {
        "describe-instances", "run-instances", "terminate-instances", "stop-instances",
        "start-instances", "reboot-instances", "modify-instance-attribute",
        "describe-vpcs", "create-vpc", "delete-vpc", "modify-vpc-attribute",
        "describe-subnets", "create-subnet", "delete-subnet", "modify-subnet-attribute",
        "describe-security-groups", "create-security-group", "delete-security-group",
        "authorize-security-group-ingress", "revoke-security-group-ingress",
        "authorize-security-group-egress", "revoke-security-group-egress",
        "describe-internet-gateways", "create-internet-gateway", "attach-internet-gateway",
        "detach-internet-gateway", "delete-internet-gateway",
        "describe-route-tables", "create-route-table", "delete-route-table",
        "associate-route-table", "disassociate-route-table",
        "create-route", "delete-route", "replace-route",
        "describe-key-pairs", "create-key-pair", "delete-key-pair",
        "describe-images", "describe-addresses", "allocate-address", "release-address",
        "associate-address", "disassociate-address",
        "create-tags", "delete-tags", "describe-tags",
        "describe-availability-zones", "describe-regions",
        "describe-network-interfaces", "describe-volumes",
        "create-volume", "attach-volume", "detach-volume", "delete-volume",
    },
    "s3": {"ls", "mb", "rb", "cp", "mv", "rm", "sync", "presign", "website"},
    "s3api": {
        "create-bucket", "delete-bucket", "list-buckets", "head-bucket",
        "put-object", "get-object", "delete-object", "head-object",
        "put-bucket-tagging", "get-bucket-tagging", "get-bucket-location",
        "put-bucket-versioning", "get-bucket-versioning",
        "put-public-access-block", "get-public-access-block",
    },
    "iam": {
        "create-role", "delete-role", "get-role", "list-roles",
        "attach-role-policy", "detach-role-policy",
        "put-role-policy", "delete-role-policy", "get-role-policy",
        "create-policy", "delete-policy", "get-policy", "list-policies",
        "create-instance-profile", "delete-instance-profile",
        "add-role-to-instance-profile", "remove-role-from-instance-profile",
        "list-attached-role-policies",
    },
    "dynamodb": {
        "create-table", "delete-table", "describe-table", "list-tables",
        "update-table", "put-item", "get-item", "delete-item",
        "update-item", "scan", "query", "tag-resource",
    },
    "lambda": {
        "create-function", "delete-function", "get-function", "list-functions",
        "invoke", "update-function-code", "update-function-configuration",
        "add-permission", "remove-permission", "get-function-configuration",
    },
    "rds": {
        "create-db-instance", "delete-db-instance", "describe-db-instances",
        "modify-db-instance", "start-db-instance", "stop-db-instance",
        "create-db-subnet-group", "delete-db-subnet-group", "describe-db-subnet-groups",
    },
    "ecs": {
        "create-cluster", "delete-cluster", "describe-clusters", "list-clusters",
        "register-task-definition", "deregister-task-definition",
        "describe-task-definition", "list-task-definitions",
        "create-service", "delete-service", "describe-services", "update-service",
        "run-task", "stop-task", "list-tasks",
    },
    "sts": {"get-caller-identity", "assume-role", "get-session-token"},
    "cloudwatch": {
        "put-metric-alarm", "delete-alarms", "describe-alarms",
        "put-metric-data", "get-metric-data", "list-metrics",
    },
    "logs": {
        "create-log-group", "delete-log-group", "describe-log-groups",
        "create-log-stream", "put-log-events", "get-log-events",
        "filter-log-events",
    },
    "elbv2": {
        "create-load-balancer", "delete-load-balancer", "describe-load-balancers",
        "create-target-group", "delete-target-group", "describe-target-groups",
        "create-listener", "delete-listener", "describe-listeners",
        "register-targets", "deregister-targets",
    },
    "sns": {
        "create-topic", "delete-topic", "list-topics", "subscribe", "unsubscribe",
        "publish", "list-subscriptions",
    },
    "sqs": {
        "create-queue", "delete-queue", "list-queues", "get-queue-url",
        "send-message", "receive-message", "get-queue-attributes",
    },
}

# Only services with explicit, non-empty action sets in ALLOWED_ACTIONS can execute
ALLOWED_SERVICES: set[str] = set(ALLOWED_ACTIONS.keys())

# Patterns to redact from log output
SECRET_REDACTION_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****************"),
    (re.compile(r"(?i)(secret[\s_-]*(access)?[\s_-]*key|password|token)[\s\"\'=:]+\S+"), r"\1=***REDACTED***"),
]

PLACEHOLDER_CHECK_REGEX = re.compile(r"\{\{([a-zA-Z0-9_\-\.]+)\}\}")


class AWSCLIExecutor:
    """Securely executes AWS CLI commands via subprocess.

    Security guarantees:
    - NEVER uses shell=True
    - Enforces explicit profile and region propagation
    - Rejects commands with unresolved placeholders
    - Only allows commands from ALLOWED_SERVICES / ALLOWED_ACTIONS
    - Enforces execution timeouts
    - Captures and structures all output
    - Redacts secrets from logs
    """

    def __init__(self, timeout: int = 120) -> None:
        self.settings = get_settings()
        self.timeout = self.settings.AWS_CLI_TIMEOUT if self.settings else timeout

    def _redact_secrets(self, text: str) -> str:
        """Redact sensitive information from text."""
        if not text:
            return text
        redacted = text
        for pattern, replacement in SECRET_REDACTION_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    def _has_unresolved_placeholders(self, obj: Any) -> list[str]:
        """Check for any remaining unresolved {{...}} placeholders in parameters."""
        unresolved: list[str] = []
        if isinstance(obj, str):
            for match in PLACEHOLDER_CHECK_REGEX.finditer(obj):
                unresolved.append(match.group(0))
        elif isinstance(obj, list):
            for item in obj:
                unresolved.extend(self._has_unresolved_placeholders(item))
        elif isinstance(obj, dict):
            for v in obj.values():
                unresolved.extend(self._has_unresolved_placeholders(v))
        return unresolved

    def _extract_resource_ids(self, output: dict[str, Any]) -> dict[str, str]:
        """Recursively extract resource IDs and key attributes from AWS JSON output."""
        ids: dict[str, str] = {}
        id_key_suffixes = ("Id", "Arn")
        name_keys = (
            "BucketName", "TableName", "FunctionName", "RoleName",
            "ClusterName", "GroupName", "KeyName"
        )

        def extract(obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and v:
                        if k.endswith(id_key_suffixes) or k in name_keys:
                            ids[k] = v
                    extract(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item)

        extract(output)
        return ids

    def execute_command(
        self,
        cmd: CLICommand,
        region: str,
        profile: Optional[str] = None,
        dry_run: bool = False,
    ) -> CommandResult:
        """Execute a single AWS CLI command securely with explicit profile and region.

        Args:
            cmd: The CLI command to execute.
            region: AWS region.
            profile: Optional AWS profile name.
            dry_run: If True, log the command but don't execute.

        Returns:
            CommandResult with stdout, stderr, exit code, and parsed output.
        """
        execution_id = str(uuid.uuid4())[:8]

        # ── 1. Security Check: Service Allowlist ───────────
        if cmd.service not in ALLOWED_ACTIONS:
            msg = f"Service '{cmd.service}' is not in the allowlist."
            logger.error("[%s] BLOCKED: %s", execution_id, msg)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=f"aws {cmd.service} {cmd.action}",
                exit_code=1,
                stderr=msg,
                status=CommandExecutionStatus.FAILED,
                success=False,
                error_type="ServiceNotAllowed",
                error_message=msg,
            )

        # ── 2. Security Check: Action Allowlist ────────────
        allowed_actions = ALLOWED_ACTIONS.get(cmd.service, set())
        if not allowed_actions or cmd.action not in allowed_actions:
            msg = f"Action '{cmd.action}' is not allowed for service '{cmd.service}'."
            logger.error("[%s] BLOCKED: %s", execution_id, msg)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=f"aws {cmd.service} {cmd.action}",
                exit_code=1,
                stderr=msg,
                status=CommandExecutionStatus.FAILED,
                success=False,
                error_type="ActionNotAllowed",
                error_message=msg,
            )

        # ── 3. Check for Unresolved Placeholders ───────────
        unresolved = self._has_unresolved_placeholders(cmd.parameters)
        if unresolved:
            msg = f"Command has unresolved template placeholders: {', '.join(unresolved)}"
            logger.error("[%s] BLOCKED: %s", execution_id, msg)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd.to_display_string(profile=profile, region=region),
                exit_code=1,
                stderr=msg,
                status=CommandExecutionStatus.FAILED,
                success=False,
                error_type="UnresolvedPlaceholder",
                error_message=msg,
            )

        # ── 4. Build Command Args with Profile & Region ────
        eff_profile = profile or cmd.profile or getattr(self.settings, "AWS_PROFILE", "default")
        eff_region = region or cmd.region or getattr(self.settings, "AWS_REGION", "ap-south-1")

        args = cmd.to_cli_args(profile=eff_profile, region=eff_region)
        cmd_display = self._redact_secrets(" ".join(args))
        logger.info("[%s] Command: %s (profile=%s, region=%s)", execution_id, cmd_display, eff_profile, eff_region)

        # ── 5. Dry Run ─────────────────────────────────────
        if dry_run:
            logger.info("[%s] DRY RUN - skipping execution", execution_id)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=0,
                stdout="(dry run - no execution)",
                status=CommandExecutionStatus.SUCCESS,
                success=True,
            )

        # ── 6. Execute via subprocess (shell=False) ────────
        try:
            start_time = time.time()
            env = self.settings.get_aws_env(profile=eff_profile, region=eff_region) if self.settings else os.environ.copy()

            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # NEVER shell=True
                timeout=self.timeout,
                env=env,
            )
            duration = time.time() - start_time

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            parsed_output: dict[str, Any] = {}
            resource_ids: dict[str, str] = {}

            if stdout:
                try:
                    parsed_output = json.loads(stdout)
                    resource_ids = self._extract_resource_ids(parsed_output)
                except json.JSONDecodeError:
                    parsed_output = {"raw_output": stdout}

            success = result.returncode == 0

            if success:
                logger.info(
                    "[%s] SUCCESS in %.2fs | resource_ids=%s",
                    execution_id, duration, resource_ids
                )
                return CommandResult(
                    command_id=cmd.command_id,
                    command_display=cmd_display,
                    exit_code=result.returncode,
                    stdout=stdout,
                    stderr=stderr,
                    duration_seconds=duration,
                    status=CommandExecutionStatus.SUCCESS,
                    success=True,
                    parsed_output=parsed_output,
                    resource_ids=resource_ids,
                )
            else:
                error_type = None
                error_message = stderr
                error_match = re.search(r"(\w+Error|AccessDenied\w*|UnauthorizedOperation|Throttling)", stderr)
                if error_match:
                    error_type = error_match.group(1)

                logger.error(
                    "[%s] FAILED (exit=%d) | error=%s",
                    execution_id, result.returncode, self._redact_secrets(stderr[:200])
                )

                return CommandResult(
                    command_id=cmd.command_id,
                    command_display=cmd_display,
                    exit_code=result.returncode,
                    stdout=stdout,
                    stderr=stderr,
                    duration_seconds=duration,
                    status=CommandExecutionStatus.FAILED,
                    success=False,
                    parsed_output=parsed_output,
                    error_type=error_type,
                    error_message=error_message,
                )

        except subprocess.TimeoutExpired:
            msg = f"Command timed out after {self.timeout}s"
            logger.error("[%s] %s", execution_id, msg)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=-1,
                stderr=msg,
                status=CommandExecutionStatus.FAILED,
                success=False,
                error_type="Timeout",
                error_message=msg,
            )
        except FileNotFoundError:
            msg = "AWS CLI executable not found. Is the AWS CLI installed and in PATH?"
            logger.error("[%s] %s", execution_id, msg)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=-1,
                stderr=msg,
                status=CommandExecutionStatus.FAILED,
                success=False,
                error_type="CLINotFound",
                error_message=msg,
            )
        except Exception as e:
            msg = f"Unexpected error: {e}"
            logger.error("[%s] %s", execution_id, msg, exc_info=True)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=-1,
                stderr=msg,
                status=CommandExecutionStatus.FAILED,
                success=False,
                error_type="UnexpectedError",
                error_message=msg,
            )
