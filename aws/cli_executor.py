"""
AWS CLI Executor module.

Securely executes AWS CLI commands via subprocess with
argument arrays (never shell=True), timeouts, secret redaction,
and structured result capture.
"""

import json
import logging
import re
import subprocess
import time
import uuid
from typing import Any, Optional

from agent.models import CommandResult, CLICommand
from config.settings import get_settings

logger = logging.getLogger(__name__)

# Only these AWS CLI service prefixes are allowed to execute
ALLOWED_SERVICES = {
    'ec2', 's3', 's3api', 'iam', 'lambda', 'dynamodb', 'cloudwatch',
    'logs', 'rds', 'ecs', 'sts', 'elbv2', 'elb', 'route53', 'sns',
    'sqs', 'cloudformation',
}

# Allowed actions per service (comprehensive CRUD)
ALLOWED_ACTIONS: dict[str, set[str]] = {
    'ec2': {
        'describe-instances', 'run-instances', 'terminate-instances', 'stop-instances',
        'start-instances', 'reboot-instances', 'modify-instance-attribute',
        'describe-vpcs', 'create-vpc', 'delete-vpc', 'modify-vpc-attribute',
        'describe-subnets', 'create-subnet', 'delete-subnet', 'modify-subnet-attribute',
        'describe-security-groups', 'create-security-group', 'delete-security-group',
        'authorize-security-group-ingress', 'revoke-security-group-ingress',
        'authorize-security-group-egress', 'revoke-security-group-egress',
        'describe-internet-gateways', 'create-internet-gateway', 'attach-internet-gateway',
        'detach-internet-gateway', 'delete-internet-gateway',
        'describe-route-tables', 'create-route-table', 'delete-route-table',
        'associate-route-table', 'disassociate-route-table',
        'create-route', 'delete-route', 'replace-route',
        'describe-key-pairs', 'create-key-pair', 'delete-key-pair',
        'describe-images', 'describe-addresses', 'allocate-address', 'release-address',
        'associate-address', 'disassociate-address',
        'create-tags', 'delete-tags', 'describe-tags',
        'describe-availability-zones', 'describe-regions',
        'describe-network-interfaces', 'describe-volumes',
        'create-volume', 'attach-volume', 'detach-volume', 'delete-volume',
    },
    's3': {'ls', 'mb', 'rb', 'cp', 'mv', 'rm', 'sync', 'presign', 'website'},
    's3api': {
        'create-bucket', 'delete-bucket', 'list-buckets', 'head-bucket',
        'put-object', 'get-object', 'delete-object', 'head-object',
        'put-bucket-tagging', 'get-bucket-tagging', 'get-bucket-location',
        'put-bucket-versioning', 'get-bucket-versioning',
        'put-public-access-block', 'get-public-access-block',
    },
    'iam': {
        'create-role', 'delete-role', 'get-role', 'list-roles',
        'attach-role-policy', 'detach-role-policy',
        'put-role-policy', 'delete-role-policy', 'get-role-policy',
        'create-policy', 'delete-policy', 'get-policy', 'list-policies',
        'create-instance-profile', 'delete-instance-profile',
        'add-role-to-instance-profile', 'remove-role-from-instance-profile',
        'list-attached-role-policies',
    },
    'dynamodb': {
        'create-table', 'delete-table', 'describe-table', 'list-tables',
        'update-table', 'put-item', 'get-item', 'delete-item',
        'update-item', 'scan', 'query', 'tag-resource',
    },
    'lambda': {
        'create-function', 'delete-function', 'get-function', 'list-functions',
        'invoke', 'update-function-code', 'update-function-configuration',
        'add-permission', 'remove-permission', 'get-function-configuration',
    },
    'rds': {
        'create-db-instance', 'delete-db-instance', 'describe-db-instances',
        'modify-db-instance', 'start-db-instance', 'stop-db-instance',
        'create-db-subnet-group', 'delete-db-subnet-group', 'describe-db-subnet-groups',
    },
    'ecs': {
        'create-cluster', 'delete-cluster', 'describe-clusters', 'list-clusters',
        'register-task-definition', 'deregister-task-definition',
        'describe-task-definition', 'list-task-definitions',
        'create-service', 'delete-service', 'describe-services', 'update-service',
        'run-task', 'stop-task', 'list-tasks',
    },
    'sts': {'get-caller-identity', 'assume-role', 'get-session-token'},
    'cloudwatch': {
        'put-metric-alarm', 'delete-alarms', 'describe-alarms',
        'put-metric-data', 'get-metric-data', 'list-metrics',
    },
    'logs': {
        'create-log-group', 'delete-log-group', 'describe-log-groups',
        'create-log-stream', 'put-log-events', 'get-log-events',
        'filter-log-events',
    },
    'elbv2': {
        'create-load-balancer', 'delete-load-balancer', 'describe-load-balancers',
        'create-target-group', 'delete-target-group', 'describe-target-groups',
        'create-listener', 'delete-listener', 'describe-listeners',
        'register-targets', 'deregister-targets',
    },
    'sns': {
        'create-topic', 'delete-topic', 'list-topics', 'subscribe', 'unsubscribe',
        'publish', 'list-subscriptions',
    },
    'sqs': {
        'create-queue', 'delete-queue', 'list-queues', 'get-queue-url',
        'send-message', 'receive-message', 'get-queue-attributes',
    },
}

# Patterns to redact from log output
SECRET_REDACTION_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), '***ACCESS_KEY***'),
    (re.compile(r'(?i)(secret[\s_-]*(access)?[\s_-]*key|password|token)[\s"\'=:]+\S+'), r'\1=***REDACTED***'),
]


class AWSCLIExecutor:
    """Securely executes AWS CLI commands via subprocess.

    Security guarantees:
    - NEVER uses shell=True
    - Only allows commands from ALLOWED_SERVICES/ALLOWED_ACTIONS
    - Enforces execution timeouts
    - Captures and structures all output
    - Redacts secrets from logs
    """

    def __init__(self, timeout: int = 120) -> None:
        settings = get_settings()
        self.timeout = settings.AWS_CLI_TIMEOUT if settings else timeout

    def _redact_secrets(self, text: str) -> str:
        """Redact sensitive information from text."""
        if not text:
            return text
        redacted = text
        for pattern, replacement in SECRET_REDACTION_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    def _extract_resource_ids(self, output: dict[str, Any]) -> dict[str, str]:
        """Recursively extract resource IDs from AWS JSON output.

        Looks for keys ending in 'Id', 'Arn', 'Name' (for certain resources).
        """
        ids: dict[str, str] = {}

        id_key_suffixes = ('Id', 'Arn')
        name_keys = ('BucketName', 'TableName', 'FunctionName', 'RoleName',
                      'ClusterName', 'GroupName', 'KeyName')

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
        dry_run: bool = False,
    ) -> CommandResult:
        """Execute a single AWS CLI command securely.

        Args:
            cmd: The CLI command to execute.
            region: AWS region.
            dry_run: If True, log the command but don't execute.

        Returns:
            CommandResult with stdout, stderr, exit code, and parsed output.
        """
        execution_id = str(uuid.uuid4())[:8]

        # ── Security Check: Service Allowlist ───────────
        if cmd.service not in ALLOWED_SERVICES:
            msg = f"Service '{cmd.service}' is not in the allowlist."
            logger.error(f"[{execution_id}] BLOCKED: {msg}")
            return CommandResult(
                command_id=cmd.command_id,
                command_display=f"aws {cmd.service} {cmd.action}",
                exit_code=1,
                stderr=msg,
                success=False,
                error_type="ServiceNotAllowed",
                error_message=msg,
            )

        # ── Security Check: Action Allowlist ────────────
        allowed_actions = ALLOWED_ACTIONS.get(cmd.service, set())
        if allowed_actions and cmd.action not in allowed_actions:
            msg = f"Action '{cmd.action}' is not allowed for service '{cmd.service}'."
            logger.error(f"[{execution_id}] BLOCKED: {msg}")
            return CommandResult(
                command_id=cmd.command_id,
                command_display=f"aws {cmd.service} {cmd.action}",
                exit_code=1,
                stderr=msg,
                success=False,
                error_type="ActionNotAllowed",
                error_message=msg,
            )

        # ── Build Command Args ──────────────────────────
        args = cmd.to_cli_args()
        # Ensure region is set
        if "--region" not in args and region:
            # Insert region after the action
            idx = 3  # after aws, service, action
            args.insert(idx, "--region")
            args.insert(idx + 1, region)

        cmd_display = self._redact_secrets(" ".join(args))
        logger.info(f"[{execution_id}] Command: {cmd_display}")

        # ── Dry Run ─────────────────────────────────────
        if dry_run:
            logger.info(f"[{execution_id}] DRY RUN - skipping execution")
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=0,
                stdout="(dry run - no execution)",
                success=True,
            )

        # ── Execute via subprocess ──────────────────────
        try:
            start_time = time.time()
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # NEVER shell=True
                timeout=self.timeout,
            )
            duration = time.time() - start_time

            # Parse output
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
                    f"[{execution_id}] SUCCESS in {duration:.2f}s | "
                    f"resource_ids={resource_ids}"
                )
            else:
                # Parse AWS error
                error_type = None
                error_message = stderr
                # Try to extract error code from AWS error format
                error_match = re.search(r'(\w+Error|AccessDenied\w*|UnauthorizedOperation|Throttling)', stderr)
                if error_match:
                    error_type = error_match.group(1)

                logger.error(
                    f"[{execution_id}] FAILED (exit={result.returncode}) | "
                    f"error={self._redact_secrets(stderr[:200])}"
                )

                return CommandResult(
                    command_id=cmd.command_id,
                    command_display=cmd_display,
                    exit_code=result.returncode,
                    stdout=stdout,
                    stderr=stderr,
                    duration_seconds=duration,
                    success=False,
                    parsed_output=parsed_output,
                    error_type=error_type,
                    error_message=error_message,
                )

            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                success=True,
                parsed_output=parsed_output,
                resource_ids=resource_ids,
            )

        except subprocess.TimeoutExpired:
            msg = f"Command timed out after {self.timeout}s"
            logger.error(f"[{execution_id}] {msg}")
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=-1,
                stderr=msg,
                success=False,
                error_type="Timeout",
                error_message=msg,
            )
        except FileNotFoundError:
            msg = "AWS CLI executable not found. Is the AWS CLI installed?"
            logger.error(f"[{execution_id}] {msg}")
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=-1,
                stderr=msg,
                success=False,
                error_type="CLINotFound",
                error_message=msg,
            )
        except Exception as e:
            msg = f"Unexpected error: {e}"
            logger.error(f"[{execution_id}] {msg}", exc_info=True)
            return CommandResult(
                command_id=cmd.command_id,
                command_display=cmd_display,
                exit_code=-1,
                stderr=msg,
                success=False,
                error_type="UnexpectedError",
                error_message=msg,
            )
