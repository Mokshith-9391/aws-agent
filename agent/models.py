"""
Core data models for the AWS Provisioning Agent.

All structured data flowing through the agent pipeline is defined here
as Pydantic models, ensuring validation, serialization, and clear contracts
between components.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ──────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────

class OperationType(str, Enum):
    """Classification of the requested operation."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    DESCRIBE = "describe"
    MODIFY = "modify"
    START = "start"
    STOP = "stop"
    ATTACH = "attach"
    DETACH = "detach"


class OperationCategory(str, Enum):
    """Security classification for operations.
    Must always be computed or verified deterministically by application code.
    """
    READ_ONLY = "READ_ONLY"
    WRITE = "WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"


class RiskLevel(str, Enum):
    """Risk level of the provisioning plan."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalType(str, Enum):
    """Authoritative approval type required for plan execution."""
    AUTO = "auto"
    STANDARD = "standard"
    EXPLICIT_CONFIRMATION = "explicit_confirmation"


class ResourceOwnership(str, Enum):
    """Scope/ownership tracking for infrastructure resources."""
    CREATED_BY_THIS_PLAN = "CREATED_BY_THIS_PLAN"
    REUSED_FROM_EXISTING = "REUSED_FROM_EXISTING"
    DISCOVERED_ONLY = "DISCOVERED_ONLY"


class DiscoveryOutcome(str, Enum):
    """Outcome of attempting to discover existing AWS resources."""
    EXISTS_AND_REUSABLE = "EXISTS_AND_REUSABLE"
    EXISTS_BUT_INCOMPATIBLE = "EXISTS_BUT_INCOMPATIBLE"
    NOT_FOUND = "NOT_FOUND"
    AMBIGUOUS = "AMBIGUOUS"
    DISCOVERY_FAILED = "DISCOVERY_FAILED"


class ExecutionStatus(str, Enum):
    """Coherent state machine for provisioning execution."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DRY_RUN = "DRY_RUN"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class CommandExecutionStatus(str, Enum):
    """Execution state of individual commands within a plan."""
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ApprovalStatus(str, Enum):
    """Status of the user approval."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    AUTO_APPROVED = "AUTO_APPROVED"


class AWSService(str, Enum):
    """Supported AWS services."""
    EC2 = "ec2"
    S3 = "s3"
    VPC = "vpc"
    IAM = "iam"
    LAMBDA = "lambda"
    DYNAMODB = "dynamodb"
    CLOUDWATCH = "cloudwatch"
    RDS = "rds"
    ECS = "ecs"
    STS = "sts"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    INTERNET_GATEWAY = "internet_gateway"
    ROUTE_TABLE = "route_table"


# ──────────────────────────────────────────────
# Resource Models
# ──────────────────────────────────────────────

class LogicalResource(BaseModel):
    """A logical AWS resource identified and managed by the plan."""
    resource_ref: str = Field(..., description="Stable logical reference key (e.g. 'vpc.main', 'security_group.web')")
    resource_type: str = Field(..., description="Resource type (e.g. 'vpc', 'subnet', 'security_group', 'instance')")
    service: str = Field(..., description="AWS service (e.g. 'ec2', 's3api', 'iam')")
    resource_id: Optional[str] = Field(None, description="Actual AWS resource ID when created or discovered")
    resource_name: Optional[str] = Field(None, description="Desired or discovered resource name")
    ownership: ResourceOwnership = Field(
        default=ResourceOwnership.CREATED_BY_THIS_PLAN,
        description="Whether created by this plan, reused from existing, or discovered only"
    )
    attributes: dict[str, Any] = Field(default_factory=dict, description="Extracted resource attributes (e.g. CidrBlock, Arn)")
    dependencies: list[str] = Field(default_factory=list, description="Logical references this resource depends on")


class ResourceConfig(BaseModel):
    """Configuration for a single AWS resource."""
    service: str = Field(..., description="AWS service (e.g., ec2, s3, vpc)")
    resource_type: str = Field(..., description="Resource type (e.g., instance, bucket, vpc)")
    resource_name: Optional[str] = Field(None, description="Desired resource name/identifier")
    configuration: dict[str, Any] = Field(default_factory=dict, description="Resource-specific configuration")
    dependencies: list[str] = Field(default_factory=list, description="Resource references this resource depends on")
    tags: dict[str, str] = Field(default_factory=dict, description="Tags to apply to the resource")
    logical_ref: Optional[str] = Field(None, description="Logical resource identifier (e.g. 'ec2.web')")


class CLICommand(BaseModel):
    """A validated AWS CLI command to be executed."""
    command_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    service: str = Field(..., description="AWS service (e.g., ec2, s3api, iam)")
    action: str = Field(..., description="CLI action (e.g., run-instances, create-bucket)")
    parameters: dict[str, Any] = Field(default_factory=dict, description="CLI parameters as key-value pairs")
    region: Optional[str] = Field(None, description="AWS region override for this command")
    profile: Optional[str] = Field(None, description="AWS profile override for this command")
    description: str = Field("", description="Human-readable description of what this command does")
    operation_category: OperationCategory = Field(OperationCategory.WRITE)
    resource_ref: Optional[str] = Field(None, description="Logical reference to the resource this command operates on (e.g. 'vpc.main')")
    depends_on: list[str] = Field(default_factory=list, description="Command IDs this command depends on")
    output_key: Optional[str] = Field(None, description="JSON path to extract from output for downstream use")
    rollback_command: Optional[CLICommand] = Field(None, description="Command to undo this operation")

    def to_cli_args(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
    ) -> list[str]:
        """Convert to a list of CLI arguments for subprocess with explicit profile & region.

        Args:
            profile: Optional override profile.
            region: Optional override region.

        Returns:
            Argument array starting with 'aws'.
        """
        args = ["aws", self.service, self.action]

        # Explicit profile propagation
        eff_profile = self.profile or profile
        if eff_profile and eff_profile.strip():
            args.extend(["--profile", eff_profile.strip()])

        # Explicit region propagation
        eff_region = self.region or region
        if eff_region and eff_region.strip():
            args.extend(["--region", eff_region.strip()])

        for key, value in self.parameters.items():
            arg_key = f"--{key}"
            if isinstance(value, bool):
                if value:
                    args.append(arg_key)
            elif isinstance(value, list):
                args.append(arg_key)
                args.extend([str(v) for v in value])
            elif isinstance(value, dict):
                import json
                args.extend([arg_key, json.dumps(value)])
            else:
                args.extend([arg_key, str(value)])

        args.extend(["--output", "json"])
        return args

    def to_display_string(
        self, profile: Optional[str] = None, region: Optional[str] = None
    ) -> str:
        """Generate a human-readable CLI command string for display."""
        return " ".join(self.to_cli_args(profile=profile, region=region))


# Allow self-referencing for rollback_command
CLICommand.model_rebuild()


class RollbackStep(BaseModel):
    """A single step in a rollback plan."""
    order: int = Field(..., description="Execution order for rollback (descending)")
    resource_description: str = Field(..., description="What resource this rolls back")
    command: CLICommand = Field(..., description="The rollback CLI command")
    resource_ref: Optional[str] = Field(None, description="Logical reference of resource being rolled back")
    depends_on_resource_id: Optional[str] = Field(None, description="Resource ID needed for rollback")


# ──────────────────────────────────────────────
# Provisioning Plan
# ──────────────────────────────────────────────

class ProvisioningPlan(BaseModel):
    """
    The structured execution plan produced by the agent.
    Every user request is converted into this plan before any execution.
    """
    plan_id: str = Field(default_factory=lambda: f"plan-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # --- Request ---
    user_request: str = Field(..., description="Original user request text")
    intent: str = Field(..., description="Interpreted intent (e.g., 'Create S3 bucket')")
    operation_type: OperationType = Field(..., description="Primary operation type")
    operation_category: OperationCategory = Field(OperationCategory.WRITE)

    # --- AWS Context ---
    aws_profile: str = Field(default="default", description="Effective AWS CLI profile")
    aws_region: str = Field(..., description="Target AWS region")
    aws_account_id: Optional[str] = Field(None, description="Target AWS account ID")

    # --- Resources ---
    resources: list[ResourceConfig] = Field(default_factory=list, description="Resources to be provisioned/managed")
    logical_resources: list[LogicalResource] = Field(default_factory=list, description="Logical resource registry tracking ownership")
    dependencies: list[dict[str, str]] = Field(
        default_factory=list,
        description="Dependency relationships between resources: [{from, to}]"
    )

    # --- Commands ---
    commands: list[CLICommand] = Field(default_factory=list, description="Ordered list of CLI commands to execute")

    # --- Risk & Safety ---
    risk_level: RiskLevel = Field(RiskLevel.MEDIUM, description="Overall risk assessment")
    destructive_operations: bool = Field(False, description="Whether plan includes destructive operations")
    approval_type: ApprovalType = Field(ApprovalType.STANDARD, description="Authoritative approval level required")
    missing_parameters: list[str] = Field(default_factory=list, description="Parameters the agent needs from the user")
    assumptions: list[str] = Field(default_factory=list, description="Assumptions made by the agent")
    requires_approval: bool = Field(True, description="Whether user approval is required")

    # --- Rollback ---
    rollback_strategy: list[RollbackStep] = Field(
        default_factory=list,
        alias="rollback_steps",
        description="Ordered rollback steps"
    )

    model_config = {"populate_by_name": True}

    @property
    def rollback_steps(self) -> list[RollbackStep]:
        """Backward-compatible alias for rollback_strategy."""
        return self.rollback_strategy

    @rollback_steps.setter
    def rollback_steps(self, steps: list[RollbackStep]) -> None:
        self.rollback_strategy = steps

    # --- Verification ---
    verification_steps: list[CLICommand] = Field(
        default_factory=list,
        description="Commands to verify resources after provisioning"
    )

    # --- Cost ---
    cost_warnings: list[str] = Field(default_factory=list, description="Potential cost implications")

    # --- Educational ---
    educational_notes: list[str] = Field(default_factory=list, description="Educational notes about the operation")

    @property
    def is_complete(self) -> bool:
        """Check if the plan has all required information."""
        return len(self.missing_parameters) == 0 and len(self.commands) > 0

    @property
    def has_destructive_commands(self) -> bool:
        """Check if any commands are destructive."""
        return any(
            cmd.operation_category == OperationCategory.DESTRUCTIVE
            for cmd in self.commands
        )


# ──────────────────────────────────────────────
# Execution Results
# ──────────────────────────────────────────────

class CommandResult(BaseModel):
    """Result of a single AWS CLI command execution."""
    command_id: str
    command_display: str = Field("", description="The command string that was executed")
    exit_code: int = Field(0)
    stdout: str = Field("")
    stderr: str = Field("")
    duration_seconds: float = Field(0.0)
    status: CommandExecutionStatus = Field(CommandExecutionStatus.PENDING)
    success: bool = Field(False)
    parsed_output: dict[str, Any] = Field(default_factory=dict, description="Parsed JSON output from AWS CLI")
    resource_ids: dict[str, str] = Field(
        default_factory=dict,
        description="Extracted resource IDs (e.g., {'VpcId': 'vpc-123'})"
    )
    extracted_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted attributes (e.g. CidrBlock, Arn, GroupName)"
    )
    error_type: Optional[str] = Field(None, description="AWS error code if failed")
    error_message: Optional[str] = Field(None, description="Human-readable error message")


class VerificationResult(BaseModel):
    """Result of verifying a resource after provisioning using actual AWS state."""
    resource_ref: Optional[str] = None
    resource_type: str
    service: str = "ec2"
    resource_id: str
    verified: bool = False
    state: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    message: str = ""
    error: Optional[str] = None


class ExecutionResult(BaseModel):
    """Complete result of executing a provisioning plan."""
    execution_id: str = Field(default_factory=lambda: f"exec-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}")
    plan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ExecutionStatus = Field(ExecutionStatus.PENDING)

    # --- Results ---
    command_results: list[CommandResult] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)

    # --- Resource tracking ---
    created_resources: dict[str, str] = Field(
        default_factory=dict,
        description="Map of resource type or ref to resource ID for all successfully created resources"
    )
    failed_resources: list[str] = Field(default_factory=list, description="Resources that failed to create")
    skipped_commands: list[str] = Field(default_factory=list, description="Commands skipped due to failed dependencies")

    # --- Metadata ---
    total_commands: int = 0
    successful_commands: int = 0
    failed_commands: int = 0
    duration_seconds: float = 0.0
    dry_run: bool = False
    error_summary: Optional[str] = None

    def update_counts(self) -> None:
        """Update command counts from results."""
        self.total_commands = len(self.command_results)
        self.successful_commands = sum(1 for r in self.command_results if r.success)
        self.failed_commands = sum(1 for r in self.command_results if not r.success and r.status != CommandExecutionStatus.SKIPPED)

        if self.dry_run:
            self.status = ExecutionStatus.DRY_RUN
            return

        if self.failed_commands == 0 and self.successful_commands > 0:
            # Check verification
            has_failed_verification = any(not vr.verified for vr in self.verification_results)
            if has_failed_verification:
                self.status = ExecutionStatus.VERIFICATION_FAILED
            else:
                self.status = ExecutionStatus.SUCCESS
        elif self.successful_commands > 0 and (self.failed_commands > 0 or len(self.skipped_commands) > 0):
            self.status = ExecutionStatus.PARTIAL_SUCCESS
        elif self.failed_commands > 0 and self.successful_commands == 0:
            self.status = ExecutionStatus.FAILED


# ──────────────────────────────────────────────
# Execution History Entry
# ──────────────────────────────────────────────

class ExecutionHistoryEntry(BaseModel):
    """A single entry in the execution history."""
    execution_id: str
    timestamp: datetime
    user_request: str
    aws_account_id: Optional[str] = None
    aws_profile: str = "default"
    aws_region: str
    intent: str
    operation_type: OperationType
    plan: ProvisioningPlan
    approval_status: ApprovalStatus
    execution_result: Optional[ExecutionResult] = None
    explanation: Optional[str] = None


# ──────────────────────────────────────────────
# AWS Identity
# ──────────────────────────────────────────────

class AWSIdentity(BaseModel):
    """AWS caller identity information."""
    account_id: str = ""
    arn: str = ""
    user_id: str = ""
    region: str = ""
    cli_version: str = ""
    cli_installed: bool = False
    credentials_valid: bool = False
    profile: str = "default"

    @property
    def display_account_id(self) -> str:
        """Return masked account ID for display."""
        if len(self.account_id) >= 4:
            return "*" * (len(self.account_id) - 4) + self.account_id[-4:]
        return self.account_id

    @property
    def is_ready(self) -> bool:
        """Check if AWS is fully configured."""
        return self.cli_installed and self.credentials_valid


# ──────────────────────────────────────────────
# Agent Conversation
# ──────────────────────────────────────────────

class ConversationMessage(BaseModel):
    """A message in the agent conversation."""
    role: str = Field(..., description="'user' or 'assistant'")
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    """Structured response from the agent to the UI."""
    message: str = Field(..., description="Main message to display to the user")
    plan: Optional[ProvisioningPlan] = None
    execution_result: Optional[ExecutionResult] = None
    requires_approval: bool = False
    approval_type: ApprovalType = ApprovalType.STANDARD
    requires_input: bool = False
    input_questions: list[str] = Field(default_factory=list)
    explanation: Optional[str] = None
    educational_content: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    resource_summary: dict[str, str] = Field(default_factory=dict)
