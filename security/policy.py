"""
Safety Policy Engine.

Evaluates provisioning plans for security, compliance, and dangerous patterns
using structured semantic inspection (not just string matching).
Enforces command limits, parses IAM JSON documents, validates network security
group ingress rules, and deterministically computes risk levels.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from agent.models import OperationCategory, ProvisioningPlan, RiskLevel
from config.settings import get_settings

logger = logging.getLogger(__name__)

# Default limit of commands allowed in a single plan
DEFAULT_MAX_COMMANDS_PER_PLAN = 15

# Administrative ports that should not be open to 0.0.0.0/0
SENSITIVE_ADMIN_PORTS = {22: "SSH", 3389: "RDP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL"}


class SafetyPolicyEngine:
    """Evaluates provisioning plans for safety, risk, and compliance."""

    def __init__(self, max_commands: Optional[int] = None) -> None:
        settings = get_settings()
        self.max_commands = (
            max_commands or getattr(settings, "MAX_COMMANDS_PER_PLAN", DEFAULT_MAX_COMMANDS_PER_PLAN)
        )

    def evaluate_plan(
        self, plan: ProvisioningPlan
    ) -> tuple[bool, list[str], list[str]]:
        """Evaluate a provisioning plan for safety issues and compliance.

        Args:
            plan: The plan to evaluate.

        Returns:
            Tuple of (is_safe: bool, warnings: list[str], blocking_issues: list[str]).
        """
        warnings: list[str] = []
        blocking_issues: list[str] = []

        try:
            # ── 1. Enforce Max Commands Limit (Critical Fix #12) ────
            if len(plan.commands) > self.max_commands:
                blocking_issues.append(
                    f"Plan contains {len(plan.commands)} commands, exceeding the maximum allowed limit "
                    f"of {self.max_commands} per plan. Break down the request into smaller operations."
                )

            # ── 2. Evaluate Each Command ────────────────────────────
            for command in plan.commands:
                cmd_svc = command.service.lower().strip()
                cmd_act = command.action.lower().strip()
                params = command.parameters or {}

                # ── A. Bulk Delete Patterns ─────────────────────────
                cmd_str = command.to_display_string()
                if ("delete" in cmd_act or "terminate" in cmd_act) and "--all" in cmd_str.lower():
                    blocking_issues.append(
                        f"Command '{cmd_svc} {cmd_act}' attempts to delete all resources of a type, which is blocked."
                    )

                # ── B. Security Group Rules (Ports & CIDR) ──────────
                if cmd_svc == "ec2" and cmd_act in ("authorize-security-group-ingress", "create-security-group"):
                    self._evaluate_security_group_ingress(params, warnings, blocking_issues)

                # ── C. Structured IAM Policy Inspection ─────────────
                if cmd_svc == "iam":
                    self._evaluate_iam_policy_structure(cmd_act, params, warnings, blocking_issues)

                # ── D. Security Controls ────────────────────────────
                if "disable" in cmd_act and ("security" in cmd_act or "guardduty" in cmd_act or "shield" in cmd_act):
                    blocking_issues.append(f"Disabling security controls via '{cmd_act}' is strictly blocked.")

            # Check destructive operations flag
            if plan.destructive_operations or any(c.operation_category == OperationCategory.DESTRUCTIVE for c in plan.commands):
                warnings.append("Plan contains DESTRUCTIVE operations that permanently remove resources.")

        except Exception as e:
            logger.error("Error evaluating plan safety: %s", e, exc_info=True)
            blocking_issues.append(f"Safety evaluation error: {e}")

        is_safe = len(blocking_issues) == 0
        return is_safe, warnings, blocking_issues

    def _evaluate_security_group_ingress(
        self,
        params: dict[str, Any],
        warnings: list[str],
        blocking_issues: list[str],
    ) -> None:
        """Inspect security group rules for dangerous open access."""
        cidr = str(params.get("cidr") or params.get("cidr-block") or "")
        protocol = str(params.get("protocol") or "").lower()
        port_raw = params.get("port")

        is_public = cidr in ("0.0.0.0/0", "::/0")
        if not is_public:
            return

        # Check for all ports / all protocols open to the world
        if protocol in ("-1", "all") or port_raw in ("0", "-1", "all", "0-65535"):
            blocking_issues.append(
                "Opening all ports and protocols to 0.0.0.0/0 (the entire internet) is strictly blocked."
            )
            return

        # Check specific port numbers
        try:
            if port_raw is not None:
                port_num = int(port_raw)
                if port_num in SENSITIVE_ADMIN_PORTS:
                    proto_name = SENSITIVE_ADMIN_PORTS[port_num]
                    warnings.append(
                        f"Security group rule opens {proto_name} (port {port_num}) to 0.0.0.0/0. "
                        f"Highly recommended to restrict access to your specific IP address."
                    )
                elif port_num in (80, 443, 8080, 8443):
                    warnings.append(f"Security group allows public internet access to web port {port_num}.")
        except ValueError:
            pass

    def _evaluate_iam_policy_structure(
        self,
        action: str,
        params: dict[str, Any],
        warnings: list[str],
        blocking_issues: list[str],
    ) -> None:
        """Structurally parse and inspect IAM policies for wildcard permissions and admin access."""
        # 1. Inspect attached policy ARNs
        policy_arn = str(params.get("policy-arn") or params.get("policy-name") or "")
        if "AdministratorAccess" in policy_arn:
            blocking_issues.append(
                "Attaching 'AdministratorAccess' policy grants unlimited root-level account permissions. "
                "Use least-privilege scoped policies."
            )

        # 2. Inspect policy documents
        doc_keys = ["policy-document", "assume-role-policy-document"]
        for key in doc_keys:
            raw_doc = params.get(key)
            if not raw_doc:
                continue

            doc_dict: Optional[dict[str, Any]] = None
            if isinstance(raw_doc, dict):
                doc_dict = raw_doc
            elif isinstance(raw_doc, str):
                try:
                    doc_dict = json.loads(raw_doc)
                except json.JSONDecodeError:
                    pass

            if doc_dict and isinstance(doc_dict, dict):
                statements = doc_dict.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue
                    effect = stmt.get("Effect", "")
                    if effect != "Allow":
                        continue

                    # Check Action
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    if "*" in actions or "iam:*" in actions:
                        blocking_issues.append(
                            "IAM policy statement grants wildcard ('*') Action with Allow effect. "
                            "Specify exact least-privilege actions."
                        )

                    # Check Resource
                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    if "*" in resources and any("*" in a for a in actions):
                        blocking_issues.append(
                            "IAM policy combines wildcard Action ('*') with wildcard Resource ('*')."
                        )

    def assess_risk(self, plan: ProvisioningPlan) -> RiskLevel:
        """Deterministically assess the risk level of a provisioning plan."""
        try:
            # If any blocking issue exists -> CRITICAL
            _, _, blocking = self.evaluate_plan(plan)
            if blocking:
                return RiskLevel.CRITICAL

            is_destructive = plan.destructive_operations or any(
                c.operation_category == OperationCategory.DESTRUCTIVE for c in plan.commands
            )

            # Multiple destructive operations -> CRITICAL
            destructive_cmds = [
                c for c in plan.commands if c.operation_category == OperationCategory.DESTRUCTIVE
            ]
            if len(destructive_cmds) > 1:
                return RiskLevel.CRITICAL

            # Single destructive operation -> HIGH
            if is_destructive:
                return RiskLevel.HIGH

            # Check commands for sensitive configurations
            for cmd in plan.commands:
                svc = cmd.service.lower()
                act = cmd.action.lower()
                params = cmd.parameters or {}

                # IAM mutations -> HIGH
                if svc == "iam":
                    return RiskLevel.HIGH

                # Sensitive administrative ports open to public -> HIGH
                if svc == "ec2" and "authorize" in act:
                    cidr = str(params.get("cidr") or "")
                    port = str(params.get("port") or "")
                    if cidr in ("0.0.0.0/0", "::/0") and port in ("22", "3389", "0"):
                        return RiskLevel.HIGH

            # Standard WRITE operations -> MEDIUM
            if plan.operation_category == OperationCategory.WRITE or any(
                c.operation_category == OperationCategory.WRITE for c in plan.commands
            ):
                return RiskLevel.MEDIUM

            # READ_ONLY -> LOW
            return RiskLevel.LOW

        except Exception as e:
            logger.error("Error assessing risk level: %s", e)
            return RiskLevel.HIGH

    def requires_explicit_confirmation(self, plan: ProvisioningPlan) -> bool:
        """Determine if typed confirmation (e.g. 'CONFIRM DELETE') is required."""
        risk = self.assess_risk(plan)
        has_destructive = plan.destructive_operations or any(
            c.operation_category == OperationCategory.DESTRUCTIVE for c in plan.commands
        )
        return risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) or has_destructive

    def get_safer_alternative(self, plan: ProvisioningPlan) -> Optional[str]:
        """Suggest a safer alternative for detected high-risk patterns."""
        for cmd in plan.commands:
            params = cmd.parameters or {}
            cidr = str(params.get("cidr") or "")
            port = str(params.get("port") or "")

            if cidr in ("0.0.0.0/0", "::/0") and port == "22":
                return "Consider replacing 0.0.0.0/0 with your specific public IP (e.g. '<your-ip>/32') or using AWS Systems Manager (SSM) Session Manager instead of public SSH."

            if cmd.service == "iam" and "AdministratorAccess" in str(params):
                return "Consider creating a custom IAM role with scoped permissions (e.g. AmazonS3ReadOnlyAccess, AmazonEC2FullAccess) instead of root-level AdministratorAccess."

        return None
