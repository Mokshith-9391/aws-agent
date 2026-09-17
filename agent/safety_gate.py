"""
Live Mode Safety Gate.

Validates that the system and AWS environment satisfy all strict readiness invariants
before real (Live Mode / dry_run=False) AWS provisioning can be executed.
Blocks live execution and enforces Dry Run if any safety check fails.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from agent.compiler import (
    DELETE_CONFIG_SCHEMAS,
    READ_CONFIG_SCHEMAS,
    RESOURCE_CONFIG_SCHEMAS,
)
from aws.cli_executor import ALLOWED_ACTIONS, ALLOWED_SERVICES
from aws.identity import AWSIdentityManager
from services.registry import AWSServiceRegistry, create_default_registry

logger = logging.getLogger(__name__)


@dataclass
class SafetyGateReport:
    """Readiness assessment report for Live Mode AWS execution."""

    is_live_ready: bool
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    cli_version: Optional[str] = None
    account_id: Optional[str] = None
    arn: Optional[str] = None


class LiveModeSafetyGate:
    """Authoritative gatekeeper determining if Live Mode AWS execution is permitted."""

    def __init__(
        self,
        identity_manager: Optional[AWSIdentityManager] = None,
        registry: Optional[AWSServiceRegistry] = None,
        executor: Optional[Any] = None,
    ) -> None:
        self._identity_manager = identity_manager or AWSIdentityManager()
        self._registry = registry or create_default_registry()
        self._executor = executor

    def check_readiness(
        self,
        profile: str = "default",
        region: str = "ap-south-1",
        check_credentials: bool = True,
    ) -> SafetyGateReport:
        """Evaluate all readiness invariants for Live Mode execution.

        Invariants checked:
        1. AWS CLI installed and functional (`aws --version`).
        2. AWS CLI caller identity accessible (if check_credentials=True).
        3. Allowlist closure: ALLOWED_SERVICES == set(ALLOWED_ACTIONS.keys()) with non-empty actions.
        4. Compiler completeness: all supported resource types have:
           - Authoritative configuration schemas
           - Valid services in ALLOWED_SERVICES
        """
        issues: list[str] = []
        warnings: list[str] = []
        cli_ver: Optional[str] = None
        account_id: Optional[str] = None
        arn: Optional[str] = None

        # 1. AWS CLI Installed
        is_mock = (
            self._executor is not None
            and (
                "mock" in type(self._executor).__name__.lower()
                or getattr(self._executor, "_is_mock", False)
            )
        )
        if is_mock:
            installed, ver_info = True, "aws-cli/2.15.0 (mock)"
        else:
            installed, ver_info = self._identity_manager.check_cli_installed()

        if not installed:
            issues.append(f"AWS CLI is not installed or not in system PATH: {ver_info}")
        else:
            cli_ver = ver_info

        # 2. AWS Credentials / Identity Check (if requested)
        if installed and check_credentials:
            if is_mock:
                account_id, arn = "123456789012", "arn:aws:iam::123456789012:user/mock"
            else:
                identity = self._identity_manager.get_caller_identity(profile=profile, region=region)
                if not identity.authenticated:
                    issues.append(
                        f"AWS caller identity verification failed for profile '{profile}' in region '{region}': "
                        f"{identity.error_message or 'Unauthenticated'}"
                    )
                else:
                    account_id = identity.account_id
                    arn = identity.arn

        # 3. Allowlist Invariant
        action_services = set(ALLOWED_ACTIONS.keys())
        if ALLOWED_SERVICES != action_services:
            issues.append(
                f"ALLOWED_SERVICES mismatch with ALLOWED_ACTIONS keys: "
                f"diff={ALLOWED_SERVICES ^ action_services}"
            )

        for svc, acts in ALLOWED_ACTIONS.items():
            if not acts:
                issues.append(f"Service '{svc}' has an empty ALLOWED_ACTIONS set.")

        # 4. Compiler Completeness Check
        for (svc, rtype), schema in RESOURCE_CONFIG_SCHEMAS.items():
            if not schema:
                issues.append(f"Resource schema for '{svc}.{rtype}' is empty.")
            # Verify that service is registered in ALLOWED_SERVICES or resolves to it
            cli_svc = svc if svc != "vpc" else "ec2"
            if cli_svc not in ALLOWED_SERVICES:
                issues.append(f"Supported resource '{svc}.{rtype}' CLI service '{cli_svc}' is not in ALLOWED_SERVICES.")

        is_ready = len(issues) == 0
        return SafetyGateReport(
            is_live_ready=is_ready,
            issues=issues,
            warnings=warnings,
            cli_version=cli_ver,
            account_id=account_id,
            arn=arn,
        )
