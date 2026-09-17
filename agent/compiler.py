"""
Deterministic Plan Compiler Layer.

Converts structured desired-state plans (intent + target resource specifications)
into fully validated, executable ProvisioningPlan objects using deterministic
Python command builders and authoritative service definitions.
The LLM is NEVER authoritative for executable CLI syntax, flags, action names,
resource IDs, operation categories, or rollback commands.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from agent.models import (
    ApprovalType,
    CLICommand,
    DesiredResource,
    DesiredStatePlan,
    LogicalResource,
    OperationCategory,
    OperationType,
    ProvisioningPlan,
    ResourceConfig,
    ResourceOwnership,
    RiskLevel,
    RollbackStep,
)
from aws.ami_discovery import AMIDiscovery
from aws.cli_validator import classify_aws_action
from services.ec2 import (
    build_describe_instances_command,
    build_run_instances_command,
    build_terminate_instances_command,
    build_create_key_pair_command,
)
from services.registry import AWSServiceRegistry, ResourceTypeDefinition
from services.s3 import (
    build_create_bucket_command,
    build_delete_bucket_command,
    build_head_bucket_command,
    build_list_buckets_command,
)
from services.vpc import (
    build_attach_igw_command,
    build_create_igw_command,
    build_create_route_table_command,
    build_create_subnet_command,
    build_create_vpc_command,
    build_delete_igw_command,
    build_delete_route_table_command,
    build_delete_security_group_command,
    build_delete_subnet_command,
    build_delete_vpc_command,
    build_ingress_command,
    build_security_group_command,
)
from services.iam import (
    build_create_policy_command,
    build_create_role_command,
    build_delete_policy_command,
    build_delete_role_command,
    build_get_role_command,
)
from services.dynamodb import (
    build_create_table_command,
    build_delete_table_command,
    build_describe_table_command,
)

logger = logging.getLogger(__name__)


class UnsupportedResourceTypeError(ValueError):
    """Raised when a plan requests a resource type not supported by the system."""
    pass


class PlanCompiler:
    """Compiles desired infrastructure state into deterministic executable CLICommands."""

    def __init__(
        self,
        registry: AWSServiceRegistry,
        ami_discovery: Optional[AMIDiscovery] = None,
    ) -> None:
        self.registry = registry
        self.ami_discovery = ami_discovery or AMIDiscovery()

    def compile(
        self,
        desired: DesiredStatePlan,
        user_request: str,
        region: str,
        profile: str = "default",
        account_id: str = "Unknown",
    ) -> ProvisioningPlan:
        """Compile a DesiredStatePlan into an authoritative ProvisioningPlan.

        Args:
            desired: The desired-state plan produced by LLM or test driver.
            user_request: Original user request text.
            region: Target AWS region.
            profile: Target AWS CLI profile.
            account_id: AWS account ID for context.

        Returns:
            ProvisioningPlan containing deterministically built CLICommands,
            LogicalResources, RollbackSteps, and VerificationSteps.

        Raises:
            UnsupportedResourceTypeError: If any requested resource type is unknown.
        """
        logger.info(
            "Compiling desired-state plan: intent='%s', resources=%d",
            desired.intent, len(desired.resources)
        )

        plan_id = f"plan-{uuid.uuid4().hex[:12]}"
        commands: list[CLICommand] = []
        logical_resources: list[LogicalResource] = []
        resource_configs: list[ResourceConfig] = []
        verification_steps: list[CLICommand] = []
        cost_warnings: list[str] = []
        assumptions = list(desired.assumptions)
        missing_parameters = list(desired.missing_parameters)

        # Mapping from logical_ref to the command_id that creates it
        ref_to_command_id: dict[str, str] = {}

        # ── 1. Validate All Resource Types First (Fail Fast) ─────────
        validated_resources: list[tuple[DesiredResource, str, ResourceTypeDefinition]] = []
        for res in desired.resources:
            lookup = None
            if res.service:
                rt_def = self.registry.get_resource_type(res.service, res.resource_type)
                if rt_def:
                    lookup = (res.service, rt_def)
            if not lookup:
                lookup = self.registry.find_resource_type(res.resource_type)

            if not lookup:
                raise UnsupportedResourceTypeError(
                    f"Unsupported resource type '{res.resource_type}' "
                    f"(service '{res.service or 'unspecified'}'). "
                    f"Supported types: {[rt.resource_type for rt in self.registry.get_all_resource_definitions()]}"
                )
            validated_resources.append((res, lookup[0], lookup[1]))

        # ── 2. Compile Resources into Commands & Logical Resources ───
        for idx, (res, svc_name, rt_def) in enumerate(validated_resources, 1):
            ref = res.logical_ref or f"{svc_name}.{res.resource_type}_{idx}"
            cfg = res.configuration or {}
            tags = res.tags or {}
            res_name = res.resource_name or tags.get("Name")

            # Record ResourceConfig
            resource_configs.append(
                ResourceConfig(
                    service=svc_name,
                    resource_type=res.resource_type,
                    resource_name=res_name,
                    configuration=cfg,
                    dependencies=res.dependencies,
                    tags=tags,
                    logical_ref=ref,
                )
            )

            # Record LogicalResource
            logical_resources.append(
                LogicalResource(
                    resource_ref=ref,
                    resource_type=res.resource_type,
                    service=svc_name,
                    domain_service=svc_name,
                    cli_service=rt_def.cli_service,
                    resource_name=res_name,
                    ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
                    dependencies=res.dependencies,
                    plan_id=plan_id,
                    created_by_plan_id=plan_id,
                )
            )

            # Add cost warnings
            if rt_def.cost_warning and rt_def.cost_warning not in cost_warnings:
                cost_warnings.append(rt_def.cost_warning)

            # Determine command-level dependency IDs
            dep_command_ids = [
                ref_to_command_id[dep]
                for dep in res.dependencies
                if dep in ref_to_command_id
            ]

            cmd_id = f"cmd-{svc_name}-{res.resource_type}-{uuid.uuid4().hex[:6]}"

            # ── Dispatch to Deterministic Builders ───────────────────
            op_type = desired.operation_type

            if op_type in (OperationType.LIST, OperationType.DESCRIBE):
                # Read-only operation compilation
                compiled_cmd = self._compile_read_command(svc_name, res.resource_type, cfg, cmd_id, region, profile)
                if compiled_cmd:
                    commands.append(compiled_cmd)

            elif op_type == OperationType.DELETE:
                # Deletion operation compilation
                compiled_cmd = self._compile_delete_command(svc_name, res.resource_type, cfg, res_name, cmd_id, ref)
                if compiled_cmd:
                    commands.append(compiled_cmd)

            else:
                # Creation / Mutation operation compilation
                compiled_cmds, ver_cmd = self._compile_create_resource(
                    svc_name=svc_name,
                    resource_type=res.resource_type,
                    ref=ref,
                    res_name=res_name,
                    cfg=cfg,
                    tags=tags,
                    cmd_id=cmd_id,
                    dep_command_ids=dep_command_ids,
                    region=region,
                    profile=profile,
                    assumptions=assumptions,
                )
                for c in compiled_cmds:
                    c.profile = profile
                    if not c.region:
                        c.region = region
                    commands.append(c)
                    ref_to_command_id[ref] = c.command_id

                if ver_cmd:
                    ver_cmd.profile = profile
                    if not ver_cmd.region:
                        ver_cmd.region = region
                    verification_steps.append(ver_cmd)

        # ── 3. Deterministic Operation Category & Risk Level ─────────
        if any(cmd.operation_category == OperationCategory.DESTRUCTIVE for cmd in commands):
            overall_category = OperationCategory.DESTRUCTIVE
        elif any(cmd.operation_category == OperationCategory.WRITE for cmd in commands):
            overall_category = OperationCategory.WRITE
        else:
            overall_category = OperationCategory.READ_ONLY

        # Deterministic Risk Level computation
        if overall_category == OperationCategory.DESTRUCTIVE:
            risk_level = RiskLevel.HIGH
        elif any(cmd.service == "iam" for cmd in commands):
            risk_level = RiskLevel.HIGH
        elif any(cmd.service in ("ec2", "rds") and cmd.action in ("run-instances", "create-db-instance") for cmd in commands):
            risk_level = RiskLevel.MEDIUM
        elif overall_category == OperationCategory.WRITE:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # ── 4. Deterministic Rollback Steps from Handlers ────────────
        rollback_strategy: list[RollbackStep] = []
        for i, cmd in enumerate(reversed(commands), 1):
            if cmd.rollback_command:
                rb_cmd = cmd.rollback_command.model_copy()
                rb_cmd.profile = profile
                if not rb_cmd.region:
                    rb_cmd.region = region
                rollback_strategy.append(
                    RollbackStep(
                        order=i,
                        resource_description=f"Rollback {cmd.description}",
                        command=rb_cmd,
                        resource_ref=cmd.resource_ref,
                    )
                )

        return ProvisioningPlan(
            plan_id=plan_id,
            user_request=user_request,
            intent=desired.intent,
            operation_type=desired.operation_type,
            operation_category=overall_category,
            aws_profile=profile,
            aws_region=region,
            aws_account_id=account_id,
            resources=resource_configs,
            logical_resources=logical_resources,
            dependencies=[
                {"from": dep, "to": res.logical_ref}
                for res in desired.resources
                for dep in res.dependencies
            ],
            commands=commands,
            risk_level=risk_level,
            destructive_operations=(overall_category == OperationCategory.DESTRUCTIVE),
            missing_parameters=missing_parameters,
            assumptions=assumptions,
            requires_approval=(overall_category != OperationCategory.READ_ONLY),
            approval_type=ApprovalType.EXPLICIT_CONFIRMATION if (overall_category == OperationCategory.DESTRUCTIVE or risk_level == RiskLevel.HIGH) else (ApprovalType.STANDARD if overall_category == OperationCategory.WRITE else ApprovalType.AUTO),
            rollback_strategy=rollback_strategy,
            verification_steps=verification_steps,
            cost_warnings=cost_warnings,
        )

    def _compile_create_resource(
        self,
        svc_name: str,
        resource_type: str,
        ref: str,
        res_name: Optional[str],
        cfg: dict[str, Any],
        tags: dict[str, str],
        cmd_id: str,
        dep_command_ids: list[str],
        region: str,
        profile: str,
        assumptions: list[str],
    ) -> tuple[list[CLICommand], Optional[CLICommand]]:
        """Compile a single resource creation request into deterministic CLI commands."""
        name_tag = res_name or tags.get("Name")

        # ── VPC ──────────────────────────────────────────────────────
        if svc_name == "vpc" and resource_type == "vpc":
            cidr = cfg.get("cidr_block") or cfg.get("cidr-block") or "10.0.0.0/16"
            cmd = build_create_vpc_command(
                cidr_block=cidr,
                name_tag=name_tag,
                command_id=cmd_id,
                resource_ref=ref,
            )
            cmd.depends_on = dep_command_ids
            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="ec2",
                action="describe-vpcs",
                parameters={"vpc-ids": [f"{{{{{ref}.id}}}}"]},
                description=f"Verify VPC {ref}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return [cmd], ver_cmd

        # ── Subnet ───────────────────────────────────────────────────
        elif svc_name == "vpc" and resource_type == "subnet":
            vpc_id = cfg.get("vpc_id") or cfg.get("vpc-id") or "{{vpc.main.id}}"
            cidr = cfg.get("cidr_block") or cfg.get("cidr-block") or "10.0.1.0/24"
            az = cfg.get("availability_zone") or cfg.get("availability-zone")
            cmd = build_create_subnet_command(
                vpc_id=vpc_id,
                cidr_block=cidr,
                availability_zone=az,
                name_tag=name_tag,
                command_id=cmd_id,
                depends_on=dep_command_ids,
                resource_ref=ref,
            )
            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="ec2",
                action="describe-subnets",
                parameters={"subnet-ids": [f"{{{{{ref}.id}}}}"]},
                description=f"Verify Subnet {ref}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return [cmd], ver_cmd

        # ── Internet Gateway ─────────────────────────────────────────
        elif svc_name == "vpc" and resource_type == "internet_gateway":
            cmd = build_create_igw_command(
                name_tag=name_tag,
                command_id=cmd_id,
                resource_ref=ref,
            )
            cmd.depends_on = dep_command_ids
            cmds = [cmd]
            vpc_id = cfg.get("vpc_id") or cfg.get("vpc-id")
            if vpc_id:
                attach_cmd = build_attach_igw_command(
                    igw_id=f"{{{{{ref}.id}}}}",
                    vpc_id=vpc_id,
                    command_id=f"{cmd_id}-attach",
                    depends_on=[cmd_id],
                )
                cmds.append(attach_cmd)
            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="ec2",
                action="describe-internet-gateways",
                parameters={"internet-gateway-ids": [f"{{{{{ref}.id}}}}"]},
                description=f"Verify Internet Gateway {ref}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return cmds, ver_cmd

        # ── Route Table ──────────────────────────────────────────────
        elif svc_name == "vpc" and resource_type == "route_table":
            vpc_id = cfg.get("vpc_id") or cfg.get("vpc-id") or "{{vpc.main.id}}"
            cmd = build_create_route_table_command(
                vpc_id=vpc_id,
                name_tag=name_tag,
                command_id=cmd_id,
                depends_on=dep_command_ids,
                resource_ref=ref,
            )
            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="ec2",
                action="describe-route-tables",
                parameters={"route-table-ids": [f"{{{{{ref}.id}}}}"]},
                description=f"Verify Route Table {ref}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return [cmd], ver_cmd

        # ── Security Group ───────────────────────────────────────────
        elif svc_name == "vpc" and resource_type == "security_group":
            group_name = res_name or cfg.get("group_name") or cfg.get("group-name") or "default-sg"
            desc = cfg.get("description") or f"Security group {group_name}"
            vpc_id = cfg.get("vpc_id") or cfg.get("vpc-id")
            sg_cmd = build_security_group_command(
                group_name=group_name,
                description=desc,
                vpc_id=vpc_id,
                command_id=cmd_id,
                depends_on=dep_command_ids,
                resource_ref=ref,
            )
            cmds = [sg_cmd]

            # Process ingress rules if provided
            ingress_rules = cfg.get("ingress_rules") or cfg.get("ingress") or []
            if not ingress_rules and ("port" in cfg or "ports" in cfg):
                ports = cfg.get("ports") or [cfg["port"]]
                cidr = cfg.get("cidr") or cfg.get("cidr_block") or "0.0.0.0/0"
                protocol = cfg.get("protocol") or "tcp"
                for p in ports:
                    ingress_rules.append({"port": int(p), "cidr": cidr, "protocol": protocol})

            for idx, rule in enumerate(ingress_rules, 1):
                ing_cmd = build_ingress_command(
                    group_id=f"{{{{{ref}.id}}}}",
                    protocol=rule.get("protocol", "tcp"),
                    port=int(rule.get("port", 80)),
                    cidr=rule.get("cidr", "0.0.0.0/0"),
                    command_id=f"{cmd_id}-ing-{idx}",
                    depends_on=[cmd_id],
                )
                cmds.append(ing_cmd)

            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="ec2",
                action="describe-security-groups",
                parameters={"group-ids": [f"{{{{{ref}.id}}}}"]},
                description=f"Verify Security Group {ref}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return cmds, ver_cmd

        # ── EC2 Instance ─────────────────────────────────────────────
        elif svc_name == "ec2" and resource_type == "instance":
            image_id = cfg.get("image_id") or cfg.get("image-id")
            if not image_id or "ami-" not in image_id or "placeholder" in image_id.lower():
                discovered_ami, rationale = self.ami_discovery.discover_amazon_linux_2023(
                    region=region, profile=profile, query_live=True
                )
                if discovered_ami:
                    image_id = discovered_ami
                    assumptions.append(rationale)
                else:
                    image_id = "ami-022ce6f32988af5fa"

            inst_type = cfg.get("instance_type") or cfg.get("instance-type") or "t3.micro"
            count = int(cfg.get("count", 1))
            subnet_id = cfg.get("subnet_id") or cfg.get("subnet-id")
            sg_ids = cfg.get("security_group_ids") or cfg.get("security-group-ids")
            key_name = cfg.get("key_name") or cfg.get("key-name")
            user_data = cfg.get("user_data") or cfg.get("user-data")

            cmd = build_run_instances_command(
                image_id=image_id,
                instance_type=inst_type,
                count=count,
                subnet_id=subnet_id,
                security_group_ids=sg_ids,
                key_name=key_name,
                name_tag=name_tag,
                user_data=user_data,
                command_id=cmd_id,
                depends_on=dep_command_ids,
                resource_ref=ref,
            )
            ver_cmd = build_describe_instances_command(
                instance_ids=[f"{{{{{ref}.id}}}}"],
                command_id=f"ver-{cmd_id}",
            )
            return [cmd], ver_cmd

        # ── EC2 Key Pair ─────────────────────────────────────────────
        elif svc_name == "ec2" and resource_type == "key_pair":
            key_name = res_name or cfg.get("key_name") or cfg.get("key-name") or f"key-{uuid.uuid4().hex[:6]}"
            cmd = build_create_key_pair_command(
                key_name=key_name,
                command_id=cmd_id,
                resource_ref=ref,
            )
            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="ec2",
                action="describe-key-pairs",
                parameters={"key-names": [key_name]},
                description=f"Verify Key Pair {key_name}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return [cmd], ver_cmd

        # ── S3 Bucket ────────────────────────────────────────────────
        elif svc_name == "s3" and resource_type == "bucket":
            bucket_name = res_name or cfg.get("bucket") or cfg.get("bucket_name") or f"agent-bucket-{uuid.uuid4().hex[:8]}"
            acl = cfg.get("acl")
            cmd = build_create_bucket_command(
                bucket_name=bucket_name,
                region=region,
                acl=acl,
                command_id=cmd_id,
                resource_ref=ref,
            )
            ver_cmd = build_head_bucket_command(
                bucket_name=bucket_name,
                command_id=f"ver-{cmd_id}",
                resource_ref=ref,
            )
            return [cmd], ver_cmd

        # ── IAM Role ─────────────────────────────────────────────────
        elif svc_name == "iam" and resource_type == "role":
            role_name = res_name or cfg.get("role_name") or cfg.get("role-name") or f"agent-role-{uuid.uuid4().hex[:6]}"
            assume_doc = cfg.get("assume_role_policy_document") or cfg.get("assume-role-policy-document") or '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
            cmd = build_create_role_command(
                role_name=role_name,
                assume_role_policy_document=assume_doc,
                description=cfg.get("description"),
                command_id=cmd_id,
                resource_ref=ref,
            )
            ver_cmd = build_get_role_command(
                role_name=role_name,
                command_id=f"ver-{cmd_id}",
                resource_ref=ref,
            )
            return [cmd], ver_cmd

        # ── IAM Policy ───────────────────────────────────────────────
        elif svc_name == "iam" and resource_type == "policy":
            policy_name = res_name or cfg.get("policy_name") or cfg.get("policy-name") or f"agent-policy-{uuid.uuid4().hex[:6]}"
            policy_doc = cfg.get("policy_document") or cfg.get("policy-document") or '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}'
            cmd = build_create_policy_command(
                policy_name=policy_name,
                policy_document=policy_doc,
                description=cfg.get("description"),
                command_id=cmd_id,
                resource_ref=ref,
            )
            ver_cmd = CLICommand(
                command_id=f"ver-{cmd_id}",
                service="iam",
                action="get-policy",
                parameters={"policy-arn": f"{{{{{ref}.id}}}}"},
                description=f"Verify Policy {policy_name}",
                operation_category=OperationCategory.READ_ONLY,
            )
            return [cmd], ver_cmd

        # ── DynamoDB Table ───────────────────────────────────────────
        elif svc_name == "dynamodb" and resource_type == "table":
            table_name = res_name or cfg.get("table_name") or cfg.get("table-name") or f"agent-table-{uuid.uuid4().hex[:6]}"
            key_schema = cfg.get("key_schema") or cfg.get("key-schema") or [{"AttributeName": "id", "KeyType": "HASH"}]
            attr_defs = cfg.get("attribute_definitions") or cfg.get("attribute-definitions") or [{"AttributeName": "id", "AttributeType": "S"}]
            billing_mode = cfg.get("billing_mode") or cfg.get("billing-mode") or "PAY_PER_REQUEST"
            cmd = build_create_table_command(
                table_name=table_name,
                key_schema=key_schema,
                attribute_definitions=attr_defs,
                billing_mode=billing_mode,
                command_id=cmd_id,
                resource_ref=ref,
            )
            ver_cmd = build_describe_table_command(
                table_name=table_name,
                command_id=f"ver-{cmd_id}",
                resource_ref=ref,
            )
            return [cmd], ver_cmd

        # Generic fallback using ResourceTypeDefinition metadata
        rt_def = self.registry.get_resource_type(svc_name, resource_type)
        if rt_def and rt_def.create_action:
            cmd = CLICommand(
                command_id=cmd_id,
                service=rt_def.cli_service,
                action=rt_def.create_action,
                parameters=cfg,
                description=f"Create {svc_name} {resource_type}",
                operation_category=classify_aws_action(rt_def.cli_service, rt_def.create_action),
                resource_ref=ref,
                depends_on=dep_command_ids,
                output_key=rt_def.id_field,
            )
            ver_cmd = None
            if rt_def.describe_action:
                ver_cmd = CLICommand(
                    command_id=f"ver-{cmd_id}",
                    service=rt_def.cli_service,
                    action=rt_def.describe_action,
                    parameters={},
                    description=f"Verify {svc_name} {resource_type}",
                    operation_category=OperationCategory.READ_ONLY,
                )
            return [cmd], ver_cmd

        raise UnsupportedResourceTypeError(
            f"Cannot build creation command for unsupported resource type '{resource_type}' in service '{svc_name}'."
        )

    def _compile_read_command(
        self,
        svc_name: str,
        resource_type: str,
        cfg: dict[str, Any],
        cmd_id: str,
        region: str,
        profile: str,
    ) -> Optional[CLICommand]:
        """Compile a read-only list/describe operation."""
        if svc_name == "ec2" and resource_type in ("instance", "ami"):
            return build_describe_instances_command(
                instance_ids=cfg.get("instance_ids") or cfg.get("instance-ids"),
                filters=cfg.get("filters"),
                command_id=cmd_id,
            )
        elif svc_name == "s3" and resource_type == "bucket":
            return build_list_buckets_command(command_id=cmd_id)
        elif svc_name == "vpc" and resource_type == "vpc":
            return CLICommand(
                command_id=cmd_id,
                service="ec2",
                action="describe-vpcs",
                parameters=cfg,
                description="Describe VPCs in region",
                operation_category=OperationCategory.READ_ONLY,
            )
        elif svc_name == "vpc" and resource_type == "subnet":
            return CLICommand(
                command_id=cmd_id,
                service="ec2",
                action="describe-subnets",
                parameters=cfg,
                description="Describe Subnets in region",
                operation_category=OperationCategory.READ_ONLY,
            )
        elif svc_name == "vpc" and resource_type == "security_group":
            return CLICommand(
                command_id=cmd_id,
                service="ec2",
                action="describe-security-groups",
                parameters=cfg,
                description="Describe Security Groups in region",
                operation_category=OperationCategory.READ_ONLY,
            )

        rt_def = self.registry.get_resource_type(svc_name, resource_type)
        if rt_def and (rt_def.list_action or rt_def.describe_action):
            action = rt_def.list_action or rt_def.describe_action
            return CLICommand(
                command_id=cmd_id,
                service=rt_def.cli_service,
                action=action,
                parameters=cfg,
                description=f"List/describe {svc_name} {resource_type}",
                operation_category=OperationCategory.READ_ONLY,
            )
        return None

    def _compile_delete_command(
        self,
        svc_name: str,
        resource_type: str,
        cfg: dict[str, Any],
        res_name: Optional[str],
        cmd_id: str,
        ref: str,
    ) -> Optional[CLICommand]:
        """Compile a deletion command."""
        if svc_name == "s3" and resource_type == "bucket":
            bucket = res_name or cfg.get("bucket") or cfg.get("bucket_name") or ""
            return build_delete_bucket_command(bucket_name=bucket, command_id=cmd_id, resource_ref=ref)

        elif svc_name == "ec2" and resource_type == "instance":
            inst_ids = cfg.get("instance_ids") or cfg.get("instance-ids") or ([res_name] if res_name else [])
            return build_terminate_instances_command(instance_ids=inst_ids, command_id=cmd_id, resource_ref=ref)

        elif svc_name == "vpc" and resource_type == "vpc":
            vpc_id = cfg.get("vpc_id") or cfg.get("vpc-id") or res_name or ""
            return build_delete_vpc_command(vpc_id=vpc_id, command_id=cmd_id, resource_ref=ref)

        elif svc_name == "vpc" and resource_type == "subnet":
            subnet_id = cfg.get("subnet_id") or cfg.get("subnet-id") or res_name or ""
            return build_delete_subnet_command(subnet_id=subnet_id, command_id=cmd_id, resource_ref=ref)

        elif svc_name == "vpc" and resource_type == "security_group":
            group_id = cfg.get("group_id") or cfg.get("group-id") or res_name or ""
            return build_delete_security_group_command(group_id=group_id, command_id=cmd_id, resource_ref=ref)

        rt_def = self.registry.get_resource_type(svc_name, resource_type)
        if rt_def and rt_def.delete_action:
            return CLICommand(
                command_id=cmd_id,
                service=rt_def.cli_service,
                action=rt_def.delete_action,
                parameters=cfg,
                description=f"Delete {svc_name} {resource_type}",
                operation_category=OperationCategory.DESTRUCTIVE,
                resource_ref=ref,
            )
        return None
