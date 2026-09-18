"""
LLM Prompt templates for the AWS Provisioning Agent.

Contains all system prompts, planning prompts, and response generation
templates used to communicate with the LLM. Prompts are structured to
produce JSON-conformant output that maps to Pydantic models.
"""

from __future__ import annotations

from typing import Any

# ──────────────────────────────────────────────
# System Prompt
# ──────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert AWS Cloud Infrastructure Agent. Your role is to interpret natural-language requests about AWS resources and produce structured provisioning plans.

## Your Responsibilities
1. Understand what the user wants to create, modify, describe, or delete in AWS.
2. Identify ALL required AWS resources, including dependencies.
3. Determine the correct order of operations (dependency order).
4. Generate accurate AWS CLI commands with proper syntax.
5. Identify missing parameters and ask for them instead of guessing dangerous values.
6. Assess risk levels honestly.
7. Provide educational explanations when requested.

## Rules
- ALWAYS output valid JSON matching the requested schema.
- NEVER invent AWS resource IDs. Use placeholder references like {{VpcId}} when a resource ID will come from a previous command's output.
- Use proper AWS CLI parameter names (hyphenated, e.g., --instance-type, --cidr-block).
- For regions other than ap-south-1, include --create-bucket-configuration LocationConstraint=<region> for S3.
- Security groups need a VPC ID. Check if a default VPC is available.
- Be conservative: prefer t3.micro/t2.micro for EC2, PAY_PER_REQUEST for DynamoDB.
- For EC2, prefer Amazon Linux 2023 AMIs when the user doesn't specify.
- NEVER generate commands that are not AWS CLI commands.
- NEVER include shell operators (|, ;, &&, ||) in command parameters.
- If information is missing and cannot be safely defaulted, list it in missing_parameters.

## Safe Defaults (use ONLY when the user doesn't specify)
- EC2 instance type: t3.micro
- EC2 AMI: Use appropriate Amazon Linux 2023 AMI for the region
- VPC CIDR: 10.0.0.0/16
- Subnet CIDR: 10.0.1.0/24
- DynamoDB billing: PAY_PER_REQUEST
- S3: private (no public access)

## Supported Services
{services_context}

## Current AWS Context
Account ID: {account_id}
Region: {region}
Profile: {profile}

## Existing Resources (if discovered)
{existing_resources}
"""

# ──────────────────────────────────────────────
# Plan Generation Prompt
# ──────────────────────────────────────────────

PLAN_GENERATION_PROMPT = """Analyze the following user request and generate a structured desired-state provisioning plan.

## User Request
{user_request}

## Conversation History (for context)
{conversation_history}

## Previously Created Resources (in this session)
{session_resources}

## Instructions
Generate a JSON object specifying the DESIRED INFRASTRUCTURE STATE with this EXACT structure:

{{
  "intent": "Clear description of what the user wants to accomplish",
  "operation_type": "create|read|update|delete|list|describe|modify|start|stop|attach|detach",
  "aws_region": "{region}",
  "resources": [
    {{
      "logical_ref": "Unique reference key (e.g. 'vpc.main', 'subnet.public', 'security_group.web', 'ec2.web', 's3.bucket')",
      "resource_type": "instance|bucket|vpc|subnet|security_group|internet_gateway|route_table|role|policy|function|table|db_instance|cluster",
      "service": "ec2|s3|vpc|iam|lambda|dynamodb|rds|ecs",
      "resource_name": "Descriptive name or tag for the resource, or null",
      "configuration": {{
        "key": "value"
      }},
      "dependencies": ["list of logical_refs this resource depends on (e.g. ['vpc.main'])"],
      "tags": {{"Name": "resource-name"}}
    }}
  ],
  "missing_parameters": ["List any required information not provided and unsafe to default, or empty"],
  "assumptions": ["List any safe defaults or assumptions applied"]
}}

IMPORTANT:
- Do NOT output executable AWS CLI commands, CLI actions, syntax, or command arrays. Application code deterministically generates all AWS CLI commands.
- For dependencies, specify the logical_ref of the prerequisite resource (e.g., subnet depends on vpc.main).
- For referenced IDs in configuration, use placeholder syntax {{logical_ref.id}} (e.g., "vpc_id": "{{vpc.main.id}}").
- Output ONLY valid JSON matching this schema, with no markdown formatting or commentary.
"""

# ──────────────────────────────────────────────
# Explanation Generation Prompt
# ──────────────────────────────────────────────

EXPLANATION_PROMPT = """Generate a detailed explanation of what happened during this AWS operation.

## Original Request
{user_request}

## Execution Plan
{plan_summary}

## Execution Results
{execution_results}

## Verification Results
{verification_results}

## Instructions
Provide a clear, structured explanation covering:

1. **What was requested**: Restate what the user asked for
2. **What the agent interpreted**: The specific AWS resources and configuration
3. **What happened**: Step-by-step what was executed and the outcome
4. **AWS resources affected**: List all resource IDs, names, and states
5. **Commands used**: Show the actual CLI commands with brief explanations of why each was used
6. **Verification**: How the results were verified
7. **Final state**: Summary of what exists now

If there were failures, explain:
- What failed and why
- Which resources were successfully created
- Recommended next steps

Format as clean markdown. Be concise but thorough.
"""

# ──────────────────────────────────────────────
# Educational Content Prompt
# ──────────────────────────────────────────────

EDUCATIONAL_PROMPT = """Provide educational content about the following AWS operation.

## Operation
{operation_description}

## Resources Involved
{resources}

## Instructions
Explain the following in beginner-friendly but technically accurate language:

1. **What is this resource?**: Brief explanation of each AWS resource involved
2. **Why is it needed?**: Why this resource is required for the user's goal
3. **AWS Architecture**: How these resources fit into AWS architecture
4. **CLI Command Breakdown**: Explain each flag/parameter used
5. **Security Considerations**: Important security aspects to be aware of
6. **Cost Considerations**: What charges might apply (don't invent exact prices)
7. **Common Mistakes**: Typical errors when working with these resources
8. **Best Practices**: Recommended approaches
9. **Related Concepts**: Other AWS services/concepts worth knowing

Format as clean markdown with sections. Keep it educational and practical.
"""

# ──────────────────────────────────────────────
# Missing Information Prompt
# ──────────────────────────────────────────────

MISSING_INFO_PROMPT = """The user made the following request, but some important information is missing.

## User Request
{user_request}

## Missing Information
{missing_params}

## Instructions
Generate a friendly message asking the user for the missing information.
For each missing parameter:
1. Explain what it is and why it's needed
2. Suggest a safe default if one exists
3. Ask if the user wants to provide a specific value or use the default

Format as a conversational message, not a JSON object.
Be helpful and educational, not robotic.
"""

# ──────────────────────────────────────────────
# Error Analysis Prompt
# ──────────────────────────────────────────────

ERROR_ANALYSIS_PROMPT = """Analyze the following AWS CLI error and provide a helpful explanation.

## Command
{command}

## Error Output
{error}

## Exit Code
{exit_code}

## Instructions
Provide:
1. **What went wrong**: Clear explanation of the error
2. **Likely cause**: Most common reasons for this error
3. **How to fix it**: Specific steps the user can take
4. **Prevention**: How to avoid this in the future

Format as clean markdown. Be specific and actionable.
"""


def build_system_prompt(
    services_context: str = "",
    account_id: str = "Unknown",
    region: str = "ap-south-1",
    profile: str = "default",
    existing_resources: str = "None discovered",
) -> str:
    """Build the complete system prompt with context."""
    return SYSTEM_PROMPT.format(
        services_context=services_context,
        account_id=account_id,
        region=region,
        profile=profile,
        existing_resources=existing_resources,
    )


def build_plan_prompt(
    user_request: str,
    region: str = "ap-south-1",
    conversation_history: str = "",
    session_resources: str = "None",
    rag_context: Optional[str] = None,
) -> str:
    """Build the plan generation prompt with optional RAG context."""
    prompt = PLAN_GENERATION_PROMPT.format(
        user_request=user_request,
        region=region,
        conversation_history=conversation_history,
        session_resources=session_resources,
    )
    if rag_context and rag_context.strip():
        prompt += f"\n\n{rag_context}\n"
    return prompt


def build_explanation_prompt(
    user_request: str,
    plan_summary: str,
    execution_results: str,
    verification_results: str = "No verification performed",
) -> str:
    """Build the explanation generation prompt."""
    return EXPLANATION_PROMPT.format(
        user_request=user_request,
        plan_summary=plan_summary,
        execution_results=execution_results,
        verification_results=verification_results,
    )


def build_educational_prompt(
    operation_description: str,
    resources: str,
) -> str:
    """Build the educational content prompt."""
    return EDUCATIONAL_PROMPT.format(
        operation_description=operation_description,
        resources=resources,
    )


def build_missing_info_prompt(
    user_request: str,
    missing_params: list[str],
) -> str:
    """Build the missing information prompt."""
    return MISSING_INFO_PROMPT.format(
        user_request=user_request,
        missing_params="\n".join(f"- {p}" for p in missing_params),
    )


def build_error_analysis_prompt(
    command: str,
    error: str,
    exit_code: int,
) -> str:
    """Build the error analysis prompt."""
    return ERROR_ANALYSIS_PROMPT.format(
        command=command,
        error=error,
        exit_code=exit_code,
    )
