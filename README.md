<div align="center">

# ☁️ AWS Resource Provisioning AI Agent

### *Intelligent Natural-Language Cloud Infrastructure Provisioning with Hardened AWS CLI Execution*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![AWS CLI](https://img.shields.io/badge/AWS%20CLI-v2-232F3E.svg?logo=amazon-aws)](https://aws.amazon.com/cli/)
[![Pydantic v2](https://img.shields.io/badge/validation-Pydantic%20v2-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/tests-58%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[Features](#-key-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Security Model](#-hardened-security-model) • [Supported Services](#-supported-aws-services) • [Walkthrough](#-step-by-step-walkthrough) • [Testing](#-testing)

</div>

---

## 📖 Overview

The **AWS Resource Provisioning Agent** is an intelligent cloud assistant that allows DevOps engineers, cloud architects, and developers to provision and manage AWS infrastructure using everyday natural language. 

Instead of writing verbose Infrastructure-as-Code (IaC) or memorizing hundreds of AWS CLI parameters, you simply state what you want to achieve:

> *"Create a simple web server in Mumbai using an EC2 t3.micro instance with HTTP access."*
> 
> *"Create a VPC with one public subnet, an internet gateway, and a route table."*
> 
> *"Launch a DynamoDB table called 'students' with pay-per-request billing."*
> 
> *"Show me what EC2 instances currently exist."*

The agent reasons about dependencies, discovers existing resources, compiles a structured plan, validates commands through an allowlist, enforces human approval policies, executes commands via the AWS CLI, verifies live resource states, and provides educational architectural explanations.

---

## 🏛️ Core Design Philosophy

$$\mathbf{LLM\ (Reasoning\ \&\ Planning)} \longrightarrow \mathbf{App\ Code\ (Validation\ \&\ Policy)} \longrightarrow \mathbf{AWS\ CLI\ (Execution)} \longrightarrow \mathbf{AWS\ (Source\ of\ Truth)}$$

* **The LLM never directly executes shell commands.** It is restricted to producing structured JSON blueprints conforming to a strict Pydantic schema.
* **Application code is the absolute security boundary.** Command allowlists, parameter regular expressions, anti-injection checks, and human approvals are enforced deterministically by Python code.
* **AWS CLI performs all real-world operations.** Subprocess calls use tokenized argument arrays with `shell=False`—eliminating command injection vulnerabilities.
* **AWS is the source of truth.** The agent verifies resource creation through real-time AWS API calls (`describe-*`, `head-*`), never blindly trusting return codes.

---

## 🚀 Key Features

* 💬 **Natural Language Understanding:** Parses high-level user intent and automatically resolves missing parameters using safe, conservative defaults (e.g., `t3.micro`, Amazon Linux 2023, default VPC).
* 🔍 **Default Dry Run Mode:** Analyzes requests, resolves dependencies, displays exact AWS CLI commands, highlights potential risks and costs, and provides rollback steps—without modifying your AWS environment.
* 🛡️ **Hardened Subprocess Security:** Disables `shell=True`, validates commands against an action allowlist, enforces command timeouts, and strips shell metacharacters.
* 🛑 **Human-in-the-Loop Approvals:**
  * **READ_ONLY** operations (`describe-*`, `list-*`) run automatically.
  * **WRITE** operations (`create-*`, `run-instances`) require interactive UI approval.
  * **DESTRUCTIVE** operations (`delete-*`, `terminate-*`) require typed confirmation (`CONFIRM DELETE`).
* 📦 **Dependency Graph Resolution:** Intelligently maps resource relationships (e.g., `VPC` $\to$ `Subnet` $\to$ `Security Group` $\to$ `EC2 Instance`) and feeds extracted runtime IDs into downstream commands.
* 🔍 **Existing Resource Awareness:** Inspects the target region for existing default VPCs, subnets, and security groups to prevent duplicate infrastructure.
* 📚 **Educational "Learning Mode":** Provides deep explanations of AWS architecture, CLI flag breakdowns, security considerations, cost caveats, and related interview questions.
* 🔒 **Zero Hardcoded Credentials & Secret Redaction:** Automatically masks AWS access keys (`AKIA...`), session tokens, passwords, and account IDs in logs and chat outputs.
* 📋 **Audit History Store:** Automatically records every execution plan, command result, and verification status in a searchable local JSON audit store.

---

## 🏗️ Architecture

```
User Prompt (Streamlit UI)
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                     Agent Orchestrator                      │
└─────┬───────────────────┬───────────────────┬───────────────┘
      │                   │                   │
      ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐
│Request Parser│   │  Discovery   │   │  Pluggable LLM Client  │
│(Anti-Inject, │   │(Default VPC, │   │(Gemini, OpenAI, Claude,│
│Sanitization) │   │ Subnets, SGs)│   │  Azure OpenAI, Ollama) │
└──────┬───────┘   └──────┬───────┘   └───────────┬────────────┘
       │                  │                       │
       └──────────────────┼───────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      Resource Planner                       │
│    (Generates validated Pydantic `ProvisioningPlan`)        │
└─────┬───────────────────┬───────────────────┬───────────────┘
      │                   │                   │
      ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐
│CLI Validator │   │Policy Engine │   │    Approval Manager    │
│(Allowlists,  │   │(Risk: LOW,   │   │ (Auto / Interactive /  │
│Regex Checks) │   │MED, HIGH, CRI│   │ Explicit Typed Confirm)│
└──────┬───────┘   └──────┬───────┘   └───────────┬────────────┘
       │                  │                       │
       └──────────────────┼───────────────────────┘
                          │ Approved Plan
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      AWS CLI Executor                       │
│      (subprocess.run, shell=False, Arg Arrays, Timeouts)     │
└─────────────────────────┬───────────────────────────────────┘
                          │ Captures stdout / stderr / exit
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               Output Parser & Resource Verifier             │
│        (describe-* / head-*, Ground-Truth State Check)      │
└─────┬───────────────────────────────────────┬───────────────┘
      │                                       │
      ▼                                       ▼
┌──────────────┐                      ┌───────────────┐
│  Explainer   │                      │Execution Store│
│(+ Learn Mode)│                      │ (JSON Audit)  │
└──────────────┘                      └───────────────┘
```

---

## 🛠️ Supported AWS Services

| Service | Supported Resource Types | CLI Service | Supported Operations |
|---|---|---|---|
| **EC2** | Instances, Key Pairs, AMIs | `aws ec2` | `run-instances`, `describe-instances`, `terminate-instances`, `create-key-pair`, `describe-images` |
| **S3** | Buckets | `aws s3api` | `create-bucket`, `head-bucket`, `list-buckets`, `delete-bucket`, `put-public-access-block` |
| **VPC** | VPCs, Subnets, Gateways, Routes, Security Groups | `aws ec2` | `create-vpc`, `create-subnet`, `create-internet-gateway`, `create-route-table`, `create-security-group`, `authorize-security-group-ingress` |
| **IAM** | Roles, Policies | `aws iam` | `create-role`, `get-role`, `delete-role`, `create-policy`, `attach-role-policy` |
| **Lambda** | Functions | `aws lambda` | `create-function`, `get-function`, `delete-function`, `list-functions`, `invoke` |
| **DynamoDB** | Tables | `aws dynamodb` | `create-table`, `describe-table`, `delete-table`, `list-tables`, `update-table` |
| **RDS** | DB Instances, Subnet Groups | `aws rds` | `create-db-instance`, `describe-db-instances`, `delete-db-instance`, `create-db-subnet-group` |
| **ECS** | Clusters, Task Definitions | `aws ecs` | `create-cluster`, `describe-clusters`, `delete-cluster`, `register-task-definition` |

---

## 🔒 Hardened Security Model

```
 ┌──────────────────────────────────────────────────────────────┐
 │                      Security Perimeter                      │
 ├──────────────────────────────────────────────────────────────┤
 │  1. Prompt Injection Protection   -> Blocks bypass attempts  │
 │  2. Parameter Sanitization        -> No ;, |, &&, ``, $()    │
 │  3. Service & Action Allowlist    -> Approved AWS CLI only   │
 │  4. subprocess.run(shell=False)   -> Array-based tokenizing  │
 │  5. Automatic Secret Redaction    -> Masks keys & passwords  │
 │  6. Mandatory Human Approval      -> Explicit confirmation   │
 └──────────────────────────────────────────────────────────────┘
```

1. **No `shell=True` Anywhere:** All execution uses native argument token arrays (`["aws", "ec2", "..."]`) preventing shell interpolation and command chaining.
2. **Strict Command Allowlisting:** Any command starting outside `ALLOWED_SERVICES` or containing unapproved actions is blocked before reaching the OS.
3. **Automated Secret Redaction:** AWS Access Keys (`AKIA...`), secret tokens, passwords, and account IDs are masked in stdout, stderr, logs, and persistent history.
4. **Dangerous Pattern Interception:** Attempts to attach `AdministratorAccess`, grant `0.0.0.0/0` across all ports, or issue bulk deletions (`--all`) trigger blocking policy alerts.

---

## 🚦 Approval Decision Matrix

| Operation Category | Trigger Conditions | Approval Requirement | UI Behavior |
|---|---|---|---|
| **READ_ONLY** | `describe-*`, `list-*`, `get-*`, `head-*` | **Auto-Approved** | Executes immediately; results shown |
| **WRITE** | `create-*`, `run-instances`, `put-*` | **Standard Approval** | Displays interactive **[Execute]** and **[Cancel]** buttons |
| **DESTRUCTIVE** | `delete-*`, `terminate-*`, `revoke-*` | **Explicit Confirmation** | User must explicitly type `CONFIRM DELETE` |
| **CRITICAL RISK** | Bulk deletions, wildcard IAM actions | **Explicit Confirmation** | Warning banner + typed confirmation |

---

## ⚡ Quick Start

### 1. Prerequisites
* **Python 3.11+**
* **AWS CLI v2** installed (`aws --version`)
* **AWS Credentials** configured (`aws configure`)
* An LLM API key (e.g. Google Gemini, OpenAI, or Anthropic)

### 2. Installation
```bash
# Clone repository
git clone https://github.com/Mokshith-9391/aws-agent.git
cd aws-agent

# Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment
Copy the example environment template:
```bash
cp .env.example .env
```
Edit `.env` to set your LLM provider and credentials:
```ini
# AWS Settings
AWS_PROFILE=default
AWS_REGION=ap-south-1

# LLM Configuration (google, openai, anthropic, azure_openai, ollama)
LLM_PROVIDER=google
LLM_MODEL=gemini-2.0-flash
API_KEY=your-gemini-api-key-here
```

### 4. Launch the Application
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 💬 Sample Interaction & Screenshots

### 1. Dry Run Analysis
When **Dry Run** mode is enabled (default), the agent analyzes your prompt without touching AWS:

```
User: "Create a simple web server in Mumbai using an EC2 t3.micro instance with HTTP access."

Agent: 🔍 Dry Run Analysis
Intent: Create a web server with port 80 HTTP ingress in ap-south-1
Region: ap-south-1 | Risk: MEDIUM | Destructive: No

AWS CLI Commands That Would Be Executed:
1. aws ec2 create-security-group --group-name ai-agent-web-sg --description "Allow HTTP" --vpc-id vpc-0a1b2c3d4e5f67890
2. aws ec2 authorize-security-group-ingress --group-id {{GroupId}} --protocol tcp --port 80 --cidr 0.0.0.0/0
3. aws ec2 run-instances --image-id ami-0123456789abcdef0 --instance-type t3.micro --security-group-ids {{GroupId}}

Resource Dependencies:
- security_group -> instance

💰 Cost Warnings:
- EC2 instances incur charges while running. Remember to terminate when not in use.

ℹ️ This is a dry run. No changes were made to AWS.
```

### 2. Live Execution & Verification
When you turn off Dry Run and approve the plan, the agent executes and verifies:

```
[Execute] -> Subprocess runs commands with shell=False
-> Extracted GroupId: sg-0987654321fedcba0
-> Extracted InstanceId: i-0abcdef1234567890
-> Live Verification: describe-instances confirmed State = "running"
-> Full architectural explanation and cost management guidance returned
```

---

## 🧪 Testing

The repository includes a comprehensive test suite of **58 automated unit and end-to-end tests**. The tests mock all AWS CLI interactions and LLM responses, allowing you to run them **100% offline without AWS credentials or charges**:

```bash
# Run all tests
python -m pytest tests/ -v

# Run with test coverage report
python -m pytest tests/ --cov=. --cov-report=term-missing
```

### Test Suite Breakdown
* `tests/test_parser.py`: Tests prompt injection rejection, input sanitization, length limits, and region extraction.
* `tests/test_validator.py`: Tests command allowlists, shell injection filtering, CIDR regex, AMI formats, and port limits.
* `tests/test_security.py`: Tests safety policy risk classifier, dangerous pattern blocking, and secret redaction.
* `tests/test_services.py`: Tests all 8 service handlers and registry metadata.
* `tests/test_cli_executor.py`: Tests secure subprocess invocation (`shell=False`), exit code capture, and JSON resource ID parsing.
* `tests/test_planner.py`: Tests structured JSON plan generation, fallback handling, and rollback/verification extraction.
* `tests/test_e2e_scenario.py`: Validates the complete Section 43 web server scenario end-to-end.

---

## 📂 Project Structure

```
aws-agent/
├── app.py                      # Streamlit UI & Interactive Approval State
├── requirements.txt            # Python Dependencies
├── .env.example                # Sample Environment Template
├── .gitignore                  # Git Ignore Policy (Protects credentials/logs)
├── README.md                   # Full Production Documentation
│
├── config/
│   ├── __init__.py
│   └── settings.py             # Pydantic Settings & Environment Loading
│
├── agent/
│   ├── __init__.py
│   ├── models.py               # Pydantic Contracts (Plan, Command, Result, Identity)
│   ├── llm_client.py           # Multi-Provider LLM Abstraction (Gemini, OpenAI, Claude, Ollama)
│   ├── prompts.py              # Prompt Templates & Guardrails
│   ├── parser.py               # Prompt Injection Detection & Input Sanitization
│   ├── planner.py              # Plan Generation & Service Registry Enrichment
│   ├── orchestrator.py         # 11-Stage Request Lifecycle Coordinator
│   └── explainer.py            # Post-Execution Technical & Educational Generator
│
├── aws/
│   ├── __init__.py
│   ├── cli_executor.py         # Subprocess Execution Layer (shell=False, Timeouts, Redaction)
│   ├── cli_validator.py        # Static Parameter & Action Allowlist Validator
│   ├── identity.py             # AWS CLI Health Check & STS Identity Discovery
│   ├── verification.py         # Post-Provisioning Live State Verifier
│   └── resource_discovery.py   # Pre-flight Infrastructure Discovery (VPCs, SGs, Subnets)
│
├── services/
│   ├── __init__.py
│   ├── registry.py             # Pluggable AWS Service Registry
│   ├── ec2.py                  # EC2 Instance & KeyPair Service Handler
│   ├── s3.py                   # S3 Bucket Service Handler
│   ├── vpc.py                  # VPC, Subnet, IGW, RouteTable, SG Service Handler
│   ├── iam.py                  # IAM Role & Policy Service Handler
│   ├── lambda_service.py       # AWS Lambda Function Service Handler
│   ├── dynamodb.py             # DynamoDB Table Service Handler
│   ├── rds.py                  # RDS Database Service Handler
│   └── ecs.py                  # ECS Cluster & Task Definition Handler
│
├── security/
│   ├── __init__.py
│   ├── policy.py               # Safety Policy Rules & Risk Classifier
│   ├── sanitizer.py            # Secret Redactor (AKIA, Tokens, Passwords)
│   └── approvals.py            # Approval Decision Matrix (Auto/Manual/Confirm)
│
├── history/
│   ├── __init__.py
│   └── execution_store.py      # Auditable JSON Execution History Store
│
└── tests/
    ├── __init__.py
    ├── test_parser.py
    ├── test_validator.py
    ├── test_services.py
    ├── test_security.py
    ├── test_cli_executor.py
    ├── test_planner.py
    └── test_e2e_scenario.py
```

---

## 🔌 Adding a New AWS Service

The application is built with a pluggable service architecture. To add a new service (e.g., **Amazon SQS**):

1. **Create the Service Handler (`services/sqs.py`):**
   ```python
   from services.registry import AWSServiceRegistry, ServiceDefinition, ResourceTypeDefinition

   def register_sqs_service(registry: AWSServiceRegistry) -> None:
       service = ServiceDefinition(
           service_name="sqs",
           cli_service="sqs",
           description="Amazon Simple Queue Service",
       )
       queue_def = ResourceTypeDefinition(
           service="sqs",
           resource_type="queue",
           cli_service="sqs",
           description="Standard or FIFO SQS Queue",
           create_action="create-queue",
           describe_action="get-queue-attributes",
           delete_action="delete-queue",
           list_action="list-queues",
           required_params=["queue-name"],
           id_field="QueueUrl",
           cost_warning="SQS requests beyond free tier incur charges.",
       )
       service.add_resource_type(queue_def)
       registry.register_service(service)
   ```

2. **Register the Handler:**
   Import and invoke `register_sqs_service(registry)` in `services/registry.py:create_default_registry()`.

3. **Update Allowlist in `aws/cli_executor.py`:**
   Add `'sqs'` to `ALLOWED_SERVICES` and register permitted actions (`create-queue`, `delete-queue`, etc.) in `ALLOWED_ACTIONS['sqs']`.

---

## ❓ Troubleshooting

| Issue | Likely Cause | Solution |
|---|---|---|
| **"AWS CLI not installed"** | AWS CLI v2 is missing from system `PATH`. | Install from [AWS CLI Official Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and reopen terminal. |
| **"Credentials invalid"** | Stale or unconfigured AWS credentials. | Run `aws configure` or verify `AWS_PROFILE` in your `.env`. |
| **"Agent initialization failed"** | Missing or incorrect LLM API key. | Ensure `API_KEY` is set in `.env` for your selected `LLM_PROVIDER`. |
| **"Command validation failed"** | Injection pattern or unapproved CLI command. | The validator blocked an unauthorized action or dangerous metacharacter. |
| **"AccessDenied" during execution** | IAM user/role lacks permissions for the action. | Attach appropriate IAM policies for the target service (e.g. `AmazonEC2FullAccess`). |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.