<div align="center">

# ☁️ AWS Resource Provisioning AI Agent

### *Intelligent Natural-Language Cloud Infrastructure Provisioning with Hardened AWS CLI Execution*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![AWS CLI](https://img.shields.io/badge/AWS%20CLI-v2-232F3E.svg?logo=amazon-aws)](https://aws.amazon.com/cli/)
[![Pydantic v2](https://img.shields.io/badge/validation-Pydantic%20v2-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/tests-116%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[Features](#-key-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Security Model](#-hardened-security-model) • [Supported Services](#-supported-aws-services) • [Walkthrough](#-step-by-step-walkthrough) • [Testing](#-testing)

</div>

---

## 📖 Overview

The **AWS Resource Provisioning Agent** is a production-grade, hardened cloud infrastructure assistant that allows DevOps engineers, cloud architects, and developers to safely plan, provision, and manage AWS resources using natural language.

Instead of writing complex Infrastructure-as-Code (IaC) or memorizing hundreds of AWS CLI parameter combinations, you state your infrastructure intent directly:

> *"Create a simple web server in Mumbai using an EC2 t3.micro instance with HTTP access."*
> 
> *"Create a VPC with one public subnet, an internet gateway, and a route table."*
> 
> *"Launch a DynamoDB table called 'students' with pay-per-request billing."*
> 
> *"Show me what EC2 instances currently exist."*

The agent reasons about cloud architectures, queries live AWS state, builds a directed acyclic dependency graph, compiles desired-state resources through deterministic Python service builders, validates commands through an allowlist and safety policy, enforces human approval, executes commands safely through the AWS CLI, verifies real-world resource states against AWS APIs, and provides educational architectural explanations.

---

## 🏛️ Core Design Philosophy & Execution Invariant

$$\text{Natural Language} \longrightarrow \text{LLM Intent / Desired State} \longrightarrow \text{Structured Plan} \longrightarrow \text{Deterministic Python Compilers \& Builders} \longrightarrow \text{DAG} \longrightarrow \text{Policy/Validation} \longrightarrow \text{Approval} \longrightarrow \text{AWS CLI Execution} \longrightarrow \text{AWS Truth} \longrightarrow \text{Verification} \longrightarrow \text{Controlled Rollback}$$

* **The LLM is NEVER authoritative for executable CLI commands.** The LLM is strictly confined to intent understanding and desired-state specification (`DesiredResource`: `logical_ref`, `resource_type`, `configuration`, `dependencies`). It is prohibited from authoring executable CLI syntax, flags, action names, resource IDs, rollback commands, or security policies.
* **Deterministic Python Compilers & Builders:** Application code (`agent/compiler.py` + `services/`) is the sole authority for translating desired resources into validated, executable `CLICommand` objects. Any unapproved or unsupported resource type is rejected immediately before command generation.
* **Allowlist Closure:** Execution service allowlists are strictly bounded by explicit action sets (`ALLOWED_SERVICES = set(ALLOWED_ACTIONS.keys())`). Any service or action not explicitly listed with approved CRUD actions is rejected.
* **AWS CLI performs all real-world operations.** Subprocess calls use tokenized argument arrays with `shell=False`—eliminating command injection vulnerabilities. All calls explicitly propagate `--profile` and `--region` flags alongside sanitized environment variables.
* **Backend Approval Re-Validation:** Destructive plans require explicit `CONFIRM DELETE` tokens checked directly in `orchestrator.execute_approved_plan()`, preventing UI bypasses.
* **AWS is the source of truth.** The agent verifies resource creation through targeted, service-specific AWS API calls (`describe-*`, `head-*`), never blindly trusting return codes or falling back to arbitrary types.
* **Controlled Rollback:** Undoes created infrastructure in reverse dependency order, strictly scoped to resources marked `ResourceOwnership.CREATED_BY_THIS_PLAN`. Never touches existing or reused resources.

---

## 🚀 Key Features & Hardening Enhancements

* 💬 **Natural Language Understanding with Strict Guardrails:** Translates intent into concrete AWS topologies with safety defaults. Prompt injection bypass attempts are filtered out at the parser layer.
* 🛡️ **Deterministic Action & Risk Classification:** Never trusts the LLM's self-reported operation category. The `classify_aws_action` engine deterministically categorizes actions based on AWS service and operation patterns, preventing category downgrades.
* 🧭 **Real Resource Reference & Context System (`ResourceContext`):** Replaces fragile string matching with a structured reference registry (`vpc.main`, `subnet.public`, `security_group.web`). Resolves placeholders recursively across nested dicts, lists, and strings; blocks execution if any reference cannot be resolved.
* 📊 **Directed Acyclic Dependency Graph (`DependencyGraph`):** Enforces topological execution order with 3-color DFS cycle detection (`CyclicDependencyError`), missing dependency detection (`MissingDependencyError`), and transitive dependent skipping on mid-flight step failures.
* 📦 **Deterministic Service Command Builders:** Dedicated builder functions in `services/ec2.py`, `services/vpc.py`, and `services/s3.py` guarantee consistent flag conventions (e.g. S3 LocationConstraint handling, tag specifications).
* 💿 **Deterministic Official AMI Discovery (`AMIDiscovery`):** Discovers official Amazon Linux 2023 AMIs using live `describe-images` queries backed by a verified regional fallback catalog. Never invents an unverified AMI ID.
* 🔒 **Structured Safety Policy Engine (`SafetyPolicyEngine`):**
  * Parses IAM JSON policy documents to block wildcard actions (`Action: "*"`) and `AdministratorAccess`.
  * Inspects Security Group ingress rules to block public all-port/all-protocol access (`0.0.0.0/0` on port 0 or protocol -1). Warns on public SSH (22) and RDP (3389).
  * Enforces `MAX_COMMANDS_PER_PLAN` limits.
* 🚦 **Authoritative Approval Engine (`ApprovalManager`):**
  * `AUTO`: Read-only operations (`describe-*`, `list-*`) run automatically.
  * `STANDARD`: Infrastructure write operations (`create-*`, `run-instances`) require interactive UI approval.
  * `EXPLICIT_CONFIRMATION`: Destructive operations (`delete-*`, `terminate-*`) require typed `CONFIRM DELETE`.
* 🔄 **Reverse Topological Rollback Engine (`RollbackEngine`):** Undoes created infrastructure in reverse dependency order, strictly scoped to resources marked `ResourceOwnership.CREATED_BY_THIS_PLAN`. Never deletes existing or reused resources.
* 🔍 **Multi-Service Ground-Truth Verification (`ResourceVerifier`):** Verifies newly created resources against live AWS state (`EC2`, `S3`, `VPC`, `Subnet`, `Security Group`, `IGW`, `IAM`, `DynamoDB`). Unknown types return explicit `UNSUPPORTED_TYPE` without EC2 fallback.
* 👤 **100% Profile and Region Propagation:** User-selected AWS profile and region in Streamlit propagate consistently to STS identity checks, discovery, planning, CLI argument arrays, and environment variables.
* 📚 **Educational "Learning Mode":** Provides deep explanations of AWS architecture, CLI flag breakdowns, security considerations, cost caveats, and related interview questions.
* 🔒 **Zero Hardcoded Credentials & Secret Redaction:** Automatically masks AWS access keys (`AKIA...`), session tokens, passwords, and account IDs in logs, CLI outputs, and persistent history.

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
│DependencyGraph│  │Policy Engine │   │    Approval Manager    │
│(Topological  │   │(IAM Inspect, │   │ (Auto / Interactive /  │
│3-Color DFS)  │   │Port Checks)  │   │ Explicit Typed Confirm)│
└──────┬───────┘   └──────┬───────┘   └───────────┬────────────┘
       │                  │                       │
       └──────────────────┼───────────────────────┘
                          │ Approved Plan
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      AWS CLI Executor                       │
│    (subprocess.run, shell=False, --profile, --region, env)  │
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
 │  6. IAM Policy Document Analysis  -> Wildcard & Admin blocks │
 │  7. Authoritative Approval Engine -> Typed CONFIRM DELETE    │
 └──────────────────────────────────────────────────────────────┘
```

1. **No `shell=True` Anywhere:** All execution uses native argument token arrays (`["aws", "ec2", "..."]`) preventing shell interpolation and command chaining.
2. **Strict Command Allowlisting:** Any command starting outside `ALLOWED_SERVICES` or containing unapproved actions is blocked before reaching the OS.
3. **Automated Secret Redaction:** AWS Access Keys (`AKIA...`), secret tokens, passwords, and account IDs are masked in stdout, stderr, logs, and persistent history.
4. **Structured IAM Policy Inspection:** Intercepts policies with `Action: "*"` and `Resource: "*"` or `AdministratorAccess` attachments before any CLI invocation.
5. **Security Group Port Protection:** Completely blocks ingress opening all ports/protocols to `0.0.0.0/0`. Highlights warnings for sensitive administrative ports (22, 3389).

---

## 🚦 Approval Decision Matrix

| Operation Category | Trigger Conditions | Approval Requirement | UI Behavior |
|---|---|---|---|
| **READ_ONLY** | `describe-*`, `list-*`, `get-*`, `head-*` | **Auto-Approved** | Executes immediately; results displayed |
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

# Optional: Enable live AWS integration tests
AWS_INTEGRATION_TESTS=false
```

### 4. Launch the Application
```bash
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🧪 Testing

The repository includes an extensive automated test suite of **116 unit and end-to-end scenario tests** (plus 3 gated live AWS integration tests). Tests mock all external AWS CLI and LLM interactions, allowing 100% offline execution without AWS credentials or charges:

```bash
# Run all unit and scenario tests
python -m pytest tests/ -v
```

### Test Suite Breakdown
* `tests/test_compiler.py`: Validates deterministic compilation from desired state across S3 (us-east-1 vs non-us-east-1 LocationConstraint), EC2, custom VPC chains, IAM roles, and DynamoDB tables; verifies `UnsupportedResourceTypeError` on invalid resource types.
* `tests/test_cli_executor.py`: Validates tokenized subprocess calls (`shell=False`), allowlist rejection for unregistered services (`route53`, `fake_svc`), unapproved actions, JSON parameter serialization, explicit profile and region flag/env propagation, unresolved placeholder blocking, and secret redaction.
* `tests/test_dependency_graph.py`: Validates topological sorting, 3-color DFS cycle detection, missing dependency detection, and transitive dependent skipping.
* `tests/test_resource_context.py`: Validates recursive placeholder resolution across nested dictionaries, lists, and strings, unresolved placeholder detection, and ownership tracking.
* `tests/test_rollback.py`: Validates reverse topological rollback ordering, mid-flight failure rollback generation, safe unresolved placeholder skipping, and strict scoping to `CREATED_BY_THIS_PLAN` resources.
* `tests/test_ami_discovery.py`: Validates live `describe-images` AMI resolution and verified regional fallback catalogs.
* `tests/test_security.py`: Validates IAM policy JSON wildcard inspection, port restriction blocking, `MAX_COMMANDS_PER_PLAN` limits, and approval requirements.
* `tests/test_validator.py`: Validates deterministic action categorization, category overrides, command injection blocking, and semantic parameter validation.
* `tests/test_parser.py`: Validates prompt injection defenses, input sanitization, length boundaries, and region detection.
* `tests/test_services.py`: Validates AWS service registry metadata and resource type definitions.
* `tests/test_e2e_scenario.py`: Validates complete lifecycle for Scenarios A through K (S3, EC2 in default VPC, full custom VPC stack, read-only discovery, destructive deletion, blocked dangerous requests, partial failure mid-flight skipping, prompt injection defense, backend confirmation token re-validation, unsupported resource type handling, and mid-flight auto-rollback).
* `tests/test_integration_aws.py`: Optional live AWS integration testing (gated behind `AWS_INTEGRATION_TESTS=true`).

---

## 📂 Project Structure

```
aws-agent/
├── app.py                      # Streamlit UI & Interactive Approval State
├── requirements.txt            # Python Dependencies
├── .env.example                # Sample Environment Template
├── .gitignore                  # Git Ignore Policy (Protects credentials/logs)
├── README.md                   # Production Documentation
│
├── config/
│   ├── __init__.py
│   └── settings.py             # Pydantic Settings & Environment Loading
│
├── agent/
│   ├── __init__.py
│   ├── models.py               # Pydantic Contracts (Plan, Command, Result, LogicalResource, DesiredState)
│   ├── compiler.py             # Deterministic Plan Compiler (Desired State -> Validated Commands)
│   ├── resource_context.py     # Logical Resource Reference & Recursive Placeholder Engine
│   ├── dependency_graph.py     # Directed Acyclic Graph & Topological Execution Sorter
│   ├── rollback.py             # Reverse Topological Rollback Engine
│   ├── llm_client.py           # Multi-Provider LLM Abstraction (Gemini, OpenAI, Claude, Ollama)
│   ├── prompts.py              # Prompt Templates & Guardrails
│   ├── parser.py               # Prompt Injection Detection & Input Sanitization
│   ├── planner.py              # Plan Generation & Desired-State Compilation Orchestrator
│   ├── orchestrator.py         # End-to-End Request Lifecycle Coordinator & State Machine
│   └── explainer.py            # Post-Execution Technical & Educational Generator
│
├── aws/
│   ├── __init__.py
│   ├── cli_executor.py         # Subprocess Execution Layer (shell=False, Timeouts, Redaction)
│   ├── cli_validator.py        # Static Parameter & Action Allowlist Validator
│   ├── ami_discovery.py        # Official Amazon Linux 2023 AMI Discovery
│   ├── identity.py             # AWS CLI Health Check & STS Identity Discovery
│   ├── verification.py         # Post-Provisioning Live State Verifier
│   └── resource_discovery.py   # Pre-flight Infrastructure Discovery (VPCs, SGs, Subnets)
│
├── services/
│   ├── __init__.py
│   ├── registry.py             # Pluggable AWS Service Registry
│   ├── ec2.py                  # EC2 Instance & KeyPair Service Handler & Builders
│   ├── s3.py                   # S3 Bucket Service Handler & Builders
│   ├── vpc.py                  # VPC, Subnet, IGW, RouteTable, SG Service Handler & Builders
│   ├── iam.py                  # IAM Role & Policy Service Handler
│   ├── lambda_service.py       # AWS Lambda Function Service Handler
│   ├── dynamodb.py             # DynamoDB Table Service Handler
│   ├── rds.py                  # RDS Database Service Handler
│   └── ecs.py                  # ECS Cluster & Task Definition Handler
│
├── security/
│   ├── __init__.py
│   ├── policy.py               # Safety Policy Rules & Risk Classifier (IAM & Port Inspections)
│   ├── sanitizer.py            # Secret Redactor (AKIA, Tokens, Passwords)
│   └── approvals.py            # Approval Decision Matrix (Auto / Standard / Explicit Confirmation)
│
├── history/
│   ├── __init__.py
│   └── execution_store.py      # Auditable JSON Execution History Store
│
└── tests/
    ├── __init__.py
    ├── test_compiler.py
    ├── test_cli_executor.py
    ├── test_dependency_graph.py
    ├── test_resource_context.py
    ├── test_rollback.py
    ├── test_ami_discovery.py
    ├── test_security.py
    ├── test_validator.py
    ├── test_parser.py
    ├── test_services.py
    ├── test_planner.py
    ├── test_e2e_scenario.py
    └── test_integration_aws.py
```

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