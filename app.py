"""
AWS Provisioning Agent - Streamlit Application.

Professional web interface for the AI-powered AWS resource provisioning agent.
Provides natural-language input, plan visualization, approval workflows,
execution monitoring, and detailed explanations.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import streamlit as st

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.models import (
    AgentResponse,
    ApprovalStatus,
    ExecutionStatus,
    OperationCategory,
    ProvisioningPlan,
    RiskLevel,
)
from agent.orchestrator import AgentOrchestrator
from aws.identity import AWSIdentityManager
from config.settings import Settings, ExecutionMode, get_settings, reload_settings

# ──────────────────────────────────────────────
# Logging Configuration
# ──────────────────────────────────────────────

def setup_logging():
    """Configure structured logging for the application."""
    settings = get_settings()
    log_dir = settings.LOG_DIR
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"agent_{datetime.now().strftime('%Y%m%d')}.log")

    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


setup_logging()
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Page Configuration
# ──────────────────────────────────────────────

st.set_page_config(
    page_title="AWS Provisioning Agent",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# Custom CSS
# ──────────────────────────────────────────────

st.markdown("""
<style>
    /* Main styling */
    .stApp {
        max-width: 100%;
    }

    /* Status indicators */
    .status-connected {
        color: #28a745;
        font-weight: bold;
    }
    .status-disconnected {
        color: #dc3545;
        font-weight: bold;
    }
    .status-warning {
        color: #ffc107;
        font-weight: bold;
    }

    /* Risk level badges */
    .risk-low { color: #28a745; }
    .risk-medium { color: #ffc107; }
    .risk-high { color: #fd7e14; }
    .risk-critical { color: #dc3545; }

    /* Plan card styling */
    .plan-card {
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 16px;
        margin: 8px 0;
        background-color: #f8f9fa;
    }

    /* Hide streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}

    /* Chat messages */
    .stChatMessage {
        border-radius: 12px;
    }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Session State Initialization
# ──────────────────────────────────────────────

def init_session_state():
    """Initialize Streamlit session state variables."""
    defaults = {
        "messages": [],
        "orchestrator": None,
        "aws_identity": None,
        "aws_profile": "default",
        "aws_region": "ap-south-1",
        "dry_run": True,
        "learning_mode": False,
        "initialized": False,
        "pending_plan": None,
        "pending_approval_type": None,
        "execution_history": [],
        "confirm_text": "",
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


init_session_state()


# ──────────────────────────────────────────────
# AWS Identity & Health Check
# ──────────────────────────────────────────────

def check_aws_health():
    """Perform AWS health check and update session state."""
    identity_manager = AWSIdentityManager()
    identity = identity_manager.health_check(
        profile=st.session_state.aws_profile,
        region=st.session_state.aws_region,
    )
    st.session_state.aws_identity = identity
    return identity


def initialize_agent():
    """Initialize the agent orchestrator."""
    try:
        settings = reload_settings()
        settings.AWS_PROFILE = st.session_state.aws_profile
        settings.AWS_REGION = st.session_state.aws_region

        orchestrator = AgentOrchestrator(settings)
        success, message = orchestrator.initialize()

        if success:
            st.session_state.orchestrator = orchestrator
            st.session_state.initialized = True
            logger.info("Agent initialized successfully")
            return True, message
        else:
            logger.error(f"Agent initialization failed: {message}")
            return False, message

    except Exception as e:
        logger.error(f"Agent initialization error: {e}", exc_info=True)
        return False, str(e)


# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────

def render_sidebar():
    """Render the sidebar with AWS connection and settings."""
    with st.sidebar:
        st.title("☁️ AWS Agent")
        st.caption("AI-Powered AWS Provisioning")

        st.divider()

        # ── AWS Connection Settings ─────────────────────
        st.subheader("🔗 AWS Connection")

        profile = st.text_input(
            "AWS Profile",
            value=st.session_state.aws_profile,
            key="sidebar_profile",
            help="AWS CLI profile to use",
        )
        if profile != st.session_state.aws_profile:
            st.session_state.aws_profile = profile
            st.session_state.aws_identity = None

        region = st.selectbox(
            "AWS Region",
            options=[
                "ap-south-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
                "ca-central-1", "sa-east-1",
            ],
            index=0,
            key="sidebar_region",
            help="Default AWS region for operations",
        )
        if region != st.session_state.aws_region:
            st.session_state.aws_region = region

        # Health check button
        if st.button("🔄 Check Connection", use_container_width=True):
            with st.spinner("Checking AWS connection..."):
                identity = check_aws_health()

        # Display connection status
        identity = st.session_state.aws_identity
        if identity:
            if identity.is_ready:
                st.success("Connected ✓")
                st.markdown(f"**Account:** `{identity.display_account_id}`")
                st.markdown(f"**Identity:** `{identity.arn.split('/')[-1] if identity.arn else 'N/A'}`")
                st.markdown(f"**Region:** `{identity.region}`")
                st.markdown(f"**CLI:** `{identity.cli_version}`")
            elif identity.cli_installed and not identity.credentials_valid:
                st.warning("CLI installed but credentials invalid")
                st.markdown(f"**CLI:** `{identity.cli_version}`")
            elif not identity.cli_installed:
                st.error("AWS CLI not installed")
        else:
            st.info("Click 'Check Connection' to verify AWS setup")

        st.divider()

        # ── Execution Settings ─────────────────────────
        st.subheader("⚙️ Settings")

        dry_run = st.toggle(
            "🔍 Dry Run Mode",
            value=st.session_state.dry_run,
            key="sidebar_dry_run",
            help="When enabled, commands are analyzed but NOT executed against AWS",
        )
        st.session_state.dry_run = dry_run

        if dry_run:
            st.info("**Dry Run ON** — No AWS changes will be made")
        else:
            st.warning("**LIVE MODE** — Commands WILL be executed against AWS")

        learning_mode = st.toggle(
            "📚 Learning Mode",
            value=st.session_state.learning_mode,
            key="sidebar_learning",
            help="Show educational explanations about AWS concepts",
        )
        st.session_state.learning_mode = learning_mode

        st.divider()

        # ── Agent Status ─────────────────────────────
        st.subheader("🤖 Agent Status")

        if st.session_state.initialized:
            st.success("Agent Ready ✓")
        else:
            if st.button("🚀 Initialize Agent", use_container_width=True):
                with st.spinner("Initializing agent..."):
                    success, msg = initialize_agent()
                    if success:
                        st.success("Agent initialized!")
                        st.rerun()
                    else:
                        st.error(f"Failed: {msg}")

        # Session resources
        if st.session_state.orchestrator:
            resources = st.session_state.orchestrator.get_session_resources()
            if resources:
                st.subheader("📦 Session Resources")
                for rtype, rid in resources.items():
                    st.markdown(f"- `{rtype}`: `{rid}`")

        st.divider()

        # ── Actions ──────────────────────────────────
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🗑️ Clear Chat", use_container_width=True):
                st.session_state.messages = []
                st.session_state.pending_plan = None
                st.session_state.pending_approval_type = None
                if st.session_state.orchestrator:
                    st.session_state.orchestrator.clear_session()
                st.rerun()
        with col2:
            if st.button("📋 History", use_container_width=True):
                st.session_state.show_history = not st.session_state.get("show_history", False)
                st.rerun()


# ──────────────────────────────────────────────
# Main Chat Area
# ──────────────────────────────────────────────

def render_chat():
    """Render the main chat interface."""
    # Header
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.title("☁️ AWS Provisioning Agent")
    with col2:
        mode = "🔍 DRY RUN" if st.session_state.dry_run else "⚡ LIVE"
        st.markdown(f"### {mode}")
    with col3:
        if st.session_state.aws_identity and st.session_state.aws_identity.is_ready:
            st.markdown(f"### 🟢 `{st.session_state.aws_region}`")
        else:
            st.markdown("### 🔴 Not Connected")

    st.caption("Describe what you want to provision or manage in AWS using natural language.")

    # Display chat history
    for message in st.session_state.messages:
        role = message["role"]
        content = message["content"]
        with st.chat_message(role, avatar="👤" if role == "user" else "☁️"):
            st.markdown(content, unsafe_allow_html=True)

            # Display plan details if present
            if "plan" in message and message["plan"]:
                render_plan_details(message["plan"])

            # Display execution result if present
            if "execution_result" in message and message["execution_result"]:
                render_execution_result(message["execution_result"])

            # Display educational content if present
            if "educational_content" in message and message["educational_content"]:
                with st.expander("📚 Learning Mode - Educational Content"):
                    st.markdown(message["educational_content"])

    # Pending approval handling
    if st.session_state.pending_plan:
        render_approval_controls()

    # Chat input
    if prompt := st.chat_input("Describe what you want AWS to provision...", key="chat_input"):
        handle_user_input(prompt)


def handle_user_input(user_input: str):
    """Process a user chat input."""
    # Add user message
    st.session_state.messages.append({
        "role": "user",
        "content": user_input,
    })

    # Check if this is a confirmation for explicit approval
    if st.session_state.pending_plan and st.session_state.pending_approval_type == "explicit_confirmation":
        if user_input.strip().upper() == "CONFIRM DELETE":
            execute_pending_plan()
            return
        else:
            st.session_state.messages.append({
                "role": "assistant",
                "content": "⚠️ Explicit confirmation required. Type **CONFIRM DELETE** to proceed, or click **Cancel** to abort.",
            })
            st.rerun()
            return

    # Auto-initialize if needed
    if not st.session_state.initialized:
        with st.spinner("Initializing agent..."):
            success, msg = initialize_agent()
            if not success:
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": f"❌ Agent initialization failed: {msg}\n\nPlease check your LLM API key in the `.env` file.",
                })
                st.rerun()
                return

    # Also auto-check AWS if needed
    if not st.session_state.aws_identity:
        with st.spinner("Checking AWS connection..."):
            check_aws_health()

    # Process through orchestrator
    orchestrator = st.session_state.orchestrator
    if not orchestrator:
        st.session_state.messages.append({
            "role": "assistant",
            "content": "❌ Agent not initialized. Please click 'Initialize Agent' in the sidebar.",
        })
        st.rerun()
        return

    with st.spinner("🤔 Analyzing your request..."):
        aws_id = st.session_state.aws_identity
        response = orchestrator.process_request(
            user_request=user_input,
            region=st.session_state.aws_region,
            profile=st.session_state.aws_profile,
            dry_run=st.session_state.dry_run,
            learning_mode=st.session_state.learning_mode,
            aws_account_id=aws_id.account_id if aws_id else "Unknown",
        )

    # Handle the response
    process_agent_response(response)
    st.rerun()


def process_agent_response(response: AgentResponse):
    """Process an agent response and update the UI state."""
    message_data = {
        "role": "assistant",
        "content": response.message,
    }

    # Attach plan if present
    if response.plan:
        message_data["plan"] = response.plan.model_dump()

    # Attach execution result if present
    if response.execution_result:
        message_data["execution_result"] = response.execution_result.model_dump()

    # Attach educational content
    if response.educational_content:
        message_data["educational_content"] = response.educational_content

    # Check if approval is needed
    if response.requires_approval and response.plan:
        st.session_state.pending_plan = response.plan
        # Authoritative approval decision directly from backend
        appr_type = getattr(response, "approval_type", None)
        if hasattr(appr_type, "value"):
            st.session_state.pending_approval_type = appr_type.value
        else:
            st.session_state.pending_approval_type = str(appr_type or "standard")
    else:
        st.session_state.pending_plan = None
        st.session_state.pending_approval_type = None

    st.session_state.messages.append(message_data)


def render_approval_controls():
    """Render approval controls for pending plans."""
    plan = st.session_state.pending_plan
    approval_type = st.session_state.pending_approval_type

    st.divider()

    # Display effective execution context immediately before approval
    st.info(
        f"🎯 **Target AWS Environment:** Profile: `{st.session_state.aws_profile}` | "
        f"Region: `{st.session_state.aws_region}`"
    )

    if approval_type == "explicit_confirmation":
        st.error("⚠️ **DESTRUCTIVE / HIGH-RISK OPERATION** — Explicit confirmation required")
        st.markdown("Type `CONFIRM DELETE` in the chat input below to proceed, or click **Cancel**.")

        if st.button("🚫 Cancel", type="primary", use_container_width=True):
            cancel_pending_plan()

    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("✅ Execute", type="primary", use_container_width=True):
                execute_pending_plan()
        with col2:
            if st.button("🚫 Cancel", use_container_width=True):
                cancel_pending_plan()
        with col3:
            if st.button("🔍 Dry Run Instead", use_container_width=True):
                dry_run_pending_plan()


def execute_pending_plan():
    """Execute the pending approved plan with explicit profile and region."""
    plan = st.session_state.pending_plan
    if not plan:
        return

    orchestrator = st.session_state.orchestrator
    if not orchestrator:
        return

    # Convert dict back to ProvisioningPlan if needed
    if isinstance(plan, dict):
        plan = ProvisioningPlan.model_validate(plan)

    st.session_state.messages.append({
        "role": "assistant",
        "content": f"⚡ **Executing approved plan using profile `{st.session_state.aws_profile}` and region `{st.session_state.aws_region}`...**",
    })

    with st.spinner("🚀 Executing AWS commands..."):
        response = orchestrator.execute_approved_plan(
            plan=plan,
            region=st.session_state.aws_region,
            profile=st.session_state.aws_profile,
            learning_mode=st.session_state.learning_mode,
        )

    st.session_state.pending_plan = None
    st.session_state.pending_approval_type = None
    process_agent_response(response)
    st.rerun()


def cancel_pending_plan():
    """Cancel the pending plan."""
    st.session_state.pending_plan = None
    st.session_state.pending_approval_type = None
    st.session_state.messages.append({
        "role": "assistant",
        "content": "🚫 Operation cancelled by user.",
    })
    st.rerun()


def dry_run_pending_plan():
    """Switch to dry run for the pending plan."""
    st.session_state.pending_plan = None
    st.session_state.pending_approval_type = None
    st.session_state.dry_run = True
    st.session_state.messages.append({
        "role": "assistant",
        "content": "🔍 Switched to Dry Run mode. Re-submit your request to see the dry-run analysis.",
    })
    st.rerun()


# ──────────────────────────────────────────────
# Plan & Result Rendering
# ──────────────────────────────────────────────

def render_plan_details(plan_data: dict):
    """Render expandable plan details."""
    with st.expander("📋 Provisioning Plan Details", expanded=False):
        col1, col2, col3 = st.columns(3)

        with col1:
            risk = plan_data.get("risk_level", "MEDIUM")
            risk_colors = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
            st.metric("Risk Level", f"{risk_colors.get(risk, '⚪')} {risk}")

        with col2:
            op_cat = plan_data.get("operation_category", "WRITE")
            cat_icons = {"READ_ONLY": "📖", "WRITE": "✏️", "DESTRUCTIVE": "💥"}
            st.metric("Operation", f"{cat_icons.get(op_cat, '❓')} {op_cat}")

        with col3:
            n_cmds = len(plan_data.get("commands", []))
            st.metric("Commands", n_cmds)

        # Resources
        resources = plan_data.get("resources", [])
        if resources:
            st.markdown("**Resources:**")
            for r in resources:
                name = r.get("resource_name", "auto-named")
                st.markdown(f"- `{r.get('service', '').upper()}` / `{r.get('resource_type', '')}`: {name}")

        # Commands
        commands = plan_data.get("commands", [])
        if commands:
            st.markdown("**Commands:**")
            for i, cmd in enumerate(commands, 1):
                desc = cmd.get("description", "")
                svc = cmd.get("service", "")
                action = cmd.get("action", "")
                params = cmd.get("parameters", {})

                # Reconstruct command display
                parts = ["aws", svc, action]
                region = cmd.get("region", "")
                if region:
                    parts.extend(["--region", region])
                for k, v in params.items():
                    if isinstance(v, bool):
                        if v:
                            parts.append(f"--{k}")
                    elif isinstance(v, dict):
                        parts.extend([f"--{k}", json.dumps(v)])
                    elif isinstance(v, list):
                        parts.append(f"--{k}")
                        parts.extend([str(item) for item in v])
                    else:
                        parts.extend([f"--{k}", str(v)])
                parts.extend(["--output", "json"])

                st.markdown(f"**{i}. {desc}**")
                st.code(" ".join(parts), language="bash")

        # Assumptions
        assumptions = plan_data.get("assumptions", [])
        if assumptions:
            st.markdown("**Assumptions:**")
            for a in assumptions:
                st.markdown(f"- {a}")

        # Cost warnings
        cost_warnings = plan_data.get("cost_warnings", [])
        if cost_warnings:
            st.markdown("**💰 Cost Warnings:**")
            for w in cost_warnings:
                st.warning(w)


def render_execution_result(result_data: dict):
    """Render execution result details."""
    status = result_data.get("status", "UNKNOWN")
    is_dry = result_data.get("dry_run", False)

    if is_dry:
        return  # Dry run details are in the message itself

    status_config = {
        "SUCCESS": ("✅", "success"),
        "PARTIAL_SUCCESS": ("⚠️", "warning"),
        "FAILED": ("❌", "error"),
        "CANCELLED": ("🚫", "info"),
        "DRY_RUN": ("🔍", "info"),
    }
    emoji, alert_type = status_config.get(status, ("ℹ️", "info"))

    with st.expander(f"{emoji} Execution Results - {status}", expanded=True):
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Commands", result_data.get("total_commands", 0))
        with col2:
            st.metric("Successful", result_data.get("successful_commands", 0))
        with col3:
            st.metric("Failed", result_data.get("failed_commands", 0))
        with col4:
            duration = result_data.get("duration_seconds", 0)
            st.metric("Duration", f"{duration:.1f}s")

        # Created resources
        created = result_data.get("created_resources", {})
        if created:
            st.markdown("**✅ Created Resources:**")
            for rtype, rid in created.items():
                st.success(f"`{rtype}`: `{rid}`")

        # Failed resources
        failed = result_data.get("failed_resources", [])
        if failed:
            st.markdown("**❌ Failed Resources:**")
            for f_res in failed:
                st.error(f_res)

        # Command results
        cmd_results = result_data.get("command_results", [])
        if cmd_results:
            st.markdown("**Command Results:**")
            for cr in cmd_results:
                icon = "✅" if cr.get("success") else "❌"
                cmd_display = cr.get("command_display", "Unknown command")
                st.markdown(f"{icon} `{cmd_display}`")

                if not cr.get("success") and cr.get("error_message"):
                    st.error(f"Error: {cr['error_message']}")

                if cr.get("resource_ids"):
                    for k, v in cr["resource_ids"].items():
                        st.info(f"→ {k}: `{v}`")

        # Verification results
        ver_results = result_data.get("verification_results", [])
        if ver_results:
            st.markdown("**Verification:**")
            for vr in ver_results:
                icon = "✅" if vr.get("verified") else "❌"
                st.markdown(
                    f"{icon} {vr.get('resource_type', '')}: "
                    f"`{vr.get('resource_id', '')}` - {vr.get('message', '')}"
                )


# ──────────────────────────────────────────────
# Execution History Panel
# ──────────────────────────────────────────────

def render_history():
    """Render the execution history panel."""
    st.subheader("📋 Execution History")

    orchestrator = st.session_state.orchestrator
    if not orchestrator:
        st.info("Agent not initialized. No history available.")
        return

    entries = orchestrator.get_execution_history(limit=20)
    if not entries:
        st.info("No execution history yet.")
        return

    for entry in entries:
        status_icons = {
            ExecutionStatus.SUCCESS: "✅",
            ExecutionStatus.PARTIAL_SUCCESS: "⚠️",
            ExecutionStatus.FAILED: "❌",
            ExecutionStatus.DRY_RUN: "🔍",
            ExecutionStatus.CANCELLED: "🚫",
        }

        exec_status = entry.execution_result.status if entry.execution_result else ExecutionStatus.PENDING
        icon = status_icons.get(exec_status, "❓")

        ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        with st.expander(f"{icon} {entry.intent} — {ts}"):
            st.markdown(f"**Request:** {entry.user_request}")
            st.markdown(f"**Region:** `{entry.aws_region}`")
            st.markdown(f"**Status:** `{exec_status.value}`")
            st.markdown(f"**Execution ID:** `{entry.execution_id}`")

            if entry.execution_result:
                result = entry.execution_result
                if result.created_resources:
                    st.markdown("**Created Resources:**")
                    for k, v in result.created_resources.items():
                        st.markdown(f"- `{k}`: `{v}`")

            if entry.explanation:
                with st.expander("Full Explanation"):
                    st.markdown(entry.explanation)


# ──────────────────────────────────────────────
# Main Application
# ──────────────────────────────────────────────

def main():
    """Main application entry point."""
    # Render sidebar
    render_sidebar()

    # Check if history panel should be shown
    if st.session_state.get("show_history", False):
        tab1, tab2 = st.tabs(["💬 Chat", "📋 History"])
        with tab1:
            render_chat()
        with tab2:
            render_history()
    else:
        render_chat()


if __name__ == "__main__":
    main()
