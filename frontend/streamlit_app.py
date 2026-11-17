"""Separate Streamlit client for invoking the AgentCore Runtime.

This process holds no AWS infrastructure credentials. Its IAM principal needs
only bedrock-agentcore:InvokeAgentRuntime (and ForUser if user identity is used).
"""
import json
import os
import streamlit as st

st.set_page_config(page_title="AWS Provisioning Agent")
st.title("AWS Provisioning Agent")
runtime_arn = os.environ.get("AGENTCORE_RUNTIME_ARN")
if not runtime_arn:
    st.error("AGENTCORE_RUNTIME_ARN is not configured for this frontend.")
    st.stop()

prompt = st.chat_input("Describe the AWS infrastructure you need")
if prompt:
    import boto3
    with st.spinner("Planning safely in AgentCore..."):
        response = boto3.client("bedrock-agentcore", region_name=os.environ.get("AWS_REGION")).invoke_agent_runtime(
            agentRuntimeArn=runtime_arn, runtimeSessionId=st.session_state.get("runtime_session_id", "streamlit-session"),
            payload=json.dumps({"prompt": prompt, "dry_run": True}).encode(),
        )
        st.json(json.loads(response["response"].read()))
