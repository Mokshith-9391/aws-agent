"""HTTP contract for a custom Amazon Bedrock AgentCore Runtime container.

AgentCore calls POST /invocations and GET /ping. The adapter deliberately
accepts only a request, region, and dry-run flag; it never accepts an AWS
profile or credentials from the separately deployed frontend.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent.orchestrator import AgentOrchestrator
from config.settings import reload_settings


class Invocation(BaseModel):
    prompt: str = Field(min_length=1, max_length=5000)
    region: Optional[str] = None
    dry_run: bool = True
    learning_mode: bool = False


@lru_cache
def orchestrator() -> AgentOrchestrator:
    # Runtime settings are process-local and do not rely on a developer profile.
    os.environ["AGENTCORE_RUNTIME"] = "true"
    settings = reload_settings()
    agent = AgentOrchestrator(settings=settings)
    ok, message = agent.initialize()
    if not ok:
        raise RuntimeError(message)
    return agent


app = FastAPI(title="AWS Provisioning AgentCore Runtime", docs_url=None, redoc_url=None)


@app.get("/ping")
def ping() -> dict[str, str]:
    return {"status": "Healthy"}


@app.post("/invocations")
def invoke(request: Invocation) -> dict:
    try:
        agent = orchestrator()
        if not request.dry_run and not agent._settings.AGENTCORE_EXECUTION_ENABLED:
            raise HTTPException(
                status_code=403,
                detail="Live execution is disabled in this AgentCore runtime. Submit a dry-run plan for approval.",
            )
        response = agent.process_request(
            user_request=request.prompt,
            region=request.region or agent._settings.AWS_REGION,
            profile="",  # credentials come only from the AgentCore execution role
            dry_run=request.dry_run,
            learning_mode=request.learning_mode,
            aws_account_id="AgentCore execution role",
        )
        return response.model_dump(mode="json")
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Agent initialization failed") from exc
