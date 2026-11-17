"""DynamoDB-backed execution history for stateless AgentCore workers.

The table is intentionally provisioned outside this application. Expected key:
``PK`` (String, value ``EXECUTION#<id>``), with a ``timestamp`` String GSI
named by ``DYNAMODB_HISTORY_TIMESTAMP_INDEX`` when chronological queries are
needed. No table is created or modified by this module.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from agent.models import ExecutionHistoryEntry
from config.settings import Settings, get_settings


class DynamoDBExecutionStore:
    def __init__(self, settings: Optional[Settings] = None, table=None) -> None:
        self.settings = settings or get_settings()
        if not self.settings.DYNAMODB_HISTORY_TABLE:
            raise ValueError("DYNAMODB_HISTORY_TABLE is required when HISTORY_BACKEND=dynamodb")
        if table is None:
            import boto3
            table = boto3.resource("dynamodb", region_name=self.settings.AWS_REGION).Table(
                self.settings.DYNAMODB_HISTORY_TABLE
            )
        self.table = table
        self._patterns = [re.compile(p) for p in self.settings.SECRET_PATTERNS]

    def _redact(self, entry: ExecutionHistoryEntry) -> ExecutionHistoryEntry:
        copy = entry.model_copy(deep=True)
        if copy.execution_result:
            for result in copy.execution_result.command_results:
                for field in ("stdout", "stderr"):
                    value = getattr(result, field, "") or ""
                    for pattern in self._patterns:
                        value = pattern.sub("[REDACTED]", value)
                    setattr(result, field, value)
        return copy

    def save_entry(self, entry: ExecutionHistoryEntry) -> None:
        redacted = self._redact(entry)
        self.table.put_item(Item={
            "PK": f"EXECUTION#{entry.execution_id}",
            "execution_id": entry.execution_id,
            "timestamp": entry.timestamp.isoformat(),
            "payload": redacted.model_dump_json(),
        }, ConditionExpression="attribute_not_exists(PK)")

    def get_entry(self, execution_id: str) -> Optional[ExecutionHistoryEntry]:
        item = self.table.get_item(Key={"PK": f"EXECUTION#{execution_id}"}).get("Item")
        return ExecutionHistoryEntry.model_validate_json(item["payload"]) if item else None

    def list_entries(self, limit: int = 50) -> list[ExecutionHistoryEntry]:
        # A dedicated index is optional but strongly recommended. The fallback
        # exists only for small development tables; production must configure it.
        index = getattr(self.settings, "DYNAMODB_HISTORY_TIMESTAMP_INDEX", None)
        kwargs = {"Limit": max(1, limit), "ScanIndexForward": False}
        if index:
            kwargs["IndexName"] = index
            response = self.table.scan(**kwargs)
        else:
            response = self.table.scan(Limit=max(1, limit))
        entries = [ExecutionHistoryEntry.model_validate_json(i["payload"]) for i in response.get("Items", [])]
        return sorted(entries, key=lambda entry: entry.timestamp, reverse=True)[:limit]
