"""
Execution history storage module for the AWS Provisioning Agent.

Provides persistent storage, querying, and retrieval of ExecutionHistoryEntry
records with secret redaction, history size limits, and robust error handling.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from agent.models import ExecutionHistoryEntry
from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)


class ExecutionStore:
    """Store and manage execution history entries on disk.

    History entries are serialized as JSON files identified by their execution_id.
    This store enforces retention limits defined by MAX_HISTORY_ENTRIES,
    redacts sensitive credentials/tokens prior to storage, and provides
    search and aggregation utilities.
    """

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize the ExecutionStore.

        Args:
            storage_dir: Directory path where history JSON files are stored.
                Defaults to 'history/data/'.
            settings: Application Settings instance. Defaults to singleton settings.
        """
        self.settings: Settings = settings or get_settings()
        self.storage_dir: Path = (
            Path(storage_dir) if storage_dir is not None else Path("history/data")
        )
        self._compiled_patterns: list[re.Pattern[str]] = self._compile_secret_patterns()
        self._ensure_storage_dir()

    def _compile_secret_patterns(self) -> list[re.Pattern[str]]:
        """Compile configured secret regex patterns for redaction.

        Returns:
            List of compiled regex patterns.
        """
        compiled: list[re.Pattern[str]] = []
        patterns = getattr(self.settings, "SECRET_PATTERNS", [])
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as e:
                logger.warning(
                    "Failed to compile secret redaction pattern",
                    extra={"pattern": pattern, "error": str(e)},
                )
        return compiled

    def _ensure_storage_dir(self) -> None:
        """Create the history storage directory if it does not exist."""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(
                "Failed to create history storage directory",
                extra={"storage_dir": str(self.storage_dir), "error": str(e)},
            )
            raise

    def _redact_text(self, text: str) -> str:
        """Redact sensitive patterns from text using configured regex patterns.

        Args:
            text: Input string to redact.

        Returns:
            Redacted string with sensitive values replaced by '[REDACTED]'.
        """
        if not text:
            return text

        redacted = text
        for pattern in self._compiled_patterns:
            try:
                redacted = pattern.sub("[REDACTED]", redacted)
            except Exception as e:
                logger.warning(
                    "Error during secret pattern substitution",
                    extra={"error": str(e)},
                )
        return redacted

    def _redact_entry(self, entry: ExecutionHistoryEntry) -> ExecutionHistoryEntry:
        """Create a copy of the entry with sensitive data redacted from command results.

        Redacts sensitive patterns from stdout and stderr across all CommandResult items.

        Args:
            entry: ExecutionHistoryEntry to redact.

        Returns:
            A new ExecutionHistoryEntry copy with redacted stdout and stderr.
        """
        entry_copy = entry.model_copy(deep=True)
        if entry_copy.execution_result and entry_copy.execution_result.command_results:
            for cmd_result in entry_copy.execution_result.command_results:
                if cmd_result.stdout:
                    cmd_result.stdout = self._redact_text(cmd_result.stdout)
                if cmd_result.stderr:
                    cmd_result.stderr = self._redact_text(cmd_result.stderr)
        return entry_copy

    def _get_file_path(self, execution_id: str) -> Path:
        """Resolve the JSON file path for a given execution ID.

        Args:
            execution_id: Execution identifier.

        Returns:
            Path object to the JSON file.
        """
        filename = f"{execution_id}.json" if not execution_id.endswith(".json") else execution_id
        return self.storage_dir / filename

    def _get_entry_timestamp(self, file_path: Path) -> datetime:
        """Extract timestamp from a history JSON file quickly, falling back to mtime.

        Args:
            file_path: Path to the JSON file.

        Returns:
            UTC datetime representing the entry or file timestamp.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                ts_str = data.get("timestamp")
                if ts_str:
                    dt = datetime.fromisoformat(ts_str)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
        except Exception:
            pass

        try:
            return datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return datetime.min.replace(tzinfo=timezone.utc)

    def _load_entry_from_file(self, file_path: Path) -> Optional[ExecutionHistoryEntry]:
        """Load and deserialize an ExecutionHistoryEntry from a JSON file.

        Args:
            file_path: Path to the JSON file.

        Returns:
            ExecutionHistoryEntry if valid, None otherwise.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
            return ExecutionHistoryEntry.model_validate_json(content)
        except OSError as e:
            logger.error(
                "Error reading history file",
                extra={"file_path": str(file_path), "error": str(e)},
            )
            return None
        except Exception as e:
            logger.error(
                "Error deserializing history entry from JSON",
                extra={"file_path": str(file_path), "error": str(e)},
            )
            return None

    def _prune_old_entries(self) -> None:
        """Enforce MAX_HISTORY_ENTRIES limit by deleting oldest entries."""
        max_entries = getattr(self.settings, "MAX_HISTORY_ENTRIES", 500)
        if max_entries <= 0:
            return

        json_files = list(self.storage_dir.glob("*.json"))
        if len(json_files) <= max_entries:
            return

        # Sort files ascending by timestamp (oldest first)
        dated_files = [
            (self._get_entry_timestamp(fp), fp)
            for fp in json_files
        ]
        dated_files.sort(key=lambda item: item[0])

        excess_count = len(dated_files) - max_entries
        for _, file_path in dated_files[:excess_count]:
            try:
                file_path.unlink(missing_ok=True)
                logger.info(
                    "Pruned old execution history entry",
                    extra={"file_path": str(file_path), "max_entries": max_entries},
                )
            except OSError as e:
                logger.warning(
                    "Failed to delete old history file during pruning",
                    extra={"file_path": str(file_path), "error": str(e)},
                )

    def save_entry(self, entry: ExecutionHistoryEntry) -> None:
        """Save an execution history entry to a JSON file.

        The file is named by entry.execution_id. Sensitive patterns in
        stdout and stderr of command results are redacted before saving.
        Enforces the MAX_HISTORY_ENTRIES retention limit.

        Args:
            entry: ExecutionHistoryEntry instance to persist.

        Raises:
            IOError: If file writing fails.
        """
        self._ensure_storage_dir()
        redacted_entry = self._redact_entry(entry)
        file_path = self._get_file_path(entry.execution_id)

        temp_file = file_path.with_suffix(f".tmp.{uuid.uuid4().hex[:8]}")
        try:
            json_content = redacted_entry.model_dump_json(indent=2)
            temp_file.write_text(json_content, encoding="utf-8")
            temp_file.replace(file_path)
            logger.info(
                "Successfully saved execution history entry",
                extra={
                    "execution_id": entry.execution_id,
                    "file_path": str(file_path),
                    "intent": entry.intent,
                },
            )
        except OSError as e:
            logger.error(
                "Failed to write execution history entry to disk",
                extra={
                    "execution_id": entry.execution_id,
                    "file_path": str(file_path),
                    "error": str(e),
                },
            )
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            raise IOError(
                f"Failed to save execution history entry '{entry.execution_id}': {e}"
            ) from e

        # Enforce history size limit
        try:
            self._prune_old_entries()
        except Exception as e:
            logger.warning(
                "Failed to prune old execution history entries",
                extra={"error": str(e)},
            )

    def get_entry(self, execution_id: str) -> Optional[ExecutionHistoryEntry]:
        """Load a specific execution history entry by execution ID.

        Args:
            execution_id: Unique execution identifier.

        Returns:
            ExecutionHistoryEntry if found and valid, None otherwise.
        """
        if not execution_id:
            return None

        file_path = self._get_file_path(execution_id)
        if not file_path.exists():
            logger.debug(
                "Execution history entry not found",
                extra={"execution_id": execution_id, "file_path": str(file_path)},
            )
            return None

        return self._load_entry_from_file(file_path)

    def list_entries(self, limit: int = 50) -> list[ExecutionHistoryEntry]:
        """List recent execution history entries sorted by timestamp descending.

        Args:
            limit: Maximum number of entries to return (default: 50).

        Returns:
            List of ExecutionHistoryEntry objects, newest first.
        """
        if limit == 0 or not self.storage_dir.exists():
            return []

        json_files = list(self.storage_dir.glob("*.json"))
        if not json_files:
            return []

        # Sort files descending by timestamp
        dated_files = [
            (self._get_entry_timestamp(fp), fp)
            for fp in json_files
        ]
        dated_files.sort(key=lambda item: item[0], reverse=True)

        entries: list[ExecutionHistoryEntry] = []
        for _, file_path in dated_files:
            entry = self._load_entry_from_file(file_path)
            if entry is not None:
                entries.append(entry)
                if limit > 0 and len(entries) >= limit:
                    break

        return entries

    def search_entries(self, query: str) -> list[ExecutionHistoryEntry]:
        """Search execution history entries matching a text query.

        Performs a case-insensitive search across user_request and intent fields.
        Returns matching entries sorted by timestamp descending.

        Args:
            query: Text query to search for.

        Returns:
            List of matching ExecutionHistoryEntry objects, newest first.
        """
        if not query or not query.strip():
            return []

        normalized_query = query.strip().lower()
        max_entries = getattr(self.settings, "MAX_HISTORY_ENTRIES", 500)
        all_entries = self.list_entries(limit=max_entries)

        matches: list[ExecutionHistoryEntry] = []
        for entry in all_entries:
            req = (entry.user_request or "").lower()
            intent = (entry.intent or "").lower()
            if normalized_query in req or normalized_query in intent:
                matches.append(entry)

        return matches

    def get_recent_resource_ids(self, limit: int = 50) -> dict[str, str]:
        """Aggregate created resource IDs from recent execution history entries.

        Inspects created_resources and command_results from recent entries.
        Newer resource IDs overwrite older ones in case of key collisions.

        Args:
            limit: Number of recent history entries to inspect (default: 50).

        Returns:
            Dictionary mapping resource types/identifiers to AWS resource IDs.
        """
        recent_entries = self.list_entries(limit=limit)
        aggregated: dict[str, str] = {}

        # Traverse oldest to newest so newer entries overwrite older ones
        for entry in reversed(recent_entries):
            if not entry.execution_result:
                continue

            if entry.execution_result.created_resources:
                for key, val in entry.execution_result.created_resources.items():
                    if val:
                        aggregated[str(key)] = str(val)

            if entry.execution_result.command_results:
                for cmd in entry.execution_result.command_results:
                    if cmd.resource_ids:
                        for key, val in cmd.resource_ids.items():
                            if val:
                                aggregated[str(key)] = str(val)

        logger.debug(
            "Aggregated recent resource IDs",
            extra={"resource_count": len(aggregated)},
        )
        return aggregated

    def clear_history(self) -> None:
        """Delete all execution history entries from disk.

        Removes all stored JSON files in the storage directory.

        Raises:
            IOError: If deleting one or more history files fails.
        """
        if not self.storage_dir.exists():
            return

        deleted_count = 0
        errors: list[str] = []

        files_to_delete = list(self.storage_dir.glob("*.json")) + list(
            self.storage_dir.glob("*.tmp*")
        )
        for file_path in files_to_delete:
            try:
                file_path.unlink()
                deleted_count += 1
            except OSError as e:
                errors.append(f"{file_path.name}: {e}")
                logger.error(
                    "Failed to delete history file",
                    extra={"file_path": str(file_path), "error": str(e)},
                )

        logger.info(
            "Cleared execution history",
            extra={"deleted_count": deleted_count, "errors_count": len(errors)},
        )

        if errors:
            raise IOError(f"Failed to delete history files: {', '.join(errors)}")
