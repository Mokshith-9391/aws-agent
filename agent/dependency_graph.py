"""
Dependency Graph and Topological Sorting for Provisioning Commands.

Constructs a directed acyclic graph (DAG) of commands based on explicit
depends_on declarations. Validates for missing dependencies, detects cycles,
computes topological execution order, and identifies dependent subgraphs for
skipping on failure.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import Optional

from agent.models import CLICommand

logger = logging.getLogger(__name__)


class CyclicDependencyError(Exception):
    """Raised when a circular dependency is detected in the plan commands."""
    def __init__(self, cycle: list[str]) -> None:
        self.cycle = cycle
        cycle_str = " -> ".join(cycle)
        super().__init__(f"Circular dependency detected in plan: {cycle_str}")


class MissingDependencyError(Exception):
    """Raised when a command references a depends_on ID that does not exist in the plan."""
    def __init__(self, command_id: str, missing_id: str) -> None:
        self.command_id = command_id
        self.missing_id = missing_id
        super().__init__(
            f"Command '{command_id}' depends on non-existent command ID '{missing_id}'"
        )


class DependencyGraph:
    """Directed Acyclic Graph (DAG) for managing command execution order."""

    def __init__(self, commands: Optional[list[CLICommand]] = None) -> None:
        self._commands: dict[str, CLICommand] = {}
        # Forward edges: A depends on B means edge B -> A (B must run before A)
        self._downstream: dict[str, set[str]] = defaultdict(set)
        # Upstream edges: A depends on B means A has upstream B
        self._upstream: dict[str, set[str]] = defaultdict(set)

        if commands:
            for cmd in commands:
                self.add_command(cmd)

    def add_command(self, cmd: CLICommand) -> None:
        """Add a command node and its dependency edges to the graph."""
        self._commands[cmd.command_id] = cmd
        # Ensure sets exist
        _ = self._downstream[cmd.command_id]
        _ = self._upstream[cmd.command_id]

        for dep_id in cmd.depends_on:
            # cmd depends on dep_id -> dep_id runs before cmd
            self._downstream[dep_id].add(cmd.command_id)
            self._upstream[cmd.command_id].add(dep_id)

    def validate(self) -> None:
        """Validate the graph: check for missing dependencies and cycles.

        Raises:
            MissingDependencyError: If a dependency ID does not exist.
            CyclicDependencyError: If a cycle exists.
        """
        # 1. Check for missing dependencies
        for cmd_id, cmd in self._commands.items():
            for dep_id in cmd.depends_on:
                if dep_id not in self._commands:
                    raise MissingDependencyError(cmd_id, dep_id)

        # 2. Cycle detection using 3-color DFS
        # 0 = unvisited, 1 = visiting (in current recursion stack), 2 = visited
        visited: dict[str, int] = {cid: 0 for cid in self._commands}
        path: list[str] = []

        def dfs(node: str) -> None:
            visited[node] = 1
            path.append(node)

            for neighbor in self._downstream.get(node, ()):
                state = visited.get(neighbor, 0)
                if state == 1:
                    # Found back edge -> cycle detected
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    raise CyclicDependencyError(cycle)
                elif state == 0:
                    dfs(neighbor)

            path.pop()
            visited[node] = 2

        for node in list(self._commands.keys()):
            if visited[node] == 0:
                dfs(node)

    def topological_sort(self) -> list[CLICommand]:
        """Compute the deterministic topological order for execution.

        Returns:
            Ordered list of CLICommand instances where every dependency precedes
            its dependents.

        Raises:
            MissingDependencyError: If an invalid dependency exists.
            CyclicDependencyError: If a cycle is detected.
        """
        self.validate()

        # In-degree represents how many upstream dependencies must run first
        in_degree = {
            cmd_id: len(self._upstream[cmd_id])
            for cmd_id in self._commands
        }

        # Queue nodes with in_degree 0 (no dependencies)
        queue = deque([cid for cid, deg in in_degree.items() if deg == 0])
        sorted_ids: list[str] = []

        while queue:
            current = queue.popleft()
            sorted_ids.append(current)

            for downstream_id in sorted(self._downstream[current]):
                in_degree[downstream_id] -= 1
                if in_degree[downstream_id] == 0:
                    queue.append(downstream_id)

        if len(sorted_ids) != len(self._commands):
            # Fallback cycle check
            remaining = [cid for cid in self._commands if cid not in sorted_ids]
            raise CyclicDependencyError(remaining)

        return [self._commands[cid] for cid in sorted_ids]

    def get_transitive_dependents(self, failed_command_id: str) -> set[str]:
        """Find all command IDs that directly or indirectly depend on a failed command.

        Used to intelligently skip commands when an upstream dependency fails.

        Args:
            failed_command_id: The ID of the command that failed.

        Returns:
            Set of all downstream command IDs that must be skipped.
        """
        dependents: set[str] = set()
        queue = deque([failed_command_id])

        while queue:
            curr = queue.popleft()
            for downstream in self._downstream.get(curr, ()):
                if downstream not in dependents:
                    dependents.add(downstream)
                    queue.append(downstream)

        return dependents
