import pytest
from agent.dependency_graph import (
    DependencyGraph,
    CyclicDependencyError,
    MissingDependencyError,
)
from agent.models import CLICommand, OperationCategory


class TestDependencyGraph:
    def test_topological_sort_linear(self):
        cmd1 = CLICommand(
            command_id="cmd-vpc",
            service="ec2",
            action="create-vpc",
            parameters={},
            description="Create VPC",
            operation_category=OperationCategory.WRITE,
        )
        cmd2 = CLICommand(
            command_id="cmd-subnet",
            service="ec2",
            action="create-subnet",
            parameters={},
            description="Create Subnet",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-vpc"],
        )
        cmd3 = CLICommand(
            command_id="cmd-ec2",
            service="ec2",
            action="run-instances",
            parameters={},
            description="Run EC2",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-subnet"],
        )

        # Pass in reverse order
        graph = DependencyGraph([cmd3, cmd2, cmd1])
        ordered = graph.topological_sort()

        ordered_ids = [c.command_id for c in ordered]
        assert ordered_ids == ["cmd-vpc", "cmd-subnet", "cmd-ec2"]

    def test_topological_sort_branching(self):
        cmd_vpc = CLICommand(
            command_id="cmd-vpc",
            service="ec2",
            action="create-vpc",
            parameters={},
            description="VPC",
            operation_category=OperationCategory.WRITE,
        )
        cmd_subnet = CLICommand(
            command_id="cmd-subnet",
            service="ec2",
            action="create-subnet",
            parameters={},
            description="Subnet",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-vpc"],
        )
        cmd_sg = CLICommand(
            command_id="cmd-sg",
            service="ec2",
            action="create-security-group",
            parameters={},
            description="SG",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-vpc"],
        )
        cmd_ec2 = CLICommand(
            command_id="cmd-ec2",
            service="ec2",
            action="run-instances",
            parameters={},
            description="Instance",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-subnet", "cmd-sg"],
        )

        graph = DependencyGraph([cmd_ec2, cmd_sg, cmd_subnet, cmd_vpc])
        ordered = graph.topological_sort()
        ordered_ids = [c.command_id for c in ordered]

        assert ordered_ids.index("cmd-vpc") < ordered_ids.index("cmd-subnet")
        assert ordered_ids.index("cmd-vpc") < ordered_ids.index("cmd-sg")
        assert ordered_ids.index("cmd-subnet") < ordered_ids.index("cmd-ec2")
        assert ordered_ids.index("cmd-sg") < ordered_ids.index("cmd-ec2")

    def test_cyclic_dependency_detected(self):
        cmd1 = CLICommand(
            command_id="cmd-a",
            service="ec2",
            action="create-vpc",
            parameters={},
            description="A",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-b"],
        )
        cmd2 = CLICommand(
            command_id="cmd-b",
            service="ec2",
            action="create-subnet",
            parameters={},
            description="B",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-a"],
        )

        graph = DependencyGraph([cmd1, cmd2])
        with pytest.raises(CyclicDependencyError) as exc_info:
            graph.topological_sort()
        assert "Circular dependency" in str(exc_info.value)

    def test_missing_dependency_detected(self):
        cmd1 = CLICommand(
            command_id="cmd-a",
            service="ec2",
            action="run-instances",
            parameters={},
            description="A",
            operation_category=OperationCategory.WRITE,
            depends_on=["cmd-nonexistent"],
        )

        graph = DependencyGraph([cmd1])
        with pytest.raises(MissingDependencyError) as exc_info:
            graph.topological_sort()
        assert "cmd-nonexistent" in str(exc_info.value)

    def test_get_transitive_dependents(self):
        cmd1 = CLICommand(command_id="cmd-1", service="ec2", action="create-vpc", parameters={}, description="1", operation_category=OperationCategory.WRITE)
        cmd2 = CLICommand(command_id="cmd-2", service="ec2", action="create-subnet", parameters={}, description="2", operation_category=OperationCategory.WRITE, depends_on=["cmd-1"])
        cmd3 = CLICommand(command_id="cmd-3", service="ec2", action="run-instances", parameters={}, description="3", operation_category=OperationCategory.WRITE, depends_on=["cmd-2"])
        cmd4 = CLICommand(command_id="cmd-4", service="s3api", action="create-bucket", parameters={}, description="4", operation_category=OperationCategory.WRITE)

        graph = DependencyGraph([cmd1, cmd2, cmd3, cmd4])
        dependents = graph.get_transitive_dependents("cmd-1")
        assert dependents == {"cmd-2", "cmd-3"}
        assert graph.get_transitive_dependents("cmd-4") == set()
