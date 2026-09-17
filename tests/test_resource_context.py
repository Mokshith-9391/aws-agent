import pytest
from agent.models import LogicalResource, ResourceOwnership
from agent.resource_context import ResourceContext, UnresolvedReferenceError


class TestResourceContext:
    def setup_method(self):
        self.context = ResourceContext()

    def test_register_and_get_resource(self):
        resource = LogicalResource(
            resource_ref="vpc.main",
            service="ec2",
            resource_type="vpc",
            resource_id="vpc-0123456789abcdef0",
            ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            attributes={"cidr": "10.0.0.0/16"},
        )
        self.context.register_resource(resource)

        retrieved = self.context.get_resource("vpc.main")
        assert retrieved is not None
        assert retrieved.resource_id == "vpc-0123456789abcdef0"
        assert retrieved.ownership == ResourceOwnership.CREATED_BY_THIS_PLAN

    def test_resolve_value_id_and_properties(self):
        self.context.register_resource(
            LogicalResource(
                resource_ref="security_group.web",
                service="ec2",
                resource_type="security_group",
                resource_id="sg-9876543210abcdef0",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
                attributes={"group_name": "web-sg", "vpc_id": "vpc-12345"},
            )
        )

        assert self.context.resolve_value("security_group.web") == "sg-9876543210abcdef0"
        assert self.context.resolve_value("security_group.web.id") == "sg-9876543210abcdef0"
        assert self.context.resolve_value("security_group.web.group_name") == "web-sg"
        assert self.context.resolve_value("security_group.web.vpc_id") == "vpc-12345"

    def test_resolve_unregistered_raises_error(self):
        with pytest.raises(UnresolvedReferenceError) as exc_info:
            self.context.resolve_value("subnet.missing.id", raise_if_unresolved=True)
        assert "subnet.missing.id" in str(exc_info.value)

    def test_recursive_placeholder_resolution_in_nested_structures(self):
        self.context.register_resource(
            LogicalResource(
                resource_ref="vpc.main",
                service="ec2",
                resource_type="vpc",
                resource_id="vpc-11111111",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )
        self.context.register_resource(
            LogicalResource(
                resource_ref="subnet.public",
                service="ec2",
                resource_type="subnet",
                resource_id="subnet-22222222",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )
        self.context.register_resource(
            LogicalResource(
                resource_ref="security_group.web",
                service="ec2",
                resource_type="security_group",
                resource_id="sg-33333333",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )

        nested_params = {
            "vpc-id": "{{vpc.main.id}}",
            "subnet-id": "{{subnet.public.id}}",
            "security-group-ids": ["{{security_group.web.id}}", "sg-existing-constant"],
            "tags": [
                {"Key": "VpcRef", "Value": "Attached to {{vpc.main.id}}"},
                {"Key": "Static", "Value": "Prod"}
            ],
            "details": {
                "inner": {
                    "ref": "{{security_group.web.id}}"
                }
            },
            "count": 1,
            "enabled": True,
        }

        resolved = self.context.resolve_placeholders_recursively(nested_params)

        assert resolved["vpc-id"] == "vpc-11111111"
        assert resolved["subnet-id"] == "subnet-22222222"
        assert resolved["security-group-ids"] == ["sg-33333333", "sg-existing-constant"]
        assert resolved["tags"][0]["Value"] == "Attached to vpc-11111111"
        assert resolved["details"]["inner"]["ref"] == "sg-33333333"
        assert resolved["count"] == 1
        assert resolved["enabled"] is True

    def test_find_unresolved_placeholders(self):
        data = {
            "vpc-id": "{{vpc.main.id}}",
            "subnet-id": "subnet-real-123",
            "list": ["{{unknown.ref}}", "clean-value"],
        }
        placeholders = self.context.find_unresolved_placeholders(data)
        assert set(placeholders) == {"{{vpc.main.id}}", "{{unknown.ref}}"}

    def test_ownership_tracking_for_plan(self):
        self.context.register_resource(
            LogicalResource(
                resource_ref="vpc.created",
                service="ec2",
                resource_type="vpc",
                resource_id="vpc-new",
                ownership=ResourceOwnership.CREATED_BY_THIS_PLAN,
            )
        )
        self.context.register_resource(
            LogicalResource(
                resource_ref="vpc.existing",
                service="ec2",
                resource_type="vpc",
                resource_id="vpc-reused",
                ownership=ResourceOwnership.REUSED_FROM_EXISTING,
            )
        )

        assert self.context.is_resource_owned_by_plan("vpc.created") is True
        assert self.context.is_resource_owned_by_plan("vpc.existing") is False
        assert self.context.is_resource_owned_by_plan("nonexistent") is False
