import pytest
from services.registry import create_default_registry

class TestServiceRegistry:
    def setup_method(self):
        self.registry = create_default_registry()
    
    def test_ec2_registered(self):
        assert self.registry.is_service_supported('ec2')
    
    def test_s3_registered(self):
        assert self.registry.is_service_supported('s3')
    
    def test_vpc_registered(self):
        assert self.registry.is_service_supported('vpc')
    
    def test_iam_registered(self):
        assert self.registry.is_service_supported('iam')
    
    def test_dynamodb_registered(self):
        assert self.registry.is_service_supported('dynamodb')
    
    def test_lambda_registered(self):
        assert self.registry.is_service_supported('lambda')
    
    def test_unknown_service_not_supported(self):
        assert not self.registry.is_service_supported('unknown_service')
    
    def test_ec2_instance_resource_type(self):
        rt = self.registry.get_resource_type('ec2', 'instance')
        assert rt is not None
        assert rt.create_action == 'run-instances'
    
    def test_s3_bucket_resource_type(self):
        rt = self.registry.get_resource_type('s3', 'bucket')
        assert rt is not None
        assert rt.create_action == 'create-bucket'
    
    def test_service_summary(self):
        summary = self.registry.get_service_summary()
        assert 'ec2' in summary
        assert 's3' in summary
        assert 'description' in summary['ec2']
    
    def test_list_all_services(self):
        services = self.registry.list_services()
        assert len(services) >= 8  # At minimum 8 services
    
    def test_list_resource_types(self):
        types = self.registry.list_resource_types('ec2')
        assert 'instance' in types
