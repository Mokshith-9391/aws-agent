"""
CLI Command Validator module.
Ensures AWS CLI commands meet security guidelines and required formats.
"""
import re
from typing import Tuple, List

from agent.models import CLICommand, OperationCategory
from aws.cli_executor import ALLOWED_SERVICES, ALLOWED_ACTIONS

class CLICommandValidator:
    """Validates parameters, formatting, and safety of CLICommands."""
    
    def __init__(self):
        self.cidr_regex = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$')
        self.region_regex = re.compile(r'^[a-z]{2}-[a-z]+-\d+$')
        self.ami_regex = re.compile(r'^ami-[a-f0-9]{8,17}$')
        self.vpc_regex = re.compile(r'^vpc-[a-f0-9]{8,17}$')
        self.subnet_regex = re.compile(r'^subnet-[a-f0-9]{8,17}$')
        self.sg_regex = re.compile(r'^sg-[a-f0-9]{8,17}$')
        self.instance_type_regex = re.compile(r'^[a-z0-9]+\.[a-z0-9]+$')
        self.s3_bucket_regex = re.compile(r'^[a-z0-9.-]{3,63}$')
        
    def validate_command(self, cmd: CLICommand) -> Tuple[bool, List[str]]:
        """Validates a command for structure and security concerns."""
        issues = []
        
        if cmd.service not in ALLOWED_SERVICES:
            issues.append(f"Service '{cmd.service}' not in allowlist.")
        else:
            allowed = ALLOWED_ACTIONS.get(cmd.service, set())
            if cmd.action not in allowed:
                issues.append(f"Action '{cmd.action}' not in allowlist for '{cmd.service}'.")
                
        if not cmd.parameters:
            return len(issues) == 0, issues
            
        for key, val in cmd.parameters.items():
            if re.search(r'[;|&`$\n\r]', key):
                issues.append(f"Parameter key '{key}' contains shell metacharacters.")
            
            if isinstance(val, str):
                # Check for command injection patterns in values
                if re.search(r'[;|&`\n\r]', val) or '$(' in val or '||' in val or '&&' in val:
                    issues.append(f"Parameter value for '{key}' contains command injection patterns.")
                
                # Format validations
                if key in ('cidr', 'cidr-block'):
                    if not self.cidr_regex.match(val):
                        issues.append(f"Invalid CIDR block format: {val}")
                        
                elif key == 'region':
                    if not self.region_regex.match(val):
                        issues.append(f"Invalid AWS region format: {val}")
                        
                elif key == 'image-id':
                    if not self.ami_regex.match(val):
                        issues.append(f"Invalid AMI ID format: {val}")
                        
                elif key == 'vpc-id':
                    if not self.vpc_regex.match(val) and not val.startswith(('$', '{{')) :
                        issues.append(f"Invalid VPC ID format: {val}")
                        
                elif key == 'subnet-id':
                    if not self.subnet_regex.match(val) and not val.startswith(('$', '{{')):
                        issues.append(f"Invalid Subnet ID format: {val}")
                        
                elif key in ('group-id', 'security-group-ids'):
                    if not self.sg_regex.match(val) and not val.startswith(('$', '{{')):
                        issues.append(f"Invalid Security Group ID format: {val}")
                        
                elif key == 'instance-type':
                    if not self.instance_type_regex.match(val):
                        issues.append(f"Invalid instance type format: {val}")
                        
                elif key == 'bucket':
                    if not self.s3_bucket_regex.match(val):
                        issues.append(f"Invalid S3 bucket name format: {val}")
                        
                elif key == 'port':
                    try:
                        port = int(val)
                        if not 0 <= port <= 65535:
                            issues.append(f"Port number out of range (0-65535): {port}")
                    except ValueError:
                        issues.append(f"Invalid port number format: {val}")
                        
        return len(issues) == 0, issues

    def classify_operation(self, service: str, action: str) -> OperationCategory:
        """Classifies the AWS API operation into a category (READ_ONLY, WRITE, DESTRUCTIVE)."""
        action_lower = action.lower()
        if action_lower.startswith(('describe', 'list', 'get', 'head')):
            return OperationCategory.READ_ONLY
        elif action_lower.startswith(('delete', 'terminate', 'remove', 'revoke', 'deregister')):
            return OperationCategory.DESTRUCTIVE
        else:
            return OperationCategory.WRITE
