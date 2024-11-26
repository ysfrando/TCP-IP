import boto3
import logging
from botocore.exceptions import ClientError
from typing import List, Dict, Any
import concurrent.futures
import json

class SecurityGroupAuditor:
    def __init__(self, region: str = 'us-east-1'):
        self.ec2 = boto3.client('ec2', region_name=region)
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def audit_security_groups(self) -> List[Dict[str, Any]]:
        try:
            response = self.ec2.describe_security_groups()
        except ClientError as e:
            self.logger.error(f"Failed to describe security groups: {e}")
            return []

        security_groups = response['SecurityGroups']
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            issues = list(executor.map(self._audit_single_group, security_groups))
        
        return [issue for sublist in issues for issue in sublist]  # Flatten list

    def _audit_single_group(self, sg: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues = []
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        
        for rule in sg['IpPermissions']:
            ip_ranges = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
            
            if '0.0.0.0/0' in ip_ranges:
                if self._is_ssh_or_rdp_open(rule):
                    issues.append(self._create_issue(sg_name, sg_id, "SSH or RDP open to the world", rule))
                elif self._is_all_ports_open(rule):
                    issues.append(self._create_issue(sg_name, sg_id, "All ports open to the world", rule))
        
        return issues

    @staticmethod
    def _is_ssh_or_rdp_open(rule: Dict[str, Any]) -> bool:
        return rule.get('FromPort') in [22, 3389] or rule.get('ToPort') in [22, 3389]

    @staticmethod
    def _is_all_ports_open(rule: Dict[str, Any]) -> bool:
        return rule.get('FromPort') == -1 or rule.get('ToPort') == -1

    @staticmethod
    def _create_issue(sg_name: str, sg_id: str, issue: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "security_group_name": sg_name,
            "security_group_id": sg_id,
            "issue": issue,
            "rule": rule
        }

    def revoke_rule(self, sg_id: str, rule: Dict[str, Any]) -> None:
        try:
            self.ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[rule])
            self.logger.info(f"Revoked rule: {json.dumps(rule)} from Security Group: {sg_id}")
        except ClientError as e:
            self.logger.error(f"Failed to revoke rule: {json.dumps(rule)} from Security Group: {sg_id}. Error: {str(e)}")

    def run_audit(self) -> None:
        self.logger.info("Starting security group audit...")
        issues = self.audit_security_groups()
        
        if not issues:
            self.logger.info("No security issues found.")
            return

        self.logger.warning(f"Found {len(issues)} security issues:")
        for issue in issues:
            self.logger.warning(json.dumps(issue, indent=2))
            if input("Revoke this rule? (y/n): ").lower() == 'y':
                self.revoke_rule(issue['security_group_id'], issue['rule'])

        self.logger.info("Audit completed.")

if __name__ == "__main__":
    auditor = SecurityGroupAuditor()
    auditor.run_audit()
