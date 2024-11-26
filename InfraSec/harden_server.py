#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
import paramiko
import json
from datetime import datetime
from typing import List, Dict, Optional
import yaml
from dataclasses import dataclass

@dataclass
class SystemConfig:
    hostname: str
    ssh_port: int
    allowed_users: List[str]
    required_packages: List[str]
    security_configs: Dict[str, str]

class SecurityAutomation:
    def __init__(self, config_file: str):
        self.logger = self._setup_logging()
        self.config = self._load_config(config_file)
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('SecurityAutomation')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('/var/log/security_automation.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _load_config(self, config_file: str) -> SystemConfig:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
            return SystemConfig(**config_data)

    def harden_system(self):
        """Implement system hardening measures"""
        try:
            # Update system packages
            self._run_command("apt-get update && apt-get upgrade -y")
            
            # Install required packages
            for package in self.config.required_packages:
                self._run_command(f"apt-get install -y {package}")
        
            # Configure SSH hardening
            self._configure_ssh()
            # Set Up Firewall rules
            self._configure_firewall()
            # Configure System Auditing
            self._setup_auditd()
            # Implement file system handling
            self._secure_filesystem()
 
            self.logger.info("System hardening completed successfully")
        except Exception as e:
            self.logger.error(f"System hardening failed: {str(e)}")
            raise

    def _configure_ssh(self):
        """Configure secure SSH settings"""
        ssh_config = {
            'PermitRootLogin': 'no',
            'PasswordAuthentication': 'no',
            'X11Forwarding': 'no',
            'MaxAuthTries': '3',
            'Protocol': '2'
        }

        sshd_config_path = '/etc/ssh/sshd_config'
        backup_path = f"{sshd_config_path}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Backup existing config
        self._run_command(f"cp {sshd_config_path} {backup_path}")
     
        # Update SSH configuration
        for key, value in ssh_config.items():
            self._run_command(f"sed -i 's/^#?{key}.*/{key} {value}/' {sshd_config_path}")
        
        # Restart SSH service
        self._run_command("systemctl restart sshd")

    def _configure_firewall(self):
        """Set up UFW firewall rules"""
        commands = [
            "ufw default deny incoming",
            "ufw default allow outgoing",
            f"ufw allow {self.config.ssh_port}/tcp",
            "ufw enable"
        ]

        for command in commands:
            self._run_command(command)

    def _setup_auditd(self):
        """Configure system auditing with auditd"""
        audit_rules = [
            "-w /etc/passwd -p wa -k identity",
            "-w /etc/group -p wa -k identity",
            "-w /etc/shadow -p wa -k identity",
            "-w /etc/sudoers -p wa -k sudo_actions",
            "-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -K sudo_commands"
        ]

        rules_file = "/etc/audit/rules.d/security.rules"
        with open(rules_file, 'w') as f:
            for rule in audit_rules:
                f.write(f"{rule}\n")
        
        self._run_command("service auditd restart")

    def _secure_filesystem(self):
        """Implement filesystem security measures"""
        fstab_entries = {
            '/tmp': 'defaults,noexec,nosuid,nodev',    
            '/var/tmp': 'defaults,noexec,nosuid,nodev',
            '/dev/shm': 'defaults,noexec,nosuid,nodev'
        }
        # Backup fstab
        self._run_command("cp /etc/fstab /etc/fstab.bak")

        # Update mount options
        for mount_point, options in fstab_entries:
            self._run_command(f"mount -o remount,{options} {mount_point}")

        def monitor_security_events(self):
            """Monitor and report security events"""
            events = {
                'failed_logins': self._check_failed_logins(),
                'sudo_usage': self._check_sudo_usage(),
                'filesystem_usage': self._check_filesystem_changes()
            }

            self._generate_security_report(events)

        def _check_failed_logins(self) -> List[Dict]:
            """Check for failed login attempts"""
            command = "grep 'Failed password' /var/log/auth.log"
            output = self._run_command(command)
            return self._parse_auth_log(output)

        def _check_sudo_usage(self) -> List[Dict]:
            """Monitor sudo command usage"""
            command = "grep 'sudo:' /var/log/auth.log"
            output = self._run_command(command)
            return self._parse_auth_log(output)

        def _check_filesystem_changes(self) -> List[Dict]:
            """Monitor critical filesystem changes"""
            paths_to_monitor = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
            changes = []
        
            for path in paths_to_monitor:
                find_command = f"find {path} -mtime -1 -type f"
                output = self._run_command(find_command)
                if output:
                    changes.extend(output.splitlines())
            return changes

        def _run_command(self, command: str) -> Optional[str]:
            try:
                result = subprocess.run(command, shell=True, check=True, capture_output=True,                  text=True) 
                return result.stdout
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Command failed: {command}\nError: {str(e)}")
                raise

        def _generate_security_report(self, events: Dict):
            """Generate security event report"""
            report = {
                'timestamp': datetime.now().isoformat(),
                'hostname': self.config.hostname,
                'events': events
            }
            
            report_path = '/var/log/security_report.json'
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)

            self.logger.info(f"Security report generated: {report_path}")

if __name__ == "__main__":
    if os.geteuid != 0:
        print("This script must be run as root!")
        sys.exit(1)

    config_file = "/etc/security_automation/config.yaml"
    automation = SecurityAutomation(config_file)

    try:
        automation.harden_system()
        automation.monitor_security_events()
    except Exception as e:
        logging.error(f"Security automation failed: {str(e)}")
        sys.exit(1)
