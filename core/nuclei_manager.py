import subprocess
import json
from typing import List, Dict
from datetime import datetime

class NucleiManager:
    def __init__(self, logger, nuclei_path="/usr/local/bin/nuclei", templates_dir="/opt/nuclei-templates"):
        self.logger = logger
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir

    def check_installation(self):
        try:
            self.nuclei_path = subprocess.check_output(["which", "nuclei"], text=True).strip()
        except subprocess.CalledProcessError:
            self.logger.error("Nuclei not found. Installing...")
            self.install_nuclei()

    def install_nuclei(self):
        commands = [
            "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "nuclei -update-templates"
        ]
        for cmd in commands:
            subprocess.run(cmd, shell=True, check=True)

    def update_templates(self):
        subprocess.run([self.nuclei_path, "-update-templates"], check=True)

    def run_scan(self, target, output_dir="/var/log/bb_scans") -> Dict:
        scan_id = f"{target.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        output_file = f"{output_dir}/bb_{scan_id}.json"
        
        command = [
            self.nuclei_path, "-u", target.url, "-severity", target.severity_threshold, 
            "-json", "-o", output_file, "-silent"
        ]
        
        for template in target.excluded_templates:
            command.extend(["-exclude-templates", template])
        
        subprocess.run(command, check=True)

        findings = []
        with open(output_file, 'r') as f:
            for line in f:
                findings.append(json.loads(line.strip()))
        
        return {
            'target_url': target.url,
            'scan_time': datetime.now().isoformat(),
            'findings': findings,
            'total_findings': len(findings)
        }
