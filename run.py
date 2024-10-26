import os
import json
import sys
import yaml
import subprocess
import requests
from pathlib import Path
import emoji
from typing import Final


class ConfigLoader:
    """Loads configuration from blacklock.yml or environment variables as a fallback."""

    def __init__(self, config_file="/github/workspace/blacklock.yml"):
        self.config = {}
        self.config_file = config_file
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            print(f"Loading configuration from {self.config_file}...")
            with open(self.config_file, "r") as file:
                self.config = yaml.safe_load(file) or {}
            print("Configuration loaded:")
            print(self.config)
        else:
            print("Configuration file not found; defaulting to environment variables.")

    def get(self, key, default=None):
        return self.config.get(key, os.getenv(key, default))


class EnvironmentValidator:
    """Validates that required configuration variables are set."""

    def __init__(self, config_loader):
        self.config_loader = config_loader

    def validate(self):
        required_vars = ["SONAR_PROJECTKEY", "SONAR_HOST_URL", "SONAR_TOKEN"]
        missing_vars = [var for var in required_vars if not self.config_loader.get(var)]

        if missing_vars:
            print(f"Error: Missing required configuration variables: {', '.join(missing_vars)}")
            sys.exit(1)

        print("Configuration validated:")
        print(f"  SONAR_PROJECTKEY: {self.config_loader.get('SONAR_PROJECTKEY')}")
        print(f"  SONAR_HOST_URL: {self.config_loader.get('SONAR_HOST_URL')}")
        print("  SONAR_TOKEN: (hidden for security)")


class Scanner:
    """Handles the execution of security scans (Semgrep and Trivy)."""

    def __init__(self, workspace_dir="/github/workspace"):
        self.workspace_dir = workspace_dir
        self.trivy_output = os.path.join(workspace_dir, "trivy_result.sarif")
        self.semgrep_output = os.path.join(workspace_dir, "semgrep_result.sarif")
        self.sonar_trivy = os.path.join(workspace_dir, "sonar_trivy.json")
        self.sonar_semgrep = os.path.join(workspace_dir, "sonar_semgrep.json")

    def run_semgrep(self):
        print("Running Semgrep scan...")
        subprocess.run(["semgrep", "scan", "--config=auto", "--sarif-output", self.semgrep_output], check=True)
        print("Semgrep scan complete.")

    def run_trivy(self):
        print("Running Trivy scan...")
        subprocess.run(["trivy", "fs", "-f", "sarif", "-o", self.trivy_output, self.workspace_dir], check=True)
        print("Trivy scan complete.")

    def convert_semgrep(self):
        """Convert Semgrep SARIF report to SonarQube-compatible JSON format."""
        sarif_data = json.loads(Path(self.semgrep_output).read_text(encoding='utf-8'))
        issues = []

        for run_data in sarif_data.get('runs', []):
            engine_id = run_data['tool']['driver']['name']
            for result in run_data.get('results', []):
                rule_id = result['ruleId']
                location_data = result['locations'][0]['physicalLocation']
                file_path = location_data['artifactLocation']['uri']
                issue = {
                    'engineId': engine_id,
                    'primaryLocation': {'filePath': file_path, 'message': rule_id},
                    'ruleId': rule_id,
                    'title': rule_id,
                    'severity': 'INFO',  # Placeholder severity
                    'type': 'VULNERABILITY'
                }
                issues.append(issue)

        Path(self.sonar_semgrep).write_text(json.dumps({'issues': issues}, indent=2), encoding='utf-8')
        print(f"Semgrep report converted to SonarQube format: {self.sonar_semgrep}")

    def convert_trivy(self):
        """Convert Trivy report to SonarQube-compatible JSON format."""
        report = json.loads(Path(self.trivy_output).read_text(encoding='utf-8'))
        issues = {'rules': [], 'issues': []}
        seen_rules = set()

        for result in report.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                rule_id = vuln["VulnerabilityID"]
                if rule_id not in seen_rules:
                    issues["rules"].append({
                        "id": rule_id,
                        "name": emoji.replace_emoji(vuln["Title"], replace=''),
                        "description": emoji.replace_emoji(vuln["Description"], replace=''),
                        "engineId": "Trivy",
                        "impacts": [{
                            "softwareQuality": "SECURITY",
                            "severity": "MEDIUM"  # Placeholder severity
                        }],
                    })
                    seen_rules.add(rule_id)

                issues["issues"].append({
                    "ruleId": rule_id,
                    "primaryLocation": {"filePath": vuln["Target"], "message": rule_id}
                })

        Path(self.sonar_trivy).write_text(json.dumps(issues, indent=2), encoding='utf-8')
        print(f"Trivy report converted to SonarQube format: {self.sonar_trivy}")


class ReportChecker:
    """Checks the generated reports for valid content and removes empty ones."""

    @staticmethod
    def check_and_remove(file_path):
        if os.path.isfile(file_path):
            print(f"Checking contents of {file_path}...")
            if os.path.getsize(file_path) == 0:
                print(f"File {file_path} is empty. Removing it.")
                os.remove(file_path)


class SonarScanner:
    """Uploads SARIF reports directly to SonarQube using the REST API."""

    def __init__(self, config_loader):
        self.sonar_project_key = config_loader.get("SONAR_PROJECTKEY")
        self.sonar_host_url = config_loader.get("SONAR_HOST_URL", "https://sonar.blacklock.io")
        self.sonar_token = os.getenv("SONAR_TOKEN")
        self.project_name = config_loader.get("SONAR_PROJECTNAME", "My Project")
        self.exclude = "**/*.java"  # Exclude all .java files

    def upload_sarif_report(self, sarif_file, report_type):
        """Uploads a SARIF report file to SonarQube via the correct API endpoint."""
        api_url = f"{self.sonar_host_url}/api/ce/submit"
        headers = {
            "Authorization": f"Bearer {self.sonar_token}"
        }
        files = {
            'report': (sarif_file, open(sarif_file, 'rb'), 'application/json')
        }
        data = {
            "projectKey": self.sonar_project_key,
            "projectName": ""#self.project_name
        }

        response = requests.post(api_url, headers=headers, files=files, data=data)
        if response.status_code == 200:
            print(response.content)
            print(f"{report_type} SARIF report uploaded successfully to SonarQube.")
        else:
            print(f"Failed to upload {report_type} SARIF report to SonarQube. Status Code: {response.status_code}")
            print(response.text)

    def run(self, trivy_report, semgrep_report):
        if os.path.isfile(trivy_report):
            print("Uploading Trivy report...")
            self.upload_sarif_report(trivy_report, "TRIVY")

        if os.path.isfile(semgrep_report):
            print("Uploading Semgrep report...")
            self.upload_sarif_report(semgrep_report, "SEMGREP")


def main():
    config_loader = ConfigLoader()
    env_validator = EnvironmentValidator(config_loader)
    env_validator.validate()

    scanner = Scanner()
    scanner.run_trivy()
    scanner.run_semgrep()
    scanner.convert_trivy()
    scanner.convert_semgrep()

    report_checker = ReportChecker()
    report_checker.check_and_remove(scanner.sonar_trivy)
    report_checker.check_and_remove(scanner.sonar_semgrep)

    sonar_scanner = SonarScanner(config_loader)
    sonar_scanner.run(scanner.sonar_trivy, scanner.sonar_semgrep)


if __name__ == "__main__":
    main()
