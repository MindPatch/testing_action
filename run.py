import os
import json
import sys
import yaml
import subprocess
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
    """Runs sonar-scanner on SARIF reports and uploads results to SonarQube."""

    def __init__(self, config_loader):
        self.sonar_project_key = config_loader.get("SONAR_PROJECTKEY")
        self.sonar_host_url = config_loader.get("SONAR_HOST_URL", "https://sonar.blacklock.io")
        self.sonar_token = os.getenv("SONAR_TOKEN")
        self.workspace_dir = "/github/workspace"
        self.exclude = "*"  # Example exclusion for .java files

    def run_sonar_scanner(self, sarif_files):
        """Runs the sonar-scanner CLI for the given SARIF report or reports."""
        sarif_files_str = ",".join(sarif_files)  # Join multiple files with a comma
        command = [
            "sonar-scanner",
            f"-Dsonar.projectKey={self.sonar_project_key}",
            f"-Dsonar.host.url={self.sonar_host_url}",
            f"-Dsonar.login={self.sonar_token}",
            f"-Dsonar.externalIssuesReportPaths={sarif_files_str}",  # Use externalIssuesReportPaths for multiple files
            f"-Dsonar.sources=.",
            "-Dsonar.verbose=true",
            "-Dsonar.language="
        ]

        print(f"Running sonar-scanner with reports: {sarif_files_str}")
        result = subprocess.run(command, cwd=self.workspace_dir, check=False, capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)

        if result.returncode == 0:
            print("SARIF report(s) processed successfully by sonar-scanner.")
        else:
            print("Failed to process SARIF report(s) with sonar-scanner. Return Code:", result.returncode)
            print(result.stderr)

    def run(self, trivy_report, semgrep_report):
        reports_to_process = []
        if os.path.isfile(trivy_report):
            reports_to_process.append(trivy_report)
        if os.path.isfile(semgrep_report):
            reports_to_process.append(semgrep_report)

        # Check that we have both the project key and token available
        if not self.sonar_project_key or not self.sonar_token:
            print("Error: SONAR_PROJECTKEY or SONAR_TOKEN is not set. Please set these values and try again.")
            return

        if reports_to_process:
            # Pass both reports (or single report) to sonar-scanner
            self.run_sonar_scanner(reports_to_process)
        else:
            print("No SARIF reports available to process.")


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
