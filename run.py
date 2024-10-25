import os
import subprocess
import json
import sys
import yaml


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
        self.trivy_output = os.path.join(workspace_dir, "trivy.json")
        self.semgrep_output = os.path.join(workspace_dir, "semgrep_result.sarif")
        self.sonar_trivy = os.path.join(workspace_dir, "sonar_trivy.json")
        self.sonar_semgrep = os.path.join(workspace_dir, "sonar_semgrep.json")

    def run_semgrep(self):
        print("Running Semgrep scan...")
        subprocess.run(["ls", "-la", self.workspace_dir], check=True)
        subprocess.run(["semgrep", "scan", "--config=auto", "--sarif-output", self.semgrep_output], check=True)
        print("Semgrep scan complete.")

    def run_trivy(self):
        print("Running Trivy scan...")
        subprocess.run(["ls", "-la", self.workspace_dir], check=True)
        subprocess.run(["trivy", "fs", "-f", "json", "-o", self.trivy_output, self.workspace_dir], check=True)
        print("Trivy scan complete.")

    def convert_reports(self):
        print("Converting scan results for SonarQube compatibility...")
        subprocess.run(["ls", "-la", self.workspace_dir], check=True)
        subprocess.run(["python", "/usr/local/bin/convert_trivy.py", self.trivy_output, ">", self.sonar_trivy], shell=True)
        subprocess.run(["python", "/usr/local/bin/convert_semgrep.py", self.semgrep_output, self.sonar_semgrep], shell=True)
        print("Report conversion complete.")


class ReportChecker:
    """Checks the generated reports for valid content and removes empty ones."""

    @staticmethod
    def check_and_remove(file_path):
        if os.path.isfile(file_path):
            print(f"Checking contents of {file_path}...")
            item_count = ReportChecker.count_items(file_path)
            if item_count > 0:
                print(f"File {file_path} has {item_count} items.")
            else:
                print(f"File {file_path} has no valid items. Removing it.")
                os.remove(file_path)

    @staticmethod
    def count_items(file_path):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            if "rules" in data and isinstance(data["rules"], list):
                return len(data["rules"])
            elif "issues" in data and isinstance(data["issues"], list):
                return len(data["issues"])
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
        return 0


class SonarScanner:
    """Executes SonarScanner based on the presence of report files."""

    def __init__(self, config_loader):
        self.sonar_project_key = config_loader.get("SONAR_PROJECTKEY")
        self.exclude = config_loader.get("SONAR_EXCLUDE", "")
        self.sonar_host_url = "https://sonar.blacklock.io"
        self.sonar_token = os.getenv("SONAR_TOKEN")

    def build_base_command(self):
        command = [
            "sonar-scanner",
            f"-Dsonar.projectKey={self.sonar_project_key}",
            f"-Dsonar.host.url={self.sonar_host_url}",
            f"-Dsonar.login={self.sonar_token}"
        ]
        if self.exclude:
            command.append(f"-Dsonar.exclusions={self.exclude}")
        return command

    def run(self, trivy_report, semgrep_report):
        command = self.build_base_command()

        if os.path.isfile(trivy_report) and os.path.isfile(semgrep_report):
            print("Running SonarScanner with both Trivy and Semgrep reports.")
            command.append(f"-Dsonar.externalIssuesReportPaths={trivy_report},{semgrep_report}")
        elif os.path.isfile(trivy_report):
            print("Running SonarScanner with Trivy report only.")
            command.append(f"-Dsonar.externalIssuesReportPaths={trivy_report}")
        elif os.path.isfile(semgrep_report):
            print("Running SonarScanner with Semgrep report only.")
            command.append(f"-Dsonar.externalIssuesReportPaths={semgrep_report}")
        else:
            print("Running SonarScanner without external issue reports.")

        print(f"SonarScanner command: {' '.join(command)}")
        subprocess.run(command, check=True)


def main():
    # Step 1: Load configuration
    config_loader = ConfigLoader()

    # Step 2: Validate configuration
    env_validator = EnvironmentValidator(config_loader)
    env_validator.validate()

    # Step 3: Initialize Scanner and Run Scans
    scanner = Scanner()
    scanner.run_semgrep()
    scanner.run_trivy()
    scanner.convert_reports()

    # Step 4: Validate Reports
    report_checker = ReportChecker()
    report_checker.check_and_remove(scanner.sonar_trivy)
    report_checker.check_and_remove(scanner.sonar_semgrep)

    # Step 5: Run SonarScanner
    sonar_scanner = SonarScanner(config_loader)
    sonar_scanner.run(scanner.sonar_trivy, scanner.sonar_semgrep)


if __name__ == "__main__":
    main()
