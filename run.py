import os
import sys
import subprocess
import json


class EnvironmentValidator:
    """Validates that required configuration variables are set."""

    def __init__(self):
        pass

    def get(self, key, default=None):
        return os.getenv(key, default)

    def validate(self):
        required_vars = ["SONAR_PROJECTKEY", "SONAR_TOKEN"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]

        if missing_vars:
            print(f"Error: Missing required configuration variables: {', '.join(missing_vars)}")
            sys.exit(1)

        print("Configuration validated:")
        print(f"  SONAR_PROJECTKEY: {os.getenv('SONAR_PROJECTKEY')}")
        print("  SONAR_TOKEN: (hidden for security)")


class SarifToSonarQubeConverter:
    def __init__(self, sarif_data):
        self.sarif_data = sarif_data
        self.sonar_data = {
            "rules": [],
            "issues": []
        }
        self.rule_ids = {}

    def map_severity(self, severity):
        """
        Map SARIF severity levels to SonarQube 10.2-compatible severity levels.
        """
        severity_mapping = {
            "BLOCKER": "HIGH",
            "CRITICAL": "HIGH",
            "MAJOR": "MEDIUM",
            "MINOR": "LOW",
            "INFO": "LOW"
        }
        return severity_mapping.get(severity.upper(), "LOW")

    def create_short_title(self, cve_id, package):
        """
        Create a short title in the format [CVE-XXXX-XXXX] package (short reason).
        """
        return f"[{cve_id}] {package}"

    def parse_package(self,input_text):
        start = input_text.find("Package: ")
        if start == -1:
            return None
        start += len("Package: ")
        
        # Find the next newline or any stopping point like ' ' that may appear after the package name
        end = input_text.find("\n", start)
        if end == -1:
            end = input_text.find(" ", start)
        
        return input_text[start:end].strip()

    def parse(self):
        """
        Parse SARIF data and convert it to SonarQube JSON format.
        """
        for run in self.sarif_data.get("runs", []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown_tool")

            # Process rules
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id", "")
                if rule_id not in self.rule_ids:
                    sarif_severity = next(
                        (tag for tag in rule.get("properties", {}).get("tags", []) if tag in {"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"}), 
                        "INFO"
                    )
                    severity = self.map_severity(sarif_severity)
                    package = rule.get("name", "Unknown Package")
                    description = rule.get("fullDescription", {}).get("text", "")
                    short_title = self.create_short_title(rule_id, package)
                    
                    impacts = rule.get("properties", {}).get("impacts", [{"softwareQuality": "RELIABILITY", "severity": severity}])

                    # Build the rule dictionary
                    sonar_rule = {
                        "id": rule_id,
                        "engineId": tool_name,
                        "name": short_title,
                        "shortDescription": {
                            "text": rule.get("shortDescription", {}).get("text", "")
                        },
                        "fullDescription": {
                            "text": description
                        },
                        "defaultConfiguration": {
                            "level": severity.lower()
                        },
                        "helpUri": rule.get("helpUri", ""),
                        "help": {
                            #"text": rule.get("help", {}).get("text", ""),
                            "markdown": short_title
                        },
                        "properties": {
                            "precision": rule.get("properties", {}).get("precision", "medium"),
                            "security-severity": rule.get("properties", {}).get("security-severity", "5.0"),
                            "tags": rule.get("properties", {}).get("tags", [])
                        },
                        "cleanCodeAttribute": rule.get("properties", {}).get("cleanCodeAttribute", "IDENTIFIABLE"),
                        "impacts": impacts
                    }
                    self.sonar_data["rules"].append(sonar_rule)
                    self.rule_ids[rule_id] = True

            # Process results (issues)
            for result in run.get("results", []):
                issue = {
                    "ruleId": result.get("ruleId", ""),
                    "effortMinutes": result.get("properties", {}).get("effortMinutes", 0),
                    "primaryLocation": {
                        "message": f'[{result.get("ruleId")}] {self.parse_package(result.get("message").get("text"))}',
                        "filePath": result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                        "textRange": {
                            "startLine": result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 1),
                            "startColumn": result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startColumn", 1),
                            "endLine": result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("endLine", 1),
                            "endColumn": result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("endColumn", 1)
                        }
                    },
                    "secondaryLocations": [
                        {
                            "message": f'[{result.get("ruleId")}] {self.parse_package(result.get("message").get("text"))}',
                            "filePath": location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                            "textRange": {
                                "startLine": location.get("physicalLocation", {}).get("region", {}).get("startLine", 1)
                            }
                        }
                        for location in result.get("relatedLocations", [])
                    ]
                }
                self.sonar_data["issues"].append(issue)

    def save_to_file(self, filepath):
        """
        Save SonarQube JSON data to a file.
        """
        with open(filepath, 'w') as file:
            json.dump(self.sonar_data, file, indent=4)
        print(f"Converted SARIF report saved to {filepath}")

    @classmethod
    def convert(cls, sarif_file, sonarjson_file):
        """
        Class method to convert SARIF file to SonarQube JSON format and save it.
        """
        with open(sarif_file, 'r') as file:
            sarif_data = json.load(file)
        
        converter = cls(sarif_data)
        converter.parse()
        converter.save_to_file(sonarjson_file)


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

    def convert_trivy(self):
        """Convert Trivy SARIF report to SonarQube-compatible JSON format."""
        SarifToSonarQubeConverter.convert(self.trivy_output, self.sonar_trivy)

    def convert_semgrep(self):
        """Convert Semgrep SARIF report to SonarQube-compatible JSON format."""
        from convert_semgrep import main as semgrep_convert
        semgrep_convert(self.semgrep_output, self.sonar_semgrep)


class ReportChecker:
    """Checks the generated reports for valid content and removes empty ones."""

    @staticmethod
    def check_and_remove(file_path):
        if os.path.isfile(file_path) and os.path.getsize(file_path) == 0:
            print(f"File {file_path} is empty. Removing it.")
            os.remove(file_path)


class SonarScanner:
    """Runs sonar-scanner on SARIF reports and uploads results to SonarQube."""

    def __init__(self):
        self.sonar_project_key = os.getenv("SONAR_PROJECTKEY")
        self.sonar_host_url = os.getenv("SONAR_HOST_URL", "https://sonar.blacklock.io")
        self.sonar_token = os.getenv("SONAR_TOKEN")
        self.workspace_dir = "/github/workspace"
        self.sonar_exclusions = os.getenv("SONAR_EXCLUSIONS", "**/*.zip")  # Default exclusion for Java files

    def run_sonar_scanner(self, sarif_files):
        """Runs the sonar-scanner CLI for the given SARIF report or reports."""
        sarif_files_str = ",".join(sarif_files)
        command = [
            "sonar-scanner",
            f"-Dsonar.projectKey={self.sonar_project_key}",
            f"-Dsonar.host.url={self.sonar_host_url}",
            f"-Dsonar.token={self.sonar_token}",
            f"-Dsonar.externalIssuesReportPaths={sarif_files_str}",
            f"-Dsonar.sources=.",
            f"-Dsonar.exclusions={self.sonar_exclusions}"
        ]

        print(f"Running sonar-scanner with reports: {sarif_files_str}")
        result = subprocess.run(command, cwd=self.workspace_dir, check=False, capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)

        if result.returncode == 0:
            print("SARIF report(s) processed successfully by sonar-scanner.")
        else:
            print("Failed to process SARIF report(s) with sonar-scanner. Return Code:", result.returncode)

    def run(self, trivy_report, semgrep_report):
        reports_to_process = [report for report in [trivy_report, semgrep_report] if os.path.isfile(report)]
        if not self.sonar_project_key or not self.sonar_token:
            print("Error: SONAR_PROJECTKEY or SONAR_TOKEN is not set. Please set these values and try again.")
            return

        if reports_to_process:
            self.run_sonar_scanner(reports_to_process)
        else:
            print("No SARIF reports available to process.")


def main():
    env_validator = EnvironmentValidator()
    env_validator.validate()

    scanner = Scanner()
    scanner.run_trivy()
    scanner.run_semgrep()
    scanner.convert_trivy()
    scanner.convert_semgrep()

    report_checker = ReportChecker()
    report_checker.check_and_remove(scanner.sonar_trivy)
    report_checker.check_and_remove(scanner.sonar_semgrep)

    sonar_scanner = SonarScanner()
    sonar_scanner.run(scanner.sonar_trivy, scanner.sonar_semgrep)


if __name__ == "__main__":
    main()
