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

class TrivySonarReport:
    LOG_PREFIX = "[trivy][plugins][sonarqube]"
    TRIVY_SONARQUBE_SEVERITY = {
        "UNKNOWN": "LOW",
        "LOW": "LOW",
        "MEDIUM": "LOW",
        "HIGH": "MEDIUM",
        "CRITICAL": "HIGH",
    }

    def __init__(self, filename, file_path=None):
        self.filename = filename
        self.file_path = file_path

    def apply_changes(self, txt):
        """Remove emojis from text."""
        return emoji.replace_emoji(txt, replace='')

    def load_trivy_report(self):
        """Load and parse the Trivy report from a JSON file."""
        with open(self.filename) as file:
            return json.load(file)

    def parse_trivy_report(self, report):
        """Parse vulnerabilities from the Trivy report."""
        for result in report.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                try:
                    vuln["Target"] = f"{report['ArtifactName']}/{result['Target']}"
                    for key in ("VulnerabilityID", "Title", "Description", "Severity", "PrimaryURL"):
                        if key not in vuln:
                            raise KeyError(key)
                except KeyError:
                    continue
                yield vuln

    def make_sonar_issues(self, vulnerabilities):
        """Create SonarQube issues from Trivy vulnerabilities."""
        seen_rules = set()
        res = {"rules": [], "issues": []}
        
        for vuln in vulnerabilities:
            rule_id = vuln["VulnerabilityID"]
            
            if rule_id not in seen_rules:
                res["rules"].append({
                    "id": rule_id,
                    "name": self.apply_changes(f"[{vuln['Target']}] {vuln['Title']}"),
                    "description": self.apply_changes(vuln["Description"]),
                    "engineId": "Trivy",
                    "cleanCodeAttribute": "LOGICAL",
                    "impacts": [{
                        "softwareQuality": "SECURITY",
                        "severity": self.TRIVY_SONARQUBE_SEVERITY[vuln["Severity"]],
                    }],
                })
                seen_rules.add(rule_id)

            res["issues"].append({
                "ruleId": rule_id,
                "primaryLocation": {
                    "message": f"{rule_id} {self.apply_changes(vuln['Title'])}",
                    "filePath": self.file_path or vuln["Target"],
                },
            })

        return res

    def generate_report(self):
        """Generate and print the SonarQube report."""
        if not os.path.exists(self.filename):
            sys.exit(f"{self.LOG_PREFIX} File not found: {self.filename}")

        report = self.load_trivy_report()
        vulnerabilities = self.parse_trivy_report(report)
        sonar_issues = self.make_sonar_issues(vulnerabilities)
        sonar_report = json.dumps(sonar_issues, indent=2)
        print(sonar_report)
        return sonar_report
        


from pathlib import Path
from typing import Final
import collections
import json
import os
import sys

class SemgrepReport:
    LEVEL_TO_SEVERITY: Final[dict[str, str]] = {
        'warning': 'MAJOR',
        'error': 'CRITICAL',
        'note': 'MINOR',
        'none': 'INFO'
    }
    DEFAULT_REPORT_TYPE: Final[str] = 'VULNERABILITY'
    REPORT_TYPE_BY_ENGINE: Final[dict[str, str]] = {
        'ansible-lint': 'VULNERABILITY',
        'robocop': 'VULNERABILITY',
        'tflint': 'VULNERABILITY'
    }

    Position = collections.namedtuple('Position', ['line', 'column'])

    def __init__(self, source: Path | str, target: Path | str):
        self.source = Path(source).resolve()
        self.target = Path(target).resolve()

    @staticmethod
    def generate_title(scan_id, cwe_tags: list[str]) -> str:
        """Generate a title based on scan ID and CWE tags."""
        return cwe_tags[0] if cwe_tags else scan_id

    def process_report(self) -> None:
        """Process the SARIF report and write issues to the target file."""
        if self.target.exists():
            raise IOError(f'Target file "{self.target}" already exists.')

        sarif_data: dict = json.loads(self.source.read_text(encoding='utf-8'))
        if 'sarif' not in sarif_data.get('$schema', ''):
            raise ValueError('Source is (probably) not a valid SARIF file.')

        issues: list[dict] = []
        for run_index, run_data in enumerate(sarif_data.get('runs', []), 1):
            driver_data = run_data['tool']['driver']
            engine_id = driver_data['name']
            engine_key = engine_id.lower()
            rules: dict[str, dict] = {rule['id']: rule for rule in driver_data.get('rules', [])}

            for result_index, result_data in enumerate(run_data.get('results', []), 1):
                if (num_locations := len(result_data.get('locations', []))) != 1:
                    raise NotImplementedError(
                        f'File {self.source} : run[{run_index}].results[{result_index}].locations[] '
                        f'size expected 1, actual {num_locations}')

                rule_id = result_data['ruleId']
                rule_data = rules.get(rule_id, {})
                location_data = result_data['locations'][0]['physicalLocation']
                file_path = location_data['artifactLocation']['uri']
                description = result_data['message']['text']
                severity_level = rule_data.get('defaultConfiguration', {}).get('level')
                severity = self.LEVEL_TO_SEVERITY.get(severity_level, 'INFO')
                properties = rule_data.get('properties', {})
                cwe_tags = [tag for tag in properties.get('tags', []) if tag.startswith('CWE-')]
                title = f"[{file_path}] " + self.generate_title(rule_id, cwe_tags)

                issue = {
                    'engineId': engine_id,
                    'primaryLocation': {
                        'filePath': file_path,
                        'message': title
                    },
                    'ruleId': rule_id,
                    'title': title,
                    'severity': severity,
                    'type': self.REPORT_TYPE_BY_ENGINE.get(engine_key, self.DEFAULT_REPORT_TYPE)
                }

                start = self.Position(
                    location_data['region']['startLine'] - 1,
                    location_data['region'].get('startColumn', 1) - 1)
                end = self.Position(
                    location_data['region'].get('endLine', start.line + 1) - 1,
                    location_data['region'].get('endColumn', start.column + 1) - 1)

                if engine_key in {'ansible-lint', 'robocop'}:
                    lines = Path(file_path).read_text(encoding='utf-8').split(os.linesep)
                    if start == end or (end.column and end.column > len(lines[end.line])):
                        if end.line + 1 < len(lines):
                            end = self.Position(end.line + 1, 0)
                        else:
                            start = self.Position(start.line - 1, start.column)
                            end = self.Position(end.line, 0)

                issue['primaryLocation']['textRange'] = {
                    'startLine': start.line + 1,
                    'startColumn': start.column,
                    'endLine': end.line + 1,
                    'endColumn': end.column
                }

                issues.append(issue)

        self.target.write_text(json.dumps({'issues': issues or []}, indent=2), encoding='utf-8')


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
        sarif_file = self.trivy_output
        sonarjson_file = self.sonar_trivy

        SarifToSonarQubeConverter.convert(sarif_file, sonarjson_file)

    def convert_semgrep(self):
        """Convert Semgrep SARIF report to SonarQube-compatible JSON format."""
        print("Converting Semgrep SARIF report to SonarQube JSON format...")
        try:
            semgrep_report = SemgrepReport(self.semgrep_output, self.sonar_semgrep)
            semgrep_report.process_report()
            print(f"Semgrep report successfully converted to {self.sonar_semgrep}.")
        except Exception as e:
            print(f"Error converting Semgrep report: {e}")


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
            f"-Dsonar.token={self.sonar_token}",
            f"-Dsonar.externalIssuesReportPaths={sarif_files_str}",  # Use externalIssuesReportPaths for multiple files
            f"-Dsonar.sources=.",
            #"-Dsonar.verbose=true",
            #"-Dsonar.issue.ignore.multicriteria.e1.resourceKey=*"
            #"-Dsonar.language=none"
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
                        "message": f'[{result.get("ruleId")}] {result.get("Title")}',
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
                            "message": f"{result.get('ruleId')} {result.get('Title')}",#location.get("message", {}).get("text", ""),
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
