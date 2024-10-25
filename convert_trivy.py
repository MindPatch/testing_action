#!/usr/bin/env python3

import json
import os
import sys
import emoji
import random


LOG_PREFIX = "[trivy][plugins][sonarqube]"
TRIVY_SONARQUBE_SEVERITY = {
    "UNKNOWN": "LOW",
    "LOW": "LOW",
    "MEDIUM": "LOW",
    "HIGH": "MEDIUM",
    "CRITICAL": "HIGH",
}

def apply_changes(txt):
    """Remove emojis from text."""
    txt = emoji.replace_emoji(txt, replace='')
    #print(f"DEBUG: {txt}")
    return txt

def load_trivy_report(filename):
    """Load and parse the Trivy report from a JSON file."""
    with open(filename) as file:
        return json.load(file)

def parse_trivy_report(report):
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

def make_sonar_issues(vulnerabilities, file_path=None):
    """Create SonarQube issues from Trivy vulnerabilities."""
    seen_rules = set()
    res = {"rules": [], "issues": []}
    
    for vuln in vulnerabilities:
        rule_id = vuln["VulnerabilityID"]
        
        if rule_id not in seen_rules:
            res["rules"].append({
                "id": rule_id,
                "name": apply_changes( "["+ vuln["Target"] + "] "+ vuln["Title"]),
                "description": apply_changes(vuln["Description"]),
                "engineId": "Trivy",
                "cleanCodeAttribute": "LOGICAL",
                "impacts": [{
                    "softwareQuality": "SECURITY",
                    "severity": TRIVY_SONARQUBE_SEVERITY[vuln["Severity"]],
                }],
            })
            seen_rules.add(rule_id)

        res["issues"].append({
            "ruleId": rule_id,
            "primaryLocation": {
                "message": f"{rule_id} {apply_changes(vuln['Title'])}",
                "filePath": vuln["Target"],
            },
        })

    return res

def make_sonar_report(res):
    """Convert the results to a SonarQube report in JSON format."""
    return json.dumps(res, indent=2)

def main(args):
    file_path = args[1]

    report = load_trivy_report(file_path)
    vulnerabilities = parse_trivy_report(report)
    sonar_issues = make_sonar_issues(vulnerabilities)
    sonar_report = make_sonar_report(sonar_issues)

    out_file = os.path.join("/github/workspace", "sonar_trivy.json")
    print("FUCK")
    print(sonar_report)
    with open(out_file, "w") as f:
        json.dump(sonar_report,f)
    print("WRITTEN")

if __name__ == "__main__":
    main(sys.argv)
