from __future__ import annotations

from pathlib import Path
from typing import Final
import collections
import json
import os
import sys
import random

def random_char():
    return "" #random.choice(['>', '-', '/'])
SCANNED_FILES = []

# https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317648
# SonarQube severity can be one of BLOCKER, CRITICAL, MAJOR, MINOR, INFO
LEVEL_TO_SEVERITY: Final[dict[str, str]] = {
    'warning': 'MAJOR',
    'error': 'CRITICAL',
    'note': 'MINOR',
    'none': 'INFO'
}

def generate_title(scan_id, cwe_tags: list[str]) -> str:
    if cwe_tags:
        cwe_tag = cwe_tags[0]  # Take the first CWE tag
        title = f"{cwe_tag}"
    else:
        title = f"{scan_id}"
    return title

DEFAULT_REPORT_TYPE: Final[str] = 'VULNERABILITY'
REPORT_TYPE_BY_ENGINE: Final[dict[str, str]] = {
    'ansible-lint': 'VULNERABILITY',
    'robocop': 'VULNERABILITY',
    'tflint': 'VULNERABILITY'
}

Position = collections.namedtuple('Position', ['line', 'column'])

def main(source: Path | str, target: Path | str) -> None:
    source = Path(source).resolve()
    target = Path(target).resolve()

    if target.exists():
        raise IOError(f'Target file "{target}" already exists.')

    sarif_data: dict = json.loads(source.read_text(encoding='utf-8'))
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
                    f'File {source} : run[{run_index}].results[{result_index}].locations[] '
                    f'size expected 1, actual {num_locations}')

            rule_id = result_data['ruleId']
            rule_data = rules.get(rule_id, {})
            location_data = result_data['locations'][0]['physicalLocation']
            file_path = location_data['artifactLocation']['uri']

            description = result_data['message']['text']

            message_lines = [
                description
            ]
            # Extract severity from `defaultConfiguration` if available
            default_config = rule_data.get('defaultConfiguration', {})
            severity_level = default_config.get('level')
            severity = LEVEL_TO_SEVERITY.get(severity_level, 'INFO')  # Default to 'INFO' if level is unknown

            # Extract CWE tags from `properties`
            properties = rule_data.get('properties', {})
            cwe_tags = [tag for tag in properties.get('tags', []) if tag.startswith('CWE-')]

            title = f"[{file_path}] " + generate_title(rule_id, cwe_tags)  # Set ruleId as the title with CWE
            issue = {
                'engineId': engine_id,
                'primaryLocation': {
                    'filePath': file_path,
                    'message': title#'\n'.join(message_lines)
                },
                'ruleId': rule_id,
                'title': title,
                'severity': severity,
                'type': REPORT_TYPE_BY_ENGINE.get(engine_key, DEFAULT_REPORT_TYPE)
            }

            start = Position(
                location_data['region']['startLine'] - 1,
                location_data['region'].get('startColumn', 1) - 1)
            end = Position(
                location_data['region'].get('endLine', start.line + 1) - 1,
                location_data['region'].get('endColumn', start.column + 1) - 1)

            if engine_key in {'ansible-lint', 'robocop'}:
                lines = Path(file_path).read_text(encoding='utf-8').split(os.linesep)
                if start == end or (end.column and end.column > len(lines[end.line])):
                    prev_start, prev_end = start, end
                    if end.line + 1 < len(lines):
                        end = Position(end.line + 1, 0)
                    else:
                        start = Position(start.line - 1, start.column)
                        end = Position(end.line, 0)
                    assert start.line >= 0, (start, end)
                    print(
                        f"Wrong indexation (0-indexed) {file_path}: "
                        f"(start={tuple(prev_start)} end={tuple(prev_end)}), "
                        f"fix it by setting start={tuple(start)} end={tuple(end)}")

            issue['primaryLocation']['textRange'] = {
                'startLine': start.line + 1,
                'startColumn': start.column,
                'endLine': end.line + 1,
                'endColumn': end.column
            }

            issues.append(issue)

    if not issues:
        issues = []

    target.write_text(json.dumps({'issues': issues}, indent=2), encoding='utf-8')

def clean_tag(value: str) -> str:
    return f"'{value}'" if ' ' in value else value

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
