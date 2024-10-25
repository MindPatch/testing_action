#!/bin/bash

# Configurations
CONFIG_FILE="/github/workspace/blacklock.yml"
WORKSPACE_DIR="/github/workspace"
TRIVY_OUTPUT="${WORKSPACE_DIR}/trivy_result.sarif"
SEMGREP_OUTPUT="${WORKSPACE_DIR}/semgrep_result.sarif"
SONAR_TRIVY="${WORKSPACE_DIR}/sonar_trivy.json"
SONAR_SEMGREP="${WORKSPACE_DIR}/sonar_semgrep.json"
SONAR_HOST_URL="https://sonar.blacklock.io"

# Load configuration from file or environment
function load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Loading configuration from $CONFIG_FILE..."
        CONFIG=$(<"$CONFIG_FILE" yq e -j -)  # Assumes yq is available to parse YAML in Bash
        echo "Configuration loaded:"
        echo "$CONFIG"
    else
        echo "Configuration file not found; defaulting to environment variables."
    fi
}

function get_config() {
    local key=$1
    local default=$2
    local value=$(echo "$CONFIG" | jq -r ".${key}" 2>/dev/null)
    echo "${value:-${!key:-$default}}"
}

# Validate configuration
function validate_environment() {
    local required_vars=("SONAR_PROJECTKEY" "SONAR_HOST_URL" "SONAR_TOKEN")
    local missing_vars=()
    for var in "${required_vars[@]}"; do
        value=$(get_config "$var")
        if [[ -z "$value" ]]; then
            missing_vars+=("$var")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        echo "Error: Missing required configuration variables: ${missing_vars[*]}"
        exit 1
    fi

    echo "Configuration validated:"
    echo "  SONAR_PROJECTKEY: $(get_config "SONAR_PROJECTKEY")"
    echo "  SONAR_HOST_URL: $(get_config "SONAR_HOST_URL")"
    echo "  SONAR_TOKEN: (hidden for security)"
}

# Run Semgrep scan
function run_semgrep() {
    echo "Running Semgrep scan..."
    ls -la "$WORKSPACE_DIR"
    semgrep scan --config=auto --sarif-output "$SEMGREP_OUTPUT"
    echo "Semgrep scan complete."
}

# Run Trivy scan
function run_trivy() {
    echo "Running Trivy scan..."
    ls -la "$WORKSPACE_DIR"
    trivy fs -f sarif -o "$TRIVY_OUTPUT" "$WORKSPACE_DIR"
    python /usr/local/bin/convert_trivy.py "$TRIVY_OUTPUT"
    ls -la "$WORKSPACE_DIR"
    echo "Trivy scan complete."
}

# Convert reports for SonarQube
function convert_reports() {
    echo "Converting scan results for SonarQube compatibility..."
    python /usr/local/bin/convert_semgrep.py "$SEMGREP_OUTPUT" "$SONAR_SEMGREP"
    ls -la "$WORKSPACE_DIR"
    echo "Report conversion complete."
}

# Check and remove empty reports
function check_and_remove() {
    local file_path=$1
    if [[ -f "$file_path" ]]; then
        echo "Checking contents of $file_path..."
        local item_count=$(count_items "$file_path")
        if [[ "$item_count" -gt 0 ]]; then
            echo "File $file_path has $item_count items."
        else
            echo "File $file_path has no valid items. Removing it."
            rm "$file_path"
        fi
    fi
}

# Count items in SARIF reports
function count_items() {
    local file_path=$1
    local count=0
    if jq -e '.rules | arrays' "$file_path" >/dev/null; then
        count=$(jq '.rules | length' "$file_path")
    elif jq -e '.issues | arrays' "$file_path" >/dev/null; then
        count=$(jq '.issues | length' "$file_path")
    fi
    echo "$count"
}

# Run SonarScanner
function run_sonarscanner() {
    local sonar_project_key=$(get_config "SONAR_PROJECTKEY")
    local sonar_token=$(get_config "SONAR_TOKEN")
    local exclude=$(get_config "SONAR_EXCLUDE" "src/tests/**,docs/**,**.java")
    
    local command=(
        sonar-scanner
        -Dsonar.projectKey="$sonar_project_key"
        -Dsonar.host.url="$SONAR_HOST_URL"
        -Dsonar.login="$sonar_token"
    )

    if [[ -n "$exclude" ]]; then
        command+=("-Dsonar.exclusions=$exclude")
    fi

    if [[ -f "$TRIVY_OUTPUT" && -f "$SEMGREP_OUTPUT" ]]; then
        echo "Running SonarScanner with both Trivy and Semgrep reports."
        command+=("-Dsonar.externalIssuesReportPaths=${TRIVY_OUTPUT},${SEMGREP_OUTPUT}")
    elif [[ -f "$TRIVY_OUTPUT" ]]; then
        echo "Running SonarScanner with Trivy report only."
        command+=("-Dsonar.externalIssuesReportPaths=${TRIVY_OUTPUT}")
    elif [[ -f "$SEMGREP_OUTPUT" ]]; then
        echo "Running SonarScanner with Semgrep report only."
        command+=("-Dsonar.externalIssuesReportPaths=${SEMGREP_OUTPUT}")
    else
        echo "Running SonarScanner without external issue reports."
    fi

    echo "SonarScanner command: ${command[*]}"
    "${command[@]}"
}

# Main execution
function main() {
    load_config
    validate_environment
    run_trivy
    echo "--------------------------------------------------------------------------------"
    run_semgrep
    convert_reports
    check_and_remove "$SONAR_TRIVY"
    check_and_remove "$SONAR_SEMGREP"
    run_sonarscanner
}

main
