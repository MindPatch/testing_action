#!/bin/sh

# Navigate to the /app/ directory where code and scans will be run
cd /app/

# Check required environment variables
if [ -z "$SONAR_PROJECTKEY" ]; then
    echo "Error: SONAR_PROJECTKEY is not set."
    exit 1
fi

if [ -z "$SONAR_HOST_URL" ]; then
    echo "Error: SONAR_HOST_URL is not set."
    exit 1
fi

if [ -z "$SONAR_TOKEN" ]; then
    echo "Error: SONAR_TOKEN is not set."
    exit 1
fi

# Optional exclude paths
if [ -n "$EXCLUDE" ]; then
    echo "Exclusion paths specified: $EXCLUDE"
    SONAR_EXCLUDE_OPTION="-Dsonar.exclusions=$EXCLUDE"
else
    SONAR_EXCLUDE_OPTION=""
    echo "No exclusion paths specified."
fi

# Run Semgrep and Trivy scans
echo "Running Semgrep and Trivy scans..."
semgrep scan --config=auto --sarif-output=semgrep_result.sarif /github/workspace
trivy fs -f json -o trivy.json /github/workspace
python /usr/local/bin/convert_trivy.py trivy.json > /app/sonar_trivy.json
python /usr/local/bin/convert_semgrep.py semgrep_result.sarif /app/sonar_semgrep.json

# File paths for generated reports
TRIVY_FILE="/app/sonar_trivy.json"
SEMGREP_FILE="/app/sonar_semgrep.json"

# Function to validate JSON report files for non-empty results
check_and_remove() {
    FILE_PATH=$1
    if [ -f "$FILE_PATH" ]; then
        # Run checker.py and capture the output as ITEM_COUNT
        ITEM_COUNT=$(python /usr/local/bin/checker.py "$FILE_PATH")
        
        # Ensure ITEM_COUNT is a number and handle cases where it's not
        if [ "$ITEM_COUNT" -gt 0 ] 2>/dev/null; then
            echo "File $FILE_PATH has valid items."
        else
            echo "File $FILE_PATH has one or no items, removing it."
            rm "$FILE_PATH"
        fi
    fi
}

# Check and remove empty report files if necessary
check_and_remove "$TRIVY_FILE"
check_and_remove "$SEMGREP_FILE"

# Debugging: Print environment variables (excluding sensitive data)
echo "SONAR_PROJECTKEY: ${SONAR_PROJECTKEY}"
echo "SONAR_HOST_URL: ${SONAR_HOST_URL}"
echo "SONAR_TOKEN: (hidden)"

# Determine SonarScanner command based on available reports
if [ -f "$TRIVY_FILE" ] && [ -f "$SEMGREP_FILE" ]; then
    echo "Both sonar_trivy.json and sonar_semgrep.json exist. Running SonarScanner with both reports."
    sonar-scanner \
        -Dsonar.projectKey="$SONAR_PROJECTKEY" \
        -Dsonar.host.url="$SONAR_HOST_URL" \
        -Dsonar.login="$SONAR_TOKEN" \
        $SONAR_EXCLUDE_OPTION \
        -Dsonar.externalIssuesReportPaths="/app/sonar_trivy.json,/app/sonar_semgrep.json"
elif [ -f "$TRIVY_FILE" ]; then
    echo "Only sonar_trivy.json exists. Running SonarScanner with Trivy report."
    sonar-scanner \
        -Dsonar.projectKey="$SONAR_PROJECTKEY" \
        -Dsonar.host.url="$SONAR_HOST_URL" \
        -Dsonar.login="$SONAR_TOKEN" \
        $SONAR_EXCLUDE_OPTION \
        -Dsonar.externalIssuesReportPaths="/app/sonar_trivy.json"
elif [ -f "$SEMGREP_FILE" ]; then
    echo "Only sonar_semgrep.json exists. Running SonarScanner with Semgrep report."
    sonar-scanner \
        -Dsonar.projectKey="$SONAR_PROJECTKEY" \
        -Dsonar.host.url="$SONAR_HOST_URL" \
        -Dsonar.login="$SONAR_TOKEN" \
        $SONAR_EXCLUDE_OPTION \
        -Dsonar.externalIssuesReportPaths="/app/sonar_semgrep.json"
else
    echo "No valid report files found. Running SonarScanner without external issue reports."
    sonar-scanner \
        -Dsonar.projectKey="$SONAR_PROJECTKEY" \
        -Dsonar.host.url="$SONAR_HOST_URL" \
        -Dsonar.login="$SONAR_TOKEN" \
        $SONAR_EXCLUDE_OPTION
fi
