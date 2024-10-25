# Stage 1: Use Trivy base image
FROM aquasec/trivy:0.53.0 AS trivy

# Stage 2: Python environment with Semgrep
FROM python:3.9-alpine AS python-env
WORKDIR /app
RUN apk add --no-cache git curl build-base
RUN pip install --upgrade pip

# Install Semgrep
RUN pip install semgrep --target /usr/local/lib/python3.9/site-packages
RUN ln -s /usr/local/lib/python3.9/site-packages/semgrep/semgrep /usr/local/bin/semgrep

# Stage 3: SonarScanner with all dependencies
FROM sonarsource/sonar-scanner-cli:5.0.1
USER root

# Install required dependencies
RUN apk add --no-cache python3 py3-pip build-base
RUN pip install semgrep emoji --break-system-packages

# Copy files from previous stages
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=python-env /app/ /app/

# Copy necessary scripts
COPY run.sh /usr/local/bin/run.py
COPY convert_trivy.py /usr/local/bin/convert_trivy.py
COPY convert_semgrep.py /usr/local/bin/convert_semgrep.py
COPY checker.py /usr/local/bin/checker.py
ENV PATH="$PATH:/usr/local/bin"

# Define the working directory and mount the volume for source code access
WORKDIR /app
VOLUME ["/app"]

# Set entrypoint to run the main script
ENTRYPOINT ["python", "/usr/local/bin/run.py"]
