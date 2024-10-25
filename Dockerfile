# Use a Python 3.12 base image for consistency
FROM python:3.12-slim

# Create a non-root user and set up necessary directories
RUN useradd -m -d /home/worker -s /bin/bash worker

# Set the workspace directory for the GitHub Action
WORKDIR /github/workspace

# Copy dependencies separately to cache better
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Switch to the non-root user
USER worker

# Run the action with the main script
ENTRYPOINT ["python", "main.py"]
