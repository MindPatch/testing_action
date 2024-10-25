import sys
import docker

def run_blacklock_code_scanner(sonar_projectkey, sonar_host_url, sonar_token):
    client = docker.from_env()

    try:
        # Pull the Blacklock Code Scanner image
        print("Pulling Blacklock Code Scanner Docker image...")
        client.images.pull("blacklocksec/code-scanner:latest")

        # Run the container with the specified environment variables
        print("Running Blacklock Code Scanner...")
        container = client.containers.run(
            "blacklocksec/code-scanner:latest",
            remove=True,
            volumes={
                "/github/workspace": {"bind": "/app", "mode": "rw"}
            },
            environment={
                "SONAR_PROJECTKEY": sonar_projectkey,
                "SONAR_HOST_URL": sonar_host_url,
                "SONAR_TOKEN": sonar_token
            },
            detach=True
        )

        # Stream the logs from the container
        for log in container.logs(stream=True):
            print(log.strip().decode("utf-8"))

    except docker.errors.ContainerError as e:
        print(f"Error running Blacklock Code Scanner: {e}")
    except docker.errors.ImageNotFound:
        print("Error: Docker image 'blacklocksec/code-scanner:latest' not found.")
    except docker.errors.APIError as e:
        print(f"Docker API error: {e}")

def main(sonar_projectkey, sonar_host_url, sonar_token):
    run_blacklock_code_scanner(sonar_projectkey, sonar_host_url, sonar_token)

if __name__ == "__main__":
    sonar_projectkey = sys.argv[1]
    sonar_host_url = sys.argv[2]
    sonar_token = sys.argv[3]
    main(sonar_projectkey, sonar_host_url, sonar_token)
