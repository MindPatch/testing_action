import docker
import argparse
from docker.errors import ContainerError, ImageNotFound, APIError

def run_blacklock_code_scanner(sonar_projectkey, sonar_host_url, sonar_token, exclude=""):
    # Initialize Docker client
    client = docker.from_env()

    print("🐳 Starting Blacklock Code Scanner...")

    try:
        # Pull the Docker image
        print("🔄 Pulling Blacklock Code Scanner Docker image...")
        client.images.pull("blacklocksec/code-scanner:latest")
        print("✅ Image pulled successfully!")

        # Prepare environment variables for the Docker container
        env_vars = {
            "SONAR_PROJECTKEY": sonar_projectkey,
            "SONAR_HOST_URL": sonar_host_url,
            "SONAR_TOKEN": sonar_token
        }
        if exclude:
            env_vars["SONAR_EXCLUDE"] = exclude
            print(f"📂 Exclude paths: {exclude}")

        # Run the Docker container
        print("🚀 Running Blacklock Code Scanner container...")
        container = client.containers.run(
            "blacklocksec/code-scanner:latest",
            remove=True,
            volumes={
                "/github/workspace": {"bind": "/app", "mode": "rw"}
            },
            environment=env_vars,
            detach=True
        )

        # Stream the container logs in real-time
        print("📡 Streaming logs from the scanner:")
        for log in container.logs(stream=True):
            print(f"🔹 {log.strip().decode('utf-8')}")

        print("🎉 Scan completed successfully!")

    except ImageNotFound:
        print("❌ Error: Docker image 'blacklocksec/code-scanner:latest' not found. Please check the image name or tag.")
        exit(1)
    except ContainerError as e:
        print(f"💥 Container Error: {e}. The scanner failed to execute correctly.")
        exit(1)
    except APIError as e:
        print(f"🛑 Docker API Error: {e}. Please check your Docker setup and network connection.")
        exit(1)
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}. Please investigate further.")
        exit(1)
    finally:
        print("🧹 Cleanup complete.")

def main():
    parser = argparse.ArgumentParser(description="Run Blacklock Code Scanner with SonarQube integration.")
    parser.add_argument("--sonar_projectkey", required=True, help="SonarQube project key.")
    parser.add_argument("--sonar_host_url", required=True, help="SonarQube host URL.")
    parser.add_argument("--sonar_token", required=True, help="SonarQube authentication token.")
    parser.add_argument("--exclude", default="", help="Comma-separated list of paths to exclude from the scan.")

    # Parse arguments
    args = parser.parse_args()

    print("📝 Starting the Blacklock Code Scanner workflow...")
    # Run the scanner with provided arguments
    run_blacklock_code_scanner(
        sonar_projectkey=args.sonar_projectkey,
        sonar_host_url=args.sonar_host_url,
        sonar_token=args.sonar_token,
        exclude=args.exclude
    )

if __name__ == "__main__":
    main()
