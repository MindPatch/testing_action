import sys
import os

def parse_blacklock_config():
    config_path = "blacklock.yml"
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            return {"name":"Mike"}
    else:
        print("blacklock.yml not found in repository root.")
        return {}

def main(param1, param2):
    # Load blacklock.yml configuration if it exists
    config = parse_blacklock_config()

    # Perform main action logic using parameters and parsed config
    print(f"Running the action with param1: {param1} and param2: {param2}")
    # Use config as needed

if __name__ == "__main__":
    param1 = sys.argv[1]
    param2 = sys.argv[2] if len(sys.argv) > 2 else "No param2 provided"
    main(param1, param2)
