import sys
import yaml
import os

def parse_blacklock_config():
    config_path = "blacklock.yml"  # Access directly in /github/workspace
    if os.path.exists(config_path):
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
            print(f"Parsed configuration: {config}")
            return config
    else:
        print("blacklock.yml not found.")
        return {}

def main(param1, param2):
    config = parse_blacklock_config()
    print(f"Running with param1: {param1} and param2: {param2}")
    # Perform main action logic here

if __name__ == "__main__":
    param1 = sys.argv[1]
    param2 = sys.argv[2] if len(sys.argv) > 2 else "No param2 provided"
    main(param1, param2)
