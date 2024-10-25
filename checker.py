import os
import json

def check_and_remove(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Check if data contains more than one item
            if isinstance(data, list) and len(data) > 1:
                print(f"{file_path} has more than one item.")
            else:
                print(f"{file_path} has one or no items, removing it.")
                os.remove(file_path)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error with {file_path}: {e}")

def main():
    trivy_file = '/app/sonar_trivy.json'
    semgrep_file = '/app/sonar_semgrep.json'
    
    # Check and remove files if necessary
    check_and_remove(trivy_file)
    check_and_remove(semgrep_file)

if __name__ == '__main__':
    main()
