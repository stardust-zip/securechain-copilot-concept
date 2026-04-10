import json
from pathlib import Path


def inspect_osv_data(file_path: str):
    with open(file_path, "r") as f:
        data = json.load(f)

    print(f"ID: {data.get('id')}")
    print(f"Summary: {data.get('summary', 'No summary')}")

    # The 'affected' array contains package names and vulnerable versions
    if "affected" in data:
        for item in data["affected"]:
            pkg = item.get("package", {}).get("name")
            print(f"Affected Package: {pkg}")


if __name__ == "__main__":
    # Grab the first json file in the directory to test
    json_files = list(Path("data/osv-npm").glob("*.json"))
    if json_files:
        inspect_osv_data(str(json_files[0]))
    else:
        print("No JSON files found. Did you unzip all.zip?")
