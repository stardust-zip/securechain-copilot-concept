import json
from pathlib import Path


def extract_osv_vulnerabilities(directory_path: str) -> list[dict]:
    """Parses OSV JSON files and extracts clean vulnerability data."""
    vulnerabilities = []
    path = Path(directory_path)

    for json_file in path.glob("*.json"):
        with open(json_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                continue  # Skip broken files

            # Extract the core signal
            vuln_id = data.get("id", "UNKNOWN_ID")
            summary = data.get("summary", "No summary provided.")
            details = data.get("details", "No details provided.")

            # Extract affected packages
            affected_packages = []
            if "affected" in data:
                for item in data["affected"]:
                    pkg_name = item.get("package", {}).get("name")
                    if pkg_name:
                        affected_packages.append(pkg_name)

            # Only keep it if it affects a specific package
            if affected_packages:
                vulnerabilities.append(
                    {
                        "id": vuln_id,
                        "summary": summary,
                        "details": details,
                        "packages": list(set(affected_packages)),  # Deduplicate
                    }
                )

    return vulnerabilities


def extract_sbom_components(file_path: str) -> list[dict]:
    """Extracts package names and versions from a CycloneDX SBOM."""
    components = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for component in data.get("components", []):
            name = component.get("name")
            version = component.get("version")
            if name and version:
                components.append({"name": name, "version": version})
    except FileNotFoundError:
        print(f"SBOM not found at {file_path}. Did you run Syft?")

    return components


def generate_knowledge_chunks(vulnerabilities: list[dict]) -> list[dict]:
    """Formats vulnerability data into text chunks ready for embedding."""
    chunks = []
    for v in vulnerabilities:
        # Create a semantically dense text block
        text_chunk = f"Vulnerability ID: {v['id']}\n"
        text_chunk += f"Affected Packages: {', '.join(v['packages'])}\n"
        text_chunk += f"Summary: {v['summary']}\n"
        text_chunk += f"Details: {v['details']}"

        # We keep the raw metadata separate from the text chunk!
        # This is critical for Phase 3 filtering.
        chunks.append(
            {
                "text": text_chunk,
                "metadata": {
                    "id": v["id"],
                    "type": "knowledge",
                    # We store the first package as a simple string for exact-match filtering later
                    "primary_package": v["packages"][0] if v["packages"] else "unknown",
                },
            }
        )
    return chunks


if __name__ == "__main__":
    print("--- 1. Testing Knowledge Extraction (OSV) ---")
    vulns = extract_osv_vulnerabilities("data/osv-npm")
    print(f"✅ Extracted {len(vulns)} vulnerabilities.")
    if vulns:
        print(f"Sample Vuln: {vulns[0]['id']} affecting {vulns[0]['packages']}")

    print("\n--- 2. Testing Context Extraction (SBOM) ---")
    sbom_data = extract_sbom_components("data/sbom.json")
    print(f"✅ Extracted {len(sbom_data)} packages from SBOM.")
    if sbom_data:
        print(f"Sample Package: {sbom_data[0]['name']} @ {sbom_data[0]['version']}")

    print("\n--- 3. Testing Semantic Chunking ---")
    if vulns:
        chunks = generate_knowledge_chunks(vulns)
        print(f"✅ Generated {len(chunks)} text chunks ready for vectorization.")
        print("\n[SAMPLE TEXT TO BE EMBEDDED]")
        print(chunks[0]["text"])
        print("\n[ATTACHED METADATA FOR FILTERING]")
        print(chunks[0]["metadata"])
