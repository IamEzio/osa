import json
from collections import defaultdict


def analyze_slaps_report(file_obj):
    """
    Parses a SLAPS vulnerability report JSON and structures it by artifact → package → vulnerabilities.
    Args:
        file_obj: Uploaded file object (from Flask request)
    Returns:
        dict: Structured vulnerability data
    """

    data = json.load(file_obj)
    findings = data.get("scanReport", {}).get("findings", [])

    structured_data = defaultdict(lambda: defaultdict(list))

    for finding in findings:
        meta = finding.get("metadata", {})
        artifact = meta.get("Artifact_Name", "Unknown Artifact")
        package = meta.get("Package_Name", "Unknown Package")

        vuln = {
            "Advisory_Name": meta.get("Advisory_Name", "N/A"),
            "Severity": meta.get("Severity", "Unknown"),
            "Package_Version": meta.get("Package_Version", "N/A"),
            "Fix_Version": meta.get("CVE_Fix_Version", "N/A"),
            "Advisory_Link": meta.get("Advisory_Link", "#"),
            "Description": finding.get("details", "").strip().split("\n")[0:5],
        }

        structured_data[artifact][package].append(vuln)

    # print(f"[SLAPS Analyzer] Parsed {len(findings)} findings from report.")
    return structured_data
