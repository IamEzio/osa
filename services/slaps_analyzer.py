import json
from collections import defaultdict


def analyze_slaps_report(data):
    """
    Parses a SLAPS vulnerability report JSON and structures it by artifact → package → vulnerabilities.
    Args:
        data
    Returns:
        dict: Structured vulnerability data
    """

    findings = data.get("scanReport", {}).get("findings", [])

    structured_data = defaultdict(lambda: list)
    meta = findings[0].get("metadata", {})
    artifact = meta.get("Artifact_Name", "Unknown Artifact")

    structured_data[artifact] = findings

    return structured_data
