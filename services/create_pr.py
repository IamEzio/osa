#!/usr/bin/env python3
from __future__ import annotations
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Dict, Optional, Tuple
from services.pom_updater import remediate_vulnerabilities, upgrade_all_boms_to_latest
from services.release_automation import create_release

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install with: pip install requests", file=sys.stderr)
    sys.exit(2)

def run(cmd: list[str], cwd: Optional[str] = None, capture_output: bool = False):
    print("⤵️  Running:", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=capture_output, text=True)


def parse_auth(auth_header: Optional[str], auth_simple: Optional[str]) -> Tuple[Dict[str, str], Optional[requests.auth.AuthBase]]:
    headers: Dict[str, str] = {}
    auth = None
    if auth_header:
        for line in auth_header.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
            else:
                headers["Authorization"] = line.strip()
    elif auth_simple:
        if ":" in auth_simple:
            username, password = auth_simple.split(":", 1)
            auth = requests.auth.HTTPBasicAuth(username, password)
        else:
            headers["Authorization"] = auth_simple
    return headers, auth


def safe_rmdir(path: str):
    if os.path.isdir(path):
        print(f"🧽 Deleting directory: {path}")
        shutil.rmtree(path)

def find_tags_for_commit(baseurl, project, repo, commit_id, auth=None, verify_ssl=True, page_size=25, verbose=True):
    """
    Iterate through tag pages and return a list of tag objects that point to commit_id.
    """
    matches = []
    start = 0
    headers = {"Accept": "application/json"}

    while True:
        url = f"{baseurl}/rest/api/1.0/projects/{project}/repos/{repo}/tags"
        params = {
            "orderBy": "MODIFICATION",
            "start": start,
            "limit": page_size
        }
        if verbose:
            print(f"Requesting: {url} params={params}")

        try:
            resp = requests.get(url, params=params, headers=headers, auth=auth, timeout=30, verify=True)
        except requests.RequestException as e:
            print(f"Network error while requesting tags: {e}", file=sys.stderr)
            return matches

        if resp.status_code == 401 or resp.status_code == 403:
            print(f"Authentication/Authorization failed (HTTP {resp.status_code}). Check credentials/permissions.", file=sys.stderr)
            return matches

        if not resp.ok:
            print(f"Failed to fetch tags: HTTP {resp.status_code} - {resp.text}", file=sys.stderr)
            return matches

        try:
            data = resp.json()
            print(f"\nData fetching TAGS: {data}")
        except ValueError:
            print("Failed to decode JSON response from Bitbucket.", file=sys.stderr)
            return matches

        # 'values' is common; sometimes API can return 'tags' or similar - be defensive
        tag_list = data.get("values") or data.get("tags") or []
        if verbose:
            print(f"Got {len(tag_list)} tags in this page.")

        for tag in tag_list:
            # Look for likely fields that contain the pointed commit id
            tag_commit = None
            # Some tag objects have structure: { "id": "refs/tags/v1.0", "displayId": "v1.0", "latestCommit": "...", ... }
            # Some older/other endpoints might use 'latestRevision' instead
            tag_commit = tag.get("latestCommit") or tag.get("latestRevision")

            # Some implementations nest commit under 'commit' or 'latestChangeset'
            if not tag_commit:
                # Example variants
                if isinstance(tag.get("commit"), dict):
                    tag_commit = tag["commit"].get("id") or tag["commit"].get("hash")
                tag_commit = tag_commit or tag.get("latestChangeset")

            if tag_commit and tag_commit.startswith(commit_id):
                # exact or prefix match (in case user gave short sha)
                print(f"tag details: {tag}")
                artifact_id = tag.get("displayId")
                print(f"tag matched, artifact version: {artifact_id}")
                return artifact_id

        # Pagination termination logic
        # Bitbucket Server APIs commonly return 'isLastPage' and 'nextPageStart'
        is_last = data.get("isLastPage")
        next_start = None
        if "nextPageStart" in data:
            next_start = data.get("nextPageStart")
        elif "start" in data and "size" in data and isinstance(data.get("size"), int):
            # fallback: advance by page_size until returned list < page_size
            next_start = start + data.get("size", len(tag_list))

        if is_last is True:
            if verbose:
                print("Reached last page (isLastPage=True).")
            break

        # If nextPageStart present, use it
        if next_start is not None and next_start > start:
            start = next_start
        else:
            # If no explicit next, stop when we got fewer tags than requested or none
            if not tag_list or len(tag_list) < page_size:
                if verbose:
                    print("No more pages (received fewer items than page_size).")
                break
            start += page_size

        if start > 1000:
            print("pagination reached beyond threshold of 40 pages!!!")
            break

        # small delay to be polite with the server if iterating many pages
        time.sleep(0.1)

    return None

# -------------------------------------------------
#  PHASE 1: Create PR and return PR details
# -------------------------------------------------
def create_bitbucket_pr(
    artifact = None,
    vuln_data = {},
    finding_indexes = [],
    configs = {},
    repo_name = ""
) -> dict:
    try:
        bitbucket_base_url = configs["BITBUCKET_BASE_URL"]
        branch_prefix = configs['BRANCH_PREFIX']
        auth_simple = os.environ.get('BITBUCKET_AUTH_SIMPLE')
        if(repo_name == ""):
            repo_name = configs['ARTIFACT_MAP'][artifact]
        repo_config = configs['REPOS'][repo_name]
        project_key = repo_config["PROJECT_KEY"]
        clone_url = repo_config['CLONE_URL']
    except Exception as e:
        print("\n[Error]: Config values are missing in config.json")
        print(f"Exception: {type(e).__name__}: {e}\n")
        return
    
    workdir = "."
    headers, requests_auth = parse_auth(None, auth_simple)
    branch_name = f"{branch_prefix}-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M')}"
    repo_dir = os.path.join(workdir, repo_name)

    print("Starting PR creation process")

    safe_rmdir(repo_dir)
    run(["git", "clone", clone_url], cwd=workdir)
    run(["git", "checkout", "-b", branch_name], cwd=repo_dir)

    if artifact is None:
        upgrade_all_boms_to_latest(repo_name=repo_name)
        description_lines = [
            "Automated PR created by Oracle Security Assistant",
            "",
            "Updates dropwizard-service-bom and oci-internal-bom to their latest version"
        ]

        title = "Automated OSA upgarde for dropwizard-service-bom and oci-internal-bom"
    else:
        remediate_vulnerabilities(artifact=artifact, vulnerability_data=vuln_data[artifact], finding_indexes=finding_indexes)
        advisory_names = []
        description_lines = [
            "Automated PR created by Oracle Security Assistant",
            ""
        ]

        for package_name, vulns in vuln_data.items():
            for vuln in vulns:
                advisory_name = vuln.get("Advisory_Name", "N/A")
                advisory_names.append(advisory_name)
                package_version = vuln.get("Package_Version", "N/A")
                advisory_link = vuln.get("Advisory_Link", "#")
                description_lines.append(
                    f"**Advisory:** {advisory_name}\n"
                    f"**Package:** {package_name}\n"
                    f"**Package Version:** {package_version}\n"
                    f"**Advisory Link:** {advisory_link}\n"
            )

        title = "Automated OSA remediation for " + ", ".join(advisory_names)

    run(["git", "add", "."], cwd=repo_dir)
    try:
        run(["git", "commit", "-m", f"Automated OSA remediation for {branch_name}"], cwd=repo_dir)
    except subprocess.CalledProcessError:
        print("⚠️ Nothing to commit — proceeding anyway.")
        return {
            "branch_name": None,
            "pr_link": None,
            "latest_commit": None
        }

    run(["git", "push", "origin", branch_name], cwd=repo_dir)

    pr_payload = {
        "title": title,
        "description": "\n".join(description_lines),
        "fromRef": {
            "id": f"refs/heads/{branch_name}",
            "repository": {"slug": repo_name, "project": {"key": project_key}}
        },
        "toRef": {
            "id": "refs/heads/master",
            "repository": {"slug": repo_name, "project": {"key": project_key}}
        },
    }

    pr_url = f"{bitbucket_base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_name}/pull-requests"
    resp = requests.post(pr_url, headers=headers, auth=requests_auth, json=pr_payload, timeout=30, verify=True)
    if not resp.ok:
        print("⚠️ Failed to create PR:", resp.text)
        raise RuntimeError("Failed to create PR")

    pr_json = resp.json()
    pr_link = pr_json.get("links", {}).get("self", [{}])[0].get("href", "")

    # Get commit ID
    branches_url = f"{bitbucket_base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_name}/branches?filterText={branch_name}"
    resp = requests.get(branches_url, headers=headers, auth=requests_auth, timeout=30)
    latest_commit = resp.json().get("values", [{}])[0].get("latestCommit")

    # Cleanup
    safe_rmdir(repo_dir)

    return {
        "branch_name": branch_name,
        "pr_link": pr_link,
        "latest_commit": latest_commit
    }


# -------------------------------------------------
#  PHASE 2: Monitor build & trigger release
# -------------------------------------------------
def monitor_build_and_release(
    artifact = None,
    commit_id: str = "",
    configs = {},
    repo_name = ""
):
    try:
        bitbucket_base_url = configs["BITBUCKET_BASE_URL"]
        if(repo_name == ""):
            repo_name = configs['ARTIFACT_MAP'][artifact]
        repo_config = configs['REPOS'][repo_name]
        project_key = repo_config["PROJECT_KEY"]
        auth_simple = os.environ.get('BITBUCKET_AUTH_SIMPLE')
        poll_interval = configs['BUILD_POLL_INTERVAL']
    except (KeyError, IndexError) as e:
        print("\n[Error]: Config values are missing in config.json")
        print(f"Exception: {type(e).__name__}: {e}\n")
        return
    
    headers, requests_auth = parse_auth(None, auth_simple)
    build_status_url = f"{bitbucket_base_url}/rest/build-status/latest/commits/{commit_id}"
    terminal_states = {"SUCCESSFUL", "FAILED", "STOPPED"}

    print(f"⏳ Monitoring build for commit {commit_id}...")
    while True:
        resp = requests.get(build_status_url, headers=headers, auth=requests_auth, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        print(f"\ndata from BUILD URL: {data}")
        state = (data.get("values") or [{}])[0].get("state")
        print(f"⏱️  Current status: {state}")
        if state in terminal_states:
            print("🏁 Build reached terminal state:", state)
            break
        time.sleep(int(poll_interval))

    if state == "SUCCESSFUL":
        artifact_id = find_tags_for_commit(bitbucket_base_url, project_key, repo_name, commit_id, requests_auth)
        print(f"✅ Artifact found: {artifact_id}")
        # create_release(artifact_id)
        return {"status": "success", "artifact_id": artifact_id}

    return {"status": "failed", "artifact_id": None}
