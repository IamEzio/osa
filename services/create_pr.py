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
from services.pom_updater import remediate_vulnerabilities

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install with: pip install requests", file=sys.stderr)
    sys.exit(2)

def run(cmd: list[str], cwd: Optional[str] = None, capture_output: bool = False) -> subprocess.CompletedProcess:
    """Run command and raise on non-zero exit (mimics set -e)."""
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

def find_tags_for_commit(baseurl, project, repo, commit_id, auth=None, verify_ssl=True, page_size=25, verbose=False):
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

def create_PR(
    bitbucket_base_url: str = "https://bitbucket.oci.oraclecorp.com",
    project_key: str = "CSI",
    repo_name: str = "personalization-service",
    clone_url: str = "ssh://git@bitbucket.oci.oraclecorp.com:7999/csi/personalization-service.git",
    branch_prefix: str = "test-osa-vulnerability-fix",
    poll_interval: int = 600,
    auth_header: Optional[str] = None,
    auth: Optional[str] = os.environ.get("BITBUCKET_AUTH_SIMPLE"),
    no_cleanup: bool = False,
    workdir: str = ".",
):
    headers, requests_auth = parse_auth(auth_header, auth)
    branch_name = f"{branch_prefix}-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M')}"
    repo_dir = os.path.join(workdir, repo_name)
    safe_rmdir(repo_dir)
    try:
        print("📥 Cloning repository...")
        run(["git", "clone", clone_url], cwd=workdir)
    except subprocess.CalledProcessError as e:
        print("❌ Git clone failed:", e, file=sys.stderr)
        sys.exit(1)
    try:
        print("cd", repo_dir)
        print(f"🌿 Creating new branch: {branch_name}")
        run(["git", "checkout", "-b", branch_name], cwd=repo_dir)
    except subprocess.CalledProcessError as e:
        print("❌ Git checkout/create branch failed:", e, file=sys.stderr)
        sys.exit(1)

    remediate_vulnerabilities()
    try:
        run(["git", "add", "."], cwd=repo_dir)
    except Exception as e:
        print("❌ Failed to write or add test file:", e, file=sys.stderr)
        sys.exit(1)
    try:
        run(["git", "commit", "-m", f"Test Automated commit for {branch_name}"], cwd=repo_dir)
    except subprocess.CalledProcessError as e:
        out = e.stdout or ""
        err = e.stderr or ""
        if "nothing to commit" in out.lower() or "nothing to commit" in err.lower():
            print("⚠️ Nothing to commit (file may be unchanged). Proceeding.")
        else:
            print("❌ Git commit failed:", e, file=sys.stderr)
            sys.exit(1)
    try:
        run(["git", "push", "origin", branch_name], cwd=repo_dir)
    except subprocess.CalledProcessError as e:
        print("❌ Git push failed:", e, file=sys.stderr)
        sys.exit(1)
    print("🚀 Creating Pull Request from", branch_name, "to master...")
    pr_payload = {
        "title": f"Test Automated PR: {branch_name}",
        "description": "This test PR was created automatically by build monitor script.",
        "state": "OPEN",
        "open": True,
        "closed": False,
        "fromRef": {
            "id": f"refs/heads/{branch_name}",
            "repository": {
                "slug": repo_name,
                "project": {"key": project_key},
            },
        },
        "toRef": {
            "id": "refs/heads/master",
            "repository": {
                "slug": repo_name,
                "project": {"key": project_key},
            },
        },
        "locked": False,
    }
    pr_url = f"{bitbucket_base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_name}/pull-requests"
    try:
        resp = requests.post(pr_url, headers=headers, auth=requests_auth, json=pr_payload, timeout=30, verify=True)
    except Exception as e:
        print("❌ Failed to create pull request (network error):", e, file=sys.stderr)
        if not no_cleanup:
            safe_rmdir(repo_dir)
        sys.exit(1)
    if not resp.ok:
        print("⚠️ Failed to create Pull Request. Status:", resp.status_code)
        try:
            print("Response:", resp.text)
        except Exception:
            pass
    else:
        try:
            pr_json = resp.json()
            pr_link = ""
            if isinstance(pr_json.get("links"), dict):
                self_links = pr_json["links"].get("self", [])
                if self_links:
                    pr_link = self_links[0].get("href", "")
            if pr_link:
                print("✅ Pull Request created successfully:", pr_link)
            else:
                print("✅ Pull Request created, but could not extract link from response.")
        except Exception:
            print("✅ Pull Request created (response not JSON or missing expected fields).")
    branches_url = (
        f"{bitbucket_base_url}/rest/api/1.0/projects/{project_key}/repos/{repo_name}/branches"
        f"?filterText={branch_name}"
    )
    try:
        resp = requests.get(branches_url, headers=headers, auth=requests_auth, timeout=30, verify=True)
        resp.raise_for_status()
        obj = resp.json()
        latest_commit = None
        values = obj.get("values", [])
        if values:
            latest_commit = values[0].get("latestCommit")
        if not latest_commit:
            print(f"❌ Failed to retrieve latest commit ID for branch {branch_name}")
            if not no_cleanup:
                safe_rmdir(repo_dir)
            sys.exit(1)
        print("✅ Latest commit:", latest_commit)
    except Exception as e:
        print("❌ Error fetching branch info:", e, file=sys.stderr)
        if not no_cleanup:
            safe_rmdir(repo_dir)
        sys.exit(1)
    build_status_url = f"{bitbucket_base_url}/rest/build-status/latest/commits/{latest_commit}"
    print("⏳ Monitoring build status for commit...")
    terminal_states = {"SUCCESSFUL", "FAILED", "STOPPED"}
    try:
        while True:
            try:
                resp = requests.get(build_status_url, headers=headers, auth=requests_auth, timeout=30, verify=True)
                resp.raise_for_status()
                data = resp.json()
                state = None
                values = data.get("values", [])
                if values:
                    state = values[0].get("state")
                if not state:
                    print("⚠️ Build status not available yet. Response:", json.dumps(data)[:1000])
                else:
                    print(f"⏱️  Current status: {state} ({datetime.datetime.utcnow().isoformat()}Z)")
                    if state in terminal_states:
                        print("🏁 Build reached terminal state:", state)
                        break
                print(f"🕒 Waiting for {poll_interval//60} minutes before next check...")
                time.sleep(poll_interval)
            except requests.HTTPError as he:
                print("⚠️ HTTP error while fetching build status:", he)
                time.sleep(poll_interval)
            except Exception as e:
                print("⚠️ Error while fetching build status:", e)
                time.sleep(poll_interval)
    finally:
        if state == "SUCCESSFUL":
            artifact_id = find_tags_for_commit(bitbucket_base_url, project_key, repo_name, latest_commit, requests_auth)
            print(f"artifact_id found is: {artifact_id}")
        if not no_cleanup:
            safe_rmdir(repo_dir)
    print("✅ Done!")

def main():
    parser = argparse.ArgumentParser(
        description="Clone repo, create branch, commit, push, create PR and monitor build status."
    )
    parser.add_argument("--bitbucket-base-url", default=os.environ.get("BITBUCKET_BASE_URL", "https://bitbucket.oci.oraclecorp.com"))
    parser.add_argument("--project-key", default=os.environ.get("PROJECT_KEY", "CSI"))
    parser.add_argument("--repo-name", default=os.environ.get("REPO_NAME", "personalization-service"))
    parser.add_argument("--clone-url", default=os.environ.get("CLONE_URL", "ssh://git@bitbucket.oci.oraclecorp.com:7999/csi/personalization-service.git"))
    parser.add_argument("--branch-prefix", default=os.environ.get("BRANCH_PREFIX", "test-osa-vulnerability-fix"))
    parser.add_argument("--poll-interval", type=int, default=int(os.environ.get("POLL_INTERVAL", "600")))
    parser.add_argument("--auth-header", help="Full header string, e.g. 'Cookie: ATLSSO=XXXX' or 'Authorization: Basic ...' (or set BITBUCKET_AUTH env var)", default=os.environ.get("BITBUCKET_AUTH"))
    parser.add_argument("--auth", help="username:password (will use HTTP Basic auth).", default=os.environ.get("BITBUCKET_AUTH_SIMPLE"))
    parser.add_argument("--no-cleanup", action="store_true", help="Do not delete the cloned repo directory at the end (for debugging).")
    parser.add_argument("--workdir", help="Working directory to clone into. Default: current directory", default=".")

    args = parser.parse_args()
    create_PR(
        bitbucket_base_url=args.bitbucket_base_url,
        project_key=args.project_key,
        repo_name=args.repo_name,
        clone_url=args.clone_url,
        branch_prefix=args.branch_prefix,
        poll_interval=args.poll_interval,
        auth_header=args.auth_header,
        auth=args.auth,
        no_cleanup=args.no_cleanup,
        workdir=args.workdir
    )

def create_bitbucket_pr():
    create_PR()

if __name__ == "__main__":
    main()