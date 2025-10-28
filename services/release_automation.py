import subprocess
import requests
import copy

def get_shepherd_config_id(shepherd_flock_url, jwt_token):
    """Returns the latest eligible Shepherd configId with branchName 'master', or None."""
    configs_url = shepherd_flock_url.rstrip('/') + '/configs'
    headers = {"Authorization": f"Bearer {jwt_token}"}
    resp = requests.get(configs_url, headers=headers)
    if not resp.ok:
        print(f"Error fetching Shepherd configs: {resp.status_code} {resp.text}")
        return None
    configs = resp.json()
    # Filter for branchName == "master", not archived/excluded, Compiled
    candidates = [
        c for c in configs
        if (
            not c.get("isArchived") and
            not c.get("isExcluded") and
            c.get("status") == "Compiled" and
            c.get("branchName") == "master"
        )
    ]
    # Sort by completedAt (latest first)
    if candidates:
        candidates.sort(key=lambda c: c.get("completedAt", ""), reverse=True)
        return candidates[0]["id"]
    else:
        print("No suitable compiled configs found with branchName 'master'.")
        return None

import subprocess
import requests
import copy

def create_release(artifact = None, artifact_id = "", configs = {}, repo_name = ""):
    ssh_command = [
        "ssh", "operator-access-token.svc.ad1.r2", "generate", "--mode", "jwt"
    ]
    try:
        jwt_token = subprocess.check_output(ssh_command, text=True).strip()
    except Exception as e:
        print("Failed to generate JWT token. Error:", e)
        return

    try:
        if(repo_name == ""):
            repo_name = configs['ARTIFACT_MAP'][artifact]
        repo_config = configs['REPOS'][repo_name]
        shepherd_flock_url = repo_config['SHEPHERD_FLOCK_URL']
        payload = copy.deepcopy(repo_config['SHEPHERD_PAYLOAD'])
    except (KeyError, IndexError) as e:
        print("\n[Error]: Config values are missing in config.json")
        print(f"Exception: {type(e).__name__}: {e}\n")
        return

    # ----- Populate configId -----
    config_id = get_shepherd_config_id(shepherd_flock_url, jwt_token)
    if not config_id:
        print("Cannot continue without valid configId.")
        return
    payload['configId'] = config_id

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    }

    # Update artifact versions
    for art in payload.get('artifacts', []):
        if art.get('version', None) == "":
            art['version'] = artifact_id

    releases_url = shepherd_flock_url.rstrip('/') + "/releases"
    response = requests.post(releases_url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    status = "success" if 200 <= response.status_code < 300 else "failed"

    try:
        data = response.json()
        print("Shepherd API response:", data)
        release_id = data.get("id")
        release_name = data.get("releaseName")
        if release_id:
            release_link = f"{releases_url}/{release_id}"
        else:
            release_link = None
    except Exception as exc:
        print("Failed to parse JSON from Shepherd API.")
        print(response.text)
        release_link = None
        release_name = None

    return {
        "status": status,
        "release_link": release_link,
        "release_name": release_name,
    }

