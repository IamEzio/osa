from flask import Flask, render_template, jsonify, request, redirect, url_for
from services.slaps_analyzer import analyze_slaps_report
from services.onboard_services import create_service
from services.create_pr import create_bitbucket_pr, monitor_build_and_release
from services.release_automation import create_release

import os
import threading
import json

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def load_configs():
    with open("./configs.json") as f:
        data = json.load(f)
        return data
    return None

# App Configurations
configs = load_configs()

# Temporary in-memory storage
analyzed_reports = {}  # { artifact_name: [findings] }
build_status_map = {}  # { artifact_name: {'status': '...', 'message': '...'} }


# --------------------------
#  HOME & SLAPS ANALYZER
# --------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upgrade_boms')
def upgrade_boms():
    repo_names = list(configs['REPOS'].keys())
    return render_template('upgrade_boms.html', repo_names=repo_names)

@app.route('/api/upgrade_boms', methods=['POST'])
def upgrade_boms_api():
    data = request.get_json()
    all_flag = data.get("all", False)
    repo_names = []
    results = {}

    if all_flag:
        repo_names = list(configs['REPOS'].keys())
    else:
        repo_name = data.get('repo_name')
        if not repo_name or repo_name not in configs['REPOS']:
            return jsonify({"error": f"Unknown repo: {repo_name}"}), 400
        repo_names = [repo_name]

    def background_upgrade_task(repos):
        for repo in repos:
            # Initialize status
            build_status_map[repo] = {
                'status': 'creating_pr',
                'pr_link': None,
                'branch_name': None,
                'build': 'pending',
                'dev_release_name': None,
                'dev_release_link': None,
                'message': 'Starting PR creation...'
            }
            try:
                pr_info = create_bitbucket_pr(repo_name=repo, configs=configs)
                if not pr_info or not pr_info.get('pr_link'):
                    build_status_map[repo]['status'] = 'failed'
                    build_status_map[repo]['message'] = 'Failed to create PR'
                    results[repo] = "failed: PR not created"
                    continue

                print(pr_info)
                # Update with PR info
                build_status_map[repo].update({
                    'status': 'OPEN',
                    'pr_link': pr_info.get('pr_link'),
                    'branch_name': pr_info.get('branch_name'),
                    'build': 'IN PROGRESS',
                    'message': 'PR created, build in progress...'
                })

                # Monitor build and trigger release
                build_result = monitor_build_and_release(
                    repo_name=repo,
                    commit_id=pr_info.get('latest_commit'),
                    configs=configs
                )
                if build_result.get('status') == 'success':
                    build_status_map[repo].update({
                        'build': 'SUCCESSFUL',
                        'dev_release_name': 'IN PROGRESS',
                        'message': 'Build successful; release creation in progress'
                    })
                    # Trigger release (if needed for BOM PRs)
                    release_result = create_release(
                        repo_name=repo,
                        artifact_id=build_result.get('artifact_id'),
                        configs=configs
                    )
                    if release_result.get('status') == 'success':
                        build_status_map[repo].update({
                            'build': 'SUCCESSFUL',
                            'dev_release_name': release_result.get('release_name'),
                            'dev_release_link': release_result.get('release_link'),
                            'message': 'Dev release created'
                        })
                else:
                    build_status_map[repo].update({
                        'build': 'failed',
                        'dev_release_name': None,
                        'dev_release_link': None,
                        'message': 'Build failed'
                    })
            except Exception as e:
                build_status_map[repo].update({
                    'status': 'failed',
                    'message': str(e)
                })
                results[repo] = f"failed: {e}"
            else:
                results[repo] = "success"

    threading.Thread(target=background_upgrade_task, args=(repo_names,), daemon=True).start()
    return jsonify({"status": "started", "repos": repo_names})

@app.route('/analyze_slaps', methods=['GET'])
def analyze_slaps_form():
    return render_template('analyze_slaps.html')

@app.route('/analyze', methods=['POST'])
def analyze_slaps():
    """Endpoint to analyze uploaded SLAPS report"""
    global analyzed_reports
    if 'report' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['report']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'vulnerability_input.json')
    file.seek(0)
    file.save(file_path)
    # print(f"\nFile: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        structured_data = analyze_slaps_report(data)
        # Cache report in memory for remediation view
        analyzed_reports = structured_data
        # print(structured_data)
        return jsonify(structured_data)
    except Exception as e:
        print("Error analyzing report:", e)
        return jsonify({"error": str(e)}), 500

# --------------------------
#  REMEDIATION FLOW
# --------------------------

@app.route('/remediate/<artifact>')
def remediate_page(artifact):
    return render_template('remediate.html', artifact_name=artifact)

@app.route('/api/remediate', methods=['POST'])
def api_remediate():
    """Render the remediation page for a specific artifact and kick off PR creation job."""
    # If artifact not analyzed, show page but with no vulnerabilities (or 404)
    # print(f"REPORTS\n\n: {analyzed_reports}")
    data = request.get_json()
    artifact = data['artifact']
    finding_indexes = data['finding_indexes']
    # print(f"\n\nartifact: {artifact} \n\n findings_indexes: {finding_indexes}")
    # If a job already running or finished for this artifact, do not start a duplicate
    state = build_status_map.get(artifact)
    if state is None or state.get("status") == "unknown":
        # Initialize state
        build_status_map[artifact] = {
            'status': 'creating_pr',   # other states: open, failed, done
            'pr_link': None,
            'branch_name': None,
            'build': 'pending',        # pending / in_progress / successful / failed
            'dev_release_name': None,
            'dev_release_link': None,
            'message': 'Starting PR creation...'
        }

        def background_remediate_task():
            try:
                # PHASE 1: create PR (returns dict with pr_link and latest_commit)
                pr_info = create_bitbucket_pr(
                    artifact = artifact,
                    vuln_data = analyzed_reports,
                    finding_indexes = finding_indexes,
                    configs = configs
                )
                if(pr_info.get('pr_link') == None):
                    return

                # update state with PR info
                build_status_map[artifact].update({
                    'status': 'OPEN',
                    'pr_link': pr_info.get('pr_link'),
                    'branch_name': pr_info.get('branch_name'),
                    'build': 'IN PROGRESS',
                    'message': 'PR created, build in progress...'
                })

                # PHASE 2: monitor build and then trigger release
                build_result = monitor_build_and_release(
                    artifact = artifact,
                    commit_id = pr_info.get('latest_commit'),
                    configs = configs
                )

                if build_result.get('status') == 'success':
                    # build_result should contain 'artifact_id' and 'release_link' (if create_release returns it)
                    build_status_map[artifact].update({
                        'build': 'SUCCESSFUL',
                        'dev_release_name': 'IN PROGRESS',
                        'message': 'Build successful; release creation in progress'
                    })
                    
                    # PHASE 3: Trigger release
                    release_result = create_release(artifact = artifact, artifact_id = build_result.get('artifact_id'), configs = configs)
                    if(release_result.get('status')) == 'success':
                        build_status_map[artifact].update({
                        'build': 'SUCCESSFUL',
                        'dev_release_name': release_result.get('release_name'),
                        'dev_release_link': release_result.get('release_link'),
                        'message': 'Dev release created'
                    })


                else:
                    build_status_map[artifact].update({
                        'build': 'failed',
                        'dev_release_name': None,
                        'dev_release_link': None,
                        'message': 'Build failed'
                    })

            except Exception as e:
                build_status_map[artifact].update({
                    'status': 'failed',
                    'message': str(e)
                })

        threading.Thread(target=background_remediate_task, daemon=True).start()

    # Render page immediately (the background job will update build_status_map)
    return render_template('remediate.html', artifact_name=artifact)


@app.route('/api/build_status/<artifact>')
def get_build_status(artifact):
    """Poll PR + build + release status"""
    return jsonify(build_status_map.get(artifact, {'status': 'unknown'}))

@app.route('/api/build_status_bom/<repo>')
def get_build_status_bom(repo):
    """Poll status of BOM upgrade PR/build/release for a repo."""
    return jsonify(build_status_map.get(repo, {'status': 'unknown'}))

@app.route('/api/vulnerabilities/<artifact>')
def get_vulnerabilities(artifact):
    """Return vulnerabilities for an artifact (from in-memory cache)"""
    if artifact not in analyzed_reports:
        return jsonify({"error": "Artifact not found"}), 404
    return jsonify(analyzed_reports[artifact])


# --------------------------
#  MAIN ENTRY POINT
# --------------------------

if __name__ == '__main__':
    app.run(debug=True)
