from flask import Flask, render_template, jsonify, request, redirect, url_for
from services.slaps_analyzer import analyze_slaps_report
from services.onboard_services import create_service
from services.create_pr import create_bitbucket_pr

import os
import threading
import json

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Temporary in-memory storage
analyzed_reports = {}  # { artifact_name: {package: [vulns]} }
build_status_map = {}  # { artifact_name: {'status': '...', 'message': '...'} }


# --------------------------
#  HOME & SLAPS ANALYZER
# --------------------------

@app.route('/')
def index():
    """Landing page with SLAPS upload form"""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_slaps():
    """Endpoint to analyze uploaded SLAPS report"""
    if 'report' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['report']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'vulnerability_input.json')
    file.seek(0)
    file.save(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        structured_data = analyze_slaps_report(data)
        # Cache report in memory for remediation view
        for artifact, pkgs in structured_data.items():
            analyzed_reports[artifact] = pkgs
        print(structured_data)
        return jsonify(structured_data)
    except Exception as e:
        print("Error analyzing report:", e)
        return jsonify({"error": str(e)}), 500


# --------------------------
#  SERVICE ONBOARDING
# --------------------------

@app.route('/onboard_service')
def onboard_form():
    """Render HTML form for onboarding a service"""
    return render_template('onboard_service.html')


@app.route('/onboard', methods=['POST'])
def onboard_service():
    """Handle onboarding form submission"""
    try:
        data = {
            "service_name": request.form["service_name"],
            "project_key": request.form["project_key"],
            "repo_slug": request.form["repo_slug"],
            "shepherd_project": request.form["shepherd_project"],
            "shepherd_flock": request.form["shepherd_flock"],
            "monitored_artifacts": [
                a.strip() for a in request.form.get("monitored_artifacts", "").split(",") if a.strip()
            ],
            "bitbucket_token": request.form["bitbucket_token"],
            "shepherd_token": request.form["shepherd_token"]
        }

        create_service(data)  # Call DB insertion logic
        print(f"✅ Service onboarded: {data['service_name']}")
        return redirect(url_for("onboard_form"))

    except Exception as e:
        print("Error onboarding service:", e)
        return redirect(url_for("onboard_form"))


# --------------------------
#  REMEDIATION FLOW
# --------------------------

@app.route('/remediate/<artifact>')
def remediate_page(artifact):
    """Render the remediation page for a specific artifact"""
    return render_template('remediate.html', artifact_name=artifact)


@app.route('/api/vulnerabilities/<artifact>')
def get_vulnerabilities(artifact):
    """Return vulnerabilities for an artifact (from in-memory cache)"""
    if artifact not in analyzed_reports:
        return jsonify({"error": "Artifact not found"}), 404
    return jsonify(analyzed_reports[artifact])


@app.route('/api/create_pr/<artifact>', methods=['POST'])
def create_pr_api(artifact):
    """Trigger Bitbucket PR creation asynchronously"""
    build_status_map[artifact] = {'status': 'in_progress', 'message': 'PR creation started'}

    def run_pr_job():
        try:
            print(f"🚀 Starting PR creation for artifact: {artifact}")
            create_bitbucket_pr()  # Run your PR creation flow
            build_status_map[artifact] = {'status': 'success', 'message': 'Build completed successfully'}
        except Exception as e:
            print(f"❌ PR creation failed for {artifact}: {e}")
            build_status_map[artifact] = {'status': 'failed', 'message': str(e)}

    threading.Thread(target=run_pr_job).start()
    return jsonify({'status': 'in_progress'})


@app.route('/api/build_status/<artifact>')
def build_status(artifact):
    """Poll build status of artifact"""
    return jsonify(build_status_map.get(artifact, {'status': 'unknown'}))


# --------------------------
#  MAIN ENTRY POINT
# --------------------------

if __name__ == '__main__':
    app.run(debug=True)
