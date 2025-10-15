from flask import Flask, render_template, jsonify, request, redirect, url_for
from services.slaps_analyzer import analyze_slaps_report
from services.onboard_services import create_service

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_slaps():
    """Endpoint to analyze uploaded SLAPS report"""
    if 'report' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['report']
    try:
        structured_data = analyze_slaps_report(file)
        return jsonify(structured_data)
    except Exception as e:
        print("Error analyzing report:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/onboard_service')
def onboard_form():
    """Render the HTML form for onboarding a service"""
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

        return redirect(url_for("onboard_form"))

    except Exception as e:
        print("Error onboarding service:", e)
        return redirect(url_for("onboard_form"))

if __name__ == '__main__':
    app.run(debug=True)
