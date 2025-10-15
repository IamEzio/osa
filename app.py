from flask import Flask, render_template, jsonify, request
from services.slaps_analyzer import analyze_slaps_report
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/raise_pr', methods=['POST'])
def raise_pr():
    return jsonify({"status": "PR created successfully"})


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


if __name__ == '__main__':
    app.run(debug=True)
