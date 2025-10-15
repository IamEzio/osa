from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/raise_pr', methods=['POST'])
def raise_pr():
    return jsonify({"status": "PR created successfully"})

if __name__ == '__main__':
    app.run(debug=True)
