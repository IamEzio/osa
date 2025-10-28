# OCI Security Assistant (OSA)
_Automated Vulnerability Analysis, Dependency Upgrade and Testing Service_

## 📘 Overview
**OCI Security Assistant (OSA)** is a Flask-based web application designed to automate dependency upgrade PR creation across OCI service repositories.  
It integrates tightly with internal developer workflows to identify outdated or vulnerable dependencies and automatically raise validated pull requests.

The goal is to reduce repetitive developer effort, improve consistency, and accelerate vulnerability remediation across OCI.

---


---

## 🚀 Getting Started

### 1️⃣ Create and Activate a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate   # (Windows: venv\Scripts\activate)
```

## Install dependencies
```bash
pip install -r requirements.txt
```
<!-- 
## Setup DB locally
```bash
python -c "from services.db_service import init_db; init_db()"
``` -->

## Setup ENV
```bash
BITBUCKET_AUTH_SIMPLE=<guid>:<your bitbucket token>
BASE_DIR_PATH="<output of pwd command from root>" (Example: "/Users/ansmaury/Desktop/osa/")
```

## Run the flask app
```bash
flask run
```

or

```bash
python app.py
```

Then open your browser at 👉 http://127.0.0.1:5000