# services/onboard_services.py

from services.db_service import get_db_connection

def create_service(service_data):
    """
    Creates a new service and its associated artifacts in the SQLite database.
    Args:
        service_data (dict): Service info JSON
    Returns:
        dict: Confirmation of created service and artifacts
    """
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Insert the service
        cur.execute("""
            INSERT INTO services (
                service_name, project_key, repo_slug, shepherd_project,
                shepherd_flock, monitored_artifacts, bitbucket_token, shepherd_token
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            service_data["service_name"],
            service_data["project_key"],
            service_data["repo_slug"],
            service_data["shepherd_project"],
            service_data["shepherd_flock"],
            ','.join(service_data.get("monitored_artifacts", [])),  # store list as CSV
            service_data["bitbucket_token"],
            service_data["shepherd_token"]
        ))

        service_id = cur.lastrowid

        # Insert artifacts for each monitored artifact
        created_artifacts = []
        for artifact in service_data.get("monitored_artifacts", []):
            cur.execute("""
                INSERT INTO artifacts (artifact_name, service_id)
                VALUES (?, ?)
            """, (artifact, service_id))
            artifact_id = cur.lastrowid
            created_artifacts.append({
                "artifact_name": artifact,
                "artifact_id": artifact_id
            })

        conn.commit()

        return {
            "message": "Service onboarded successfully",
            "service_id": service_id,
            "artifacts": created_artifacts
        }

    except Exception as e:
        conn.rollback()
        raise e

    finally:
        conn.close()
