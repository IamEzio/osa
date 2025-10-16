CREATE TABLE services (
    service_id SERIAL PRIMARY KEY,
    service_name TEXT NOT NULL,
    project_key TEXT NOT NULL,
    repo_slug TEXT NOT NULL,
    shepherd_project TEXT NOT NULL,
    shepherd_flock TEXT NOT NULL,
    monitored_artifacts TEXT[],  -- optional list for reference
    bitbucket_token TEXT NOT NULL,
    shepherd_token TEXT NOT NULL
);

CREATE TABLE artifacts (
    artifact_id SERIAL PRIMARY KEY,
    artifact_name TEXT NOT NULL,
    service_id INTEGER NOT NULL REFERENCES services(service_id) ON DELETE CASCADE
);

CREATE TABLE vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    artifact_id INTEGER NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    severity TEXT,
    advisory_name TEXT,
    advisory_link TEXT,
    package_version TEXT,
    fix_version TEXT,
    status TEXT DEFAULT 'open',  -- could be open/resolved/rejected
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
