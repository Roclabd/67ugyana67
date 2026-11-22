CREATE TABLE IF NOT EXISTS workflows (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(160) NOT NULL,
    version BIGINT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    payload CLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id VARCHAR(36) PRIMARY KEY,
    workflow_id VARCHAR(36) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    state VARCHAR(12) NOT NULL,
    payload CLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS workflow_runs_history ON workflow_runs(workflow_id, started_at);

CREATE TABLE IF NOT EXISTS run_events (
    seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(36) NOT NULL,
    event_name VARCHAR(40) NOT NULL,
    payload CLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS run_events_replay ON run_events(run_id, seq);

CREATE TABLE IF NOT EXISTS schedules (
    workflow_id VARCHAR(36) NOT NULL,
    node_id VARCHAR(100) NOT NULL,
    fire_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY(workflow_id, node_id, fire_at)
);

CREATE TABLE IF NOT EXISTS templates (
    id VARCHAR(36) PRIMARY KEY,
    payload CLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS review_baselines (
    workflow_id VARCHAR(36) PRIMARY KEY,
    run_id VARCHAR(36) NOT NULL
);

CREATE TABLE IF NOT EXISTS accepted_risks (
    workflow_id VARCHAR(36) NOT NULL,
    scope_key VARCHAR(64) NOT NULL,
    fingerprint VARCHAR(160) NOT NULL,
    run_id VARCHAR(36) NOT NULL,
    reason VARCHAR(300) NOT NULL,
    PRIMARY KEY(workflow_id, scope_key, fingerprint)
);

CREATE TABLE IF NOT EXISTS repository_settings (
    id INTEGER PRIMARY KEY,
    payload CLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS telegram_settings (
    id INTEGER PRIMARY KEY,
    payload CLOB NOT NULL
);
