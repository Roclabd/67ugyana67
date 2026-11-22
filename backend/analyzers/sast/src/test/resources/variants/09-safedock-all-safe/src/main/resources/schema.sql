CREATE TABLE note (
    note_id BIGINT PRIMARY KEY,
    owner_id VARCHAR(48) NOT NULL,
    title VARCHAR(120) NOT NULL,
    tag VARCHAR(24) NOT NULL,
    age_days INT NOT NULL DEFAULT 0
);
