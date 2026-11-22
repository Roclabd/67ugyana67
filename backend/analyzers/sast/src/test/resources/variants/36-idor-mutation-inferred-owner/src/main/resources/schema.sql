CREATE TABLE slot (
    slot_id UUID PRIMARY KEY,
    curator_id VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL
);
