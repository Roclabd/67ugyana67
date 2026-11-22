CREATE TABLE report (
    report_id BIGINT PRIMARY KEY,
    title VARCHAR(120) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_on DATE NOT NULL,
    archived BOOLEAN NOT NULL DEFAULT FALSE
);
