CREATE TABLE repair_ticket (
    ticket_id BIGINT PRIMARY KEY,
    customer_id VARCHAR(80) NOT NULL,
    work_note VARCHAR(500) NOT NULL
);
