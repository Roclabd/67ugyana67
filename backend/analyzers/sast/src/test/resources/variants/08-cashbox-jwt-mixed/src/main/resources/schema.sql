CREATE TABLE account (
    account_id BIGINT PRIMARY KEY,
    owner_id VARCHAR(48) NOT NULL,
    balance BIGINT NOT NULL
);

CREATE TABLE statement (
    statement_id BIGINT PRIMARY KEY,
    owner_id VARCHAR(48) NOT NULL,
    period VARCHAR(7) NOT NULL,
    total BIGINT NOT NULL
);

CREATE TABLE transfer (
    transfer_id BIGINT PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES account(account_id),
    amount BIGINT NOT NULL,
    description VARCHAR(140) NOT NULL
);
