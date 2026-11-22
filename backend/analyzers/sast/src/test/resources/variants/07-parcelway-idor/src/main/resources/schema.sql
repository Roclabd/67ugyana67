CREATE TABLE orders (
    order_id BIGINT PRIMARY KEY,
    customer_id VARCHAR(48) NOT NULL,
    total BIGINT NOT NULL
);

CREATE TABLE parcel (
    id BIGINT PRIMARY KEY,
    owner_id VARCHAR(48) NOT NULL,
    description VARCHAR(120) NOT NULL
);

CREATE TABLE receipt (
    id BIGINT PRIMARY KEY,
    user_id VARCHAR(48) NOT NULL,
    amount BIGINT NOT NULL
);
