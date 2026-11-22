CREATE TABLE stock_item (
    id BIGINT PRIMARY KEY,
    sku VARCHAR(24) UNIQUE NOT NULL,
    name VARCHAR(120) NOT NULL,
    location_code VARCHAR(12) NOT NULL,
    qty INT NOT NULL
);

CREATE TABLE reservation (
    id BIGINT PRIMARY KEY,
    owner_id VARCHAR(48) NOT NULL,
    sku VARCHAR(24) NOT NULL,
    qty INT NOT NULL
);
