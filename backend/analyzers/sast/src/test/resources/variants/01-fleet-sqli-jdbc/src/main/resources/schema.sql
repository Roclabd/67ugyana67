CREATE TABLE vehicle (
    vehicle_id BIGINT PRIMARY KEY,
    plate VARCHAR(16) UNIQUE NOT NULL,
    vin VARCHAR(20) UNIQUE NOT NULL,
    make VARCHAR(40) NOT NULL,
    dealer_name VARCHAR(60) NOT NULL,
    region_code VARCHAR(8) NOT NULL
);
