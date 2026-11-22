CREATE TABLE doctor (
    doctor_id BIGINT PRIMARY KEY,
    full_name VARCHAR(80) NOT NULL,
    speciality VARCHAR(40) NOT NULL
);

CREATE TABLE visit (
    visit_id BIGINT PRIMARY KEY,
    patient_id VARCHAR(48) NOT NULL,
    doctor_name VARCHAR(80) NOT NULL,
    visit_date DATE NOT NULL,
    note VARCHAR(400) NOT NULL
);
