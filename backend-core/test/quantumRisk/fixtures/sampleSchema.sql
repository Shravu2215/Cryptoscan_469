CREATE TABLE identity_records (
  id INTEGER PRIMARY KEY,
  aadhaar_number VARCHAR(12),
  pan_number VARCHAR(10)
);

CREATE TABLE payment_records (
  id INTEGER PRIMARY KEY,
  card_number VARCHAR(19),
  cardholder_name VARCHAR(200)
);

CREATE TABLE health_records (
  id INTEGER PRIMARY KEY,
  patient_id VARCHAR(64),
  diagnosis TEXT,
  health_record JSON
);