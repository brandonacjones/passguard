DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS services;

CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_username TEXT NOT NULL UNIQUE,
    user_password BLOB NOT NULL
);

CREATE TABLE services (
    service_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    service_password BLOB NOT NULL,
    service_url TEXT,
    service_username TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);