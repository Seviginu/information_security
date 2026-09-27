CREATE TABLE app_user (
    username VARCHAR(64) PRIMARY KEY,
    password_hash VARCHAR(100) NOT NULL
);

CREATE TABLE note (
    id UUID PRIMARY KEY,
    owner VARCHAR(64) NOT NULL REFERENCES app_user(username),
    content VARCHAR(2000) NOT NULL
);
