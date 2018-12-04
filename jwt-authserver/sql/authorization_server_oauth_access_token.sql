CREATE TABLE oauth_access_token
(
    token_id varchar(255),
    token blob,
    authentication_id varchar(255),
    user_name varchar(255),
    client_id varchar(255),
    authentication blob,
    refresh_token varchar(255)
);
