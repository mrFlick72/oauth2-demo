CREATE TABLE oauth_client_details
(
    client_id varchar(256) PRIMARY KEY NOT NULL,
    resource_ids varchar(256),
    client_secret varchar(256),
    scope varchar(256),
    authorized_grant_types varchar(256),
    web_server_redirect_uri varchar(256),
    authorities varchar(256),
    access_token_validity int(11),
    refresh_token_validity int(11),
    additional_information varchar(4096),
    autoapprove varchar(256)
);
