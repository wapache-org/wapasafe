drop table if exists oauth2_client;
drop table if exists oauth2_user;

create table oauth2_user (
  id bigint auto_increment,
  username varchar(100),
  password varchar(255),
  constraint pk_oauth2_user primary key(id)
);
create unique index idx_oauth2_user_username on oauth2_user(username);

create table oauth2_client (
  id bigint auto_increment,
  client_name varchar(100),
  client_id varchar(100),
  client_secret varchar(100),
  constraint pk_oauth2_client primary key(id)
);
create index idx_oauth2_client_client_id on oauth2_client(client_id);