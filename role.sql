create role if not exists kamesh_demos;
alter user kameshs set DEFAULT_ROLE='kamesh_demos';
grant create database on account to role kamesh_demos;
grant create integration on account to role kamesh_demos;
grant role kamesh_demos to user kameshs;

use role kamesh_demos;
grant CREATE AUTHENTICATION POLICY ON SCHEMA openflow_demos.policies TO ROLE ACCOUNTADMIN;
