#!/usr/bin/env bash

set -euo pipefail 

## Setup Service User for GitHub Actions
snow sql --stdin <<EOF
    use role accountadmin;
    CREATE USER IF NOT EXISTS $SA_USER
        TYPE = SERVICE
        COMMENT = 'Service User Openflow Demos';
    GRANT ROLE $SA_ROLE TO USER $SA_USER;
EOF

# Get GitHub Actions IP ranges only IPV4
# GH_CIDRS=$(curl -s https://api.github.com/meta | jq -r '.actions | map(select(contains(":") | not)) | map("'\''" + . + "'\''") | join(",")')

# Get local IP and add /32 suffix
LOCAL_IP="$(dig +short myip.opendns.com @resolver1.opendns.com)/32"
#LOCAL_IP="0.0.0.0/0"

# Combine GitHub CIDRs and local IP
CIDR_VALUE_LIST="'${LOCAL_IP}'"

# Create or alter the network rule and policy
snow sql --query "use role accountadmin;alter user $SA_USER unset network_policy;" || true
snow sql --stdin <<EOF
use role $SA_ROLE;
grant create network rule on schema $PAT_OBJECTS_DB.networks to role accountadmin;
grant create authentication policy on schema $PAT_OBJECTS_DB.policies to role accountadmin;
create database if not exists $PAT_OBJECTS_DB;
use database $PAT_OBJECTS_DB;
create schema if not exists networks;
create schema if not exists policies;
create schema if not exists data;
create network rule if not exists $PAT_OBJECTS_DB.networks.pat_openflow_demos_local_access_rule
  mode = ingress
  type = ipv4
  value_list = ($CIDR_VALUE_LIST)
  comment = 'Allow only GitHub Actions and local machine IPv4 addresses';

use role accountadmin;
-- attach the network rule to the network policy
create network policy if not exists OPENFLOW_DEMOS_PAT_NETWORK_POLICY
allowed_network_rule_list = ($PAT_OBJECTS_DB.networks.pat_openflow_demos_local_access_rule)
comment = 'Network policy to allow all IPv4 addresses.';

-- set the network policy to the user to allow using pat with snowflake cli
alter user $SA_USER set network_policy='OPENFLOW_DEMOS_PAT_NETWORK_POLICY';
EOF

# Create or alter the authentication policy that will be set to the service user
snow sql --query "use role accountadmin;alter user $SA_USER unset AUTHENTICATION POLICY;" || true
snow sql --stdin <<EOF
create or alter authentication policy $PAT_OBJECTS_DB.policies.demos_auth_policy
  authentication_methods = ('PROGRAMMATIC_ACCESS_TOKEN')
  pat_policy = (
    default_expiry_in_days=45,
    max_expiry_in_days=90,
    network_policy_evaluation = ENFORCED_REQUIRED
  );
 alter user $SA_USER set AUTHENTICATION POLICY $PAT_OBJECTS_DB.policies.demos_auth_policy;
EOF

# Create PAT for the service user
# Check if PAT already exists
EXISTING_PAT=$( snow sql -q "show user pats for user $SA_USER" \
  --format=json \
  | jq -r '.[] | select(.name|ascii_downcase == "openflow_demos_pat") | .name')

if [ -z "$EXISTING_PAT" ]; then
  # Create PAT if it doesn't exist
  echo "Creating new PAT for service user $SA_USER..."
  SNOWFLAKE_SA_PASSWORD=$(snow sql \
    --query "ALTER USER IF EXISTS $SA_USER ADD PAT openflow_demos_pat ROLE_RESTRICTION = $SA_ROLE" \
    --format=json | jq -r '.[] | .token_secret')
else
  echo "PAT for service user $SA_USER already exists. Rotating PAT..."
  # Rotate PAT 
  SNOWFLAKE_SA_PASSWORD=$(snow sql \
    --query "ALTER USER IF EXISTS $SA_USER ROTATE PAT openflow_demos_pat" \
    --format=json | jq -r '.[] | .token_secret')
fi;

echo "Service User PAT created successfully."

# Update .envrc with the new PAT
if [ -f .envrc ]; then
  sed -i.bak "s/^export SNOWFLAKE_PASSWORD=.*/export SNOWFLAKE_PASSWORD='${SNOWFLAKE_SA_PASSWORD}'/" .envrc
  echo "Updated .envrc with new SNOWFLAKE_PASSWORD"
  direnv allow .
fi
echo "Verify connection with path PAT..."
SNOWFLAKE_PASSWORD="$SNOWFLAKE_SA_PASSWORD" snow sql -x \
  --user="$SA_USER" \
  --account="$(snow connection test --format json | jq  -r '.Account')" \
  -q "select current_timestamp()"