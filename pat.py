#!/usr/bin/env python3
"""
Snowflake PAT (Programmatic Access Token) Manager

Sets up a service user with network policies, authentication policies,
and creates/rotates PATs for programmatic access.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import click
import requests


def run_snow_sql(query: str, *, format: str = "json", check: bool = True) -> dict | list | None:
    """Execute a snow sql command and return parsed JSON output."""
    cmd = ["snow", "sql", "--query", query, "--format", format]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    if format == "json" and result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def run_snow_sql_stdin(sql: str, *, check: bool = True) -> subprocess.CompletedProcess:
    """Execute multi-statement SQL via stdin."""
    cmd = ["snow", "sql", "--stdin"]
    result = subprocess.run(cmd, input=sql, capture_output=True, text=True)

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    return result


def get_local_ip() -> str:
    """Get the local public IP address with /32 CIDR suffix."""
    try:
        # Use a reliable IP echo service
        response = requests.get("https://api.ipify.org", timeout=10)
        response.raise_for_status()
        return f"{response.text.strip()}/32"
    except requests.RequestException as e:
        raise click.ClickException(f"Failed to get local IP: {e}")


def get_snowflake_account() -> str:
    """Get the current Snowflake account from connection test."""
    result = subprocess.run(
        ["snow", "connection", "test", "--format", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise click.ClickException(f"Failed to test connection: {result.stderr}")

    data = json.loads(result.stdout)
    return data.get("Account", "")


def setup_service_user(user: str, pat_role: str) -> None:
    """Create service user and grant the PAT role."""
    click.echo(f"Setting up service user: {user}")

    sql = f"""
        USE ROLE accountadmin;
        CREATE USER IF NOT EXISTS {user}
            TYPE = SERVICE
            COMMENT = 'Service user for PAT access';
        GRANT ROLE {pat_role} TO USER {user};
    """
    run_snow_sql_stdin(sql)
    click.echo(f"✓ Service user {user} configured with role {pat_role}")


def setup_network_policy(user: str, admin_role: str, db: str, local_ip: str) -> None:
    """Create network rule and policy for the service user using admin_role."""

    # Derive policy names from user
    network_rule_name = f"{user}_network_rule".upper()
    network_policy_name = f"{user}_network_policy".upper()
    click.echo(f"Setting up network policy for user {user}")
    click.echo(f"Using admin role: {admin_role}")
    click.echo(f"Network rule: {db}.networks.{network_rule_name}")
    click.echo(f"Network policy: {network_policy_name}")

    # First, unset and drop any existing network policy (ignore errors)
    run_snow_sql_stdin(
        f"""
USE ROLE accountadmin;
ALTER USER {user} UNSET network_policy;
DROP NETWORK POLICY IF EXISTS {network_policy_name};
""",
        check=False,
    )

    cidr_list = f"'{local_ip}'"

    sql = f"""
        USE ROLE {admin_role};
        GRANT CREATE NETWORK RULE ON SCHEMA {db}.networks TO ROLE accountadmin;
        GRANT CREATE AUTHENTICATION POLICY ON SCHEMA {db}.policies TO ROLE accountadmin;

        CREATE DATABASE IF NOT EXISTS {db};
        USE DATABASE {db};

        CREATE SCHEMA IF NOT EXISTS networks;
        CREATE SCHEMA IF NOT EXISTS policies;
        CREATE SCHEMA IF NOT EXISTS data;

        CREATE OR REPLACE NETWORK RULE {db}.networks.{network_rule_name}
            MODE = ingress
            TYPE = ipv4
            VALUE_LIST = ({cidr_list})
            COMMENT = 'Network rule for {user} PAT access';

        USE ROLE accountadmin;

        CREATE OR REPLACE NETWORK POLICY {network_policy_name}
            ALLOWED_NETWORK_RULE_LIST = ({db}.networks.{network_rule_name})
            COMMENT = 'Network policy for {user} PAT access';

        ALTER USER {user} SET NETWORK_POLICY = '{network_policy_name}';
    """
    run_snow_sql_stdin(sql)
    click.echo("✓ Network policy configured")


def setup_auth_policy(user: str, db: str, default_expiry_days: int, max_expiry_days: int) -> None:
    """Create authentication policy for PAT access."""
    click.echo("Setting up authentication policy...")

    # Derive auth policy name from user
    auth_policy_name = f"{user}_auth_policy".upper()

    # First, unset any existing auth policy (ignore errors)
    run_snow_sql(
        f"USE ROLE accountadmin; ALTER USER {user} UNSET AUTHENTICATION POLICY;",
        check=False,
    )

    sql = f"""
        CREATE OR ALTER AUTHENTICATION POLICY {db}.policies.{auth_policy_name}
            AUTHENTICATION_METHODS = ('PROGRAMMATIC_ACCESS_TOKEN')
            PAT_POLICY = (
                default_expiry_in_days = {default_expiry_days},
                max_expiry_in_days = {max_expiry_days},
                network_policy_evaluation = ENFORCED_REQUIRED
            );

        ALTER USER {user} SET AUTHENTICATION POLICY {db}.policies.{auth_policy_name};
    """
    run_snow_sql_stdin(sql)
    click.echo("✓ Authentication policy configured")


def get_existing_pat(user: str, pat_name: str) -> str | None:
    """Check if a PAT with the given name exists for the user."""
    result = run_snow_sql(f"SHOW USER PATS FOR USER {user}")

    if not result:
        return None

    for pat in result:
        if pat.get("name", "").lower() == pat_name.lower():
            return pat.get("name")

    return None


def create_or_rotate_pat(user: str, pat_role: str, pat_name: str, rotate: bool = False) -> str:
    """Create a new PAT or rotate an existing one with pat_role as the role restriction."""
    existing = get_existing_pat(user, pat_name)

    if existing and not rotate:
        click.echo(f"PAT '{pat_name}' already exists. Use --rotate to rotate it.")
        raise click.ClickException("PAT already exists")

    if existing:
        click.echo(f"Rotating PAT for service user {user}...")
        query = f"ALTER USER IF EXISTS {user} ROTATE PAT {pat_name}"
    else:
        click.echo(f"Creating new PAT for service user {user} with role restriction {pat_role}...")
        query = f"ALTER USER IF EXISTS {user} ADD PAT {pat_name} ROLE_RESTRICTION = {pat_role}"

    result = run_snow_sql(query)

    if not result or not result[0].get("token_secret"):
        raise click.ClickException("Failed to get PAT token from response")

    token = result[0]["token_secret"]
    click.echo("✓ PAT created/rotated successfully")
    return token


def update_env(env_path: Path, user: str, password: str, pat_role: str) -> None:
    """Update .env file with the new SNOWFLAKE_PASSWORD and SA_ROLE (PAT role restriction)."""
    if not env_path.exists():
        click.echo(f"⚠ {env_path} not found, skipping update")
        return

    content = env_path.read_text()

    # Create backup
    backup_path = env_path.with_suffix(".env.bak")
    shutil.copy(env_path, backup_path)

    # Replace or add SNOWFLAKE_PASSWORD
    password_pattern = r"^SNOWFLAKE_PASSWORD=.*$"
    password_replacement = f"SNOWFLAKE_PASSWORD='{password}'"

    if re.search(password_pattern, content, re.MULTILINE):
        new_content = re.sub(password_pattern, password_replacement, content, flags=re.MULTILINE)
    else:
        new_content = content.rstrip() + f"\n{password_replacement}\n"

    # Replace or add SA_USER
    user_pattern = r"^SA_USER=.*$"
    user_replacement = f"SA_USER='{user}'"

    if re.search(user_pattern, new_content, re.MULTILINE):
        new_content = re.sub(user_pattern, user_replacement, new_content, flags=re.MULTILINE)
    else:
        new_content = new_content.rstrip() + f"\n{user_replacement}\n"

    # Replace or add SA_ROLE (the PAT role restriction)
    role_pattern = r"^SA_ROLE=.*$"
    role_replacement = f"SA_ROLE='{pat_role}'"

    if re.search(role_pattern, new_content, re.MULTILINE):
        new_content = re.sub(role_pattern, role_replacement, new_content, flags=re.MULTILINE)
    else:
        new_content = new_content.rstrip() + f"\n{role_replacement}\n"

    env_path.write_text(new_content)
    click.echo(f"✓ Updated {env_path} with new SNOWFLAKE_PASSWORD, SA_USER, and SA_ROLE")


def verify_connection(user: str, password: str, pat_role: str) -> None:
    """Verify the PAT connection works."""
    click.echo("Verifying connection with PAT...")

    account = get_snowflake_account()

    result = subprocess.run(
        [
            "snow",
            "sql",
            "-x",
            "--user",
            user,
            "--account",
            account,
            "--role",
            pat_role,
            "-q",
            "SELECT current_timestamp()",
        ],
        env={**os.environ, "SNOWFLAKE_PASSWORD": password},
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise click.ClickException(f"Connection verification failed: {result.stderr}")

    click.echo("✓ Connection verified successfully")


@click.command()
@click.option(
    "--user",
    "-u",
    envvar="SA_USER",
    required=True,
    help="Service account user name (or set SA_USER env var)",
)
@click.option(
    "--role",
    "-r",
    envvar="SA_ROLE",
    required=True,
    help="Role restriction for the PAT (or set SA_ROLE env var)",
)
@click.option(
    "--admin-role",
    "-a",
    envvar="SA_ADMIN_ROLE",
    default=None,
    help="Admin role for creating network rules/policies (default: --role)",
)
@click.option(
    "--db",
    "-d",
    envvar="PAT_OBJECTS_DB",
    required=True,
    help="Database for PAT objects (or set PAT_OBJECTS_DB env var)",
)
@click.option(
    "--pat-name",
    default=None,
    envvar="PAT_NAME",
    help="Name for the PAT token (default: {user}_pat)",
)
@click.option(
    "--rotate/--no-rotate",
    default=True,
    help="Rotate existing PAT if it exists (default: True)",
)
@click.option(
    "--env-path",
    type=click.Path(path_type=Path),
    default=Path(".env"),
    envvar="DOT_ENV_FILE",
    help="Path to .env file to update",
)
@click.option(
    "--skip-verify",
    is_flag=True,
    help="Skip connection verification after PAT creation",
)
@click.option(
    "--local-ip",
    help="Override local IP detection (format: x.x.x.x/32)",
)
@click.option(
    "--default-expiry-days",
    default=45,
    type=int,
    help="Default PAT expiry in days (default: 45)",
)
@click.option(
    "--max-expiry-days",
    default=90,
    type=int,
    help="Maximum PAT expiry in days (default: 90)",
)
def main(
    user: str,
    role: str,
    admin_role: str | None,
    db: str,
    pat_name: str | None,
    rotate: bool,
    env_path: Path,
    skip_verify: bool,
    local_ip: str | None,
    default_expiry_days: int,
    max_expiry_days: int,
) -> None:
    """
    Snowflake PAT Manager - Setup service user with programmatic access tokens.

    This tool:

    \b
    1. Creates/configures a Snowflake service user
    2. Sets up network rules and policies for secure access
    3. Configures authentication policy for PAT
    4. Creates or rotates a PAT for the service user
    5. Updates .env with the new credentials
    6. Verifies the connection works

    \b
    Two roles can be specified:
    - --admin-role: Role with privileges to create network rules, policies, database objects
    - --role: Role restriction for the PAT (the role the service account will actually use)

    Example:

    \b
        # Using environment variables
        export SA_USER=my_service_user
        export SA_ROLE=demo_role           # PAT role restriction
        export SA_ADMIN_ROLE=sysadmin      # Role for creating policies
        export PAT_OBJECTS_DB=my_db
        python pat.py

        # Using CLI arguments (admin-role defaults to role if not specified)
        python pat.py --user my_user --role demo_role --admin-role sysadmin --db my_db
    """
    click.echo("=" * 50)
    click.echo("Snowflake PAT Manager")
    click.echo("=" * 50)
    click.echo()

    # Set default admin_role to role if not provided
    if not admin_role:
        admin_role = role

    # Set default pat_name based on user if not provided
    if not pat_name:
        pat_name = f"{user}_pat".upper()

    # Get local IP if not provided
    if not local_ip:
        click.echo("Detecting local IP...")
        local_ip = get_local_ip()
        click.echo(f"✓ Local IP: {local_ip}")

    click.echo()
    click.echo(f"User:       {user}")
    click.echo(f"PAT Role:   {role} (role restriction for PAT)")
    click.echo(f"Admin Role: {admin_role} (for creating policies)")
    click.echo(f"Database:   {db}")
    click.echo(f"PAT Name:   {pat_name}")

    click.echo()

    # Step 1: Setup service user (grants the PAT role to user)
    setup_service_user(user=user, pat_role=role)

    # Step 2: Setup network policy (uses admin_role for creating resources)
    setup_network_policy(user=user, admin_role=admin_role, db=db, local_ip=local_ip)

    # Step 3: Setup authentication policy (uses admin_role)
    setup_auth_policy(
        user=user, db=db, default_expiry_days=default_expiry_days, max_expiry_days=max_expiry_days
    )

    # Step 4: Create or rotate PAT (uses role as the PAT role restriction)
    password = create_or_rotate_pat(user=user, pat_role=role, pat_name=pat_name, rotate=rotate)

    # Step 5: Update .env (stores the PAT role)
    update_env(env_path=env_path, user=user, password=password, pat_role=role)

    # Step 6: Verify connection
    if not skip_verify:
        verify_connection(user=user, password=password, pat_role=role)

    click.echo()
    click.echo("=" * 50)
    click.echo("✓ PAT setup completed successfully!")
    click.echo("=" * 50)


if __name__ == "__main__":
    main()  # type: ignore[call-arg] # noqa: S101
