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


def setup_service_user(user: str, role: str) -> None:
    """Create service user and grant role."""
    click.echo(f"Setting up service user: {user}")

    sql = f"""
        USE ROLE accountadmin;
        CREATE USER IF NOT EXISTS {user}
            TYPE = SERVICE
            COMMENT = 'Service User Openflow Demos';
        GRANT ROLE {role} TO USER {user};
    """
    run_snow_sql_stdin(sql)
    click.echo(f"✓ Service user {user} configured")


def setup_network_policy(user: str, role: str, db: str, local_ip: str) -> None:
    """Create network rule and policy for the service user."""
    click.echo("Setting up network policy...")

    # First, unset any existing network policy (ignore errors)
    run_snow_sql(
        f"USE ROLE accountadmin; ALTER USER {user} UNSET network_policy;",
        check=False,
    )

    cidr_list = f"'{local_ip}'"

    sql = f"""
        USE ROLE {role};
        GRANT CREATE NETWORK RULE ON SCHEMA {db}.networks TO ROLE accountadmin;
        GRANT CREATE AUTHENTICATION POLICY ON SCHEMA {db}.policies TO ROLE accountadmin;

        CREATE DATABASE IF NOT EXISTS {db};
        USE DATABASE {db};

        CREATE SCHEMA IF NOT EXISTS networks;
        CREATE SCHEMA IF NOT EXISTS policies;
        CREATE SCHEMA IF NOT EXISTS data;

        CREATE NETWORK RULE IF NOT EXISTS {db}.networks.pat_openflow_demos_local_access_rule
            MODE = ingress
            TYPE = ipv4
            VALUE_LIST = ({cidr_list})
            COMMENT = 'Allow only GitHub Actions and local machine IPv4 addresses';

        USE ROLE accountadmin;

        CREATE NETWORK POLICY IF NOT EXISTS OPENFLOW_DEMOS_PAT_NETWORK_POLICY
            ALLOWED_NETWORK_RULE_LIST = ({db}.networks.pat_openflow_demos_local_access_rule)
            COMMENT = 'Network policy to allow all IPv4 addresses.';

        ALTER USER {user} SET NETWORK_POLICY = 'OPENFLOW_DEMOS_PAT_NETWORK_POLICY';
    """
    run_snow_sql_stdin(sql)
    click.echo("✓ Network policy configured")


def setup_auth_policy(user: str, db: str, default_expiry_days: int, max_expiry_days: int) -> None:
    """Create authentication policy for PAT access."""
    click.echo("Setting up authentication policy...")

    # First, unset any existing auth policy (ignore errors)
    run_snow_sql(
        f"USE ROLE accountadmin; ALTER USER {user} UNSET AUTHENTICATION POLICY;",
        check=False,
    )

    sql = f"""
        CREATE OR ALTER AUTHENTICATION POLICY {db}.policies.demos_auth_policy
            AUTHENTICATION_METHODS = ('PROGRAMMATIC_ACCESS_TOKEN')
            PAT_POLICY = (
                default_expiry_in_days = {default_expiry_days},
                max_expiry_in_days = {max_expiry_days},
                network_policy_evaluation = ENFORCED_REQUIRED
            );

        ALTER USER {user} SET AUTHENTICATION POLICY {db}.policies.demos_auth_policy;
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


def create_or_rotate_pat(user: str, role: str, pat_name: str, rotate: bool = False) -> str:
    """Create a new PAT or rotate an existing one."""
    existing = get_existing_pat(user, pat_name)

    if existing and not rotate:
        click.echo(f"PAT '{pat_name}' already exists. Use --rotate to rotate it.")
        raise click.ClickException("PAT already exists")

    if existing:
        click.echo(f"Rotating PAT for service user {user}...")
        query = f"ALTER USER IF EXISTS {user} ROTATE PAT {pat_name}"
    else:
        click.echo(f"Creating new PAT for service user {user}...")
        query = f"ALTER USER IF EXISTS {user} ADD PAT {pat_name} ROLE_RESTRICTION = {role}"

    result = run_snow_sql(query)

    if not result or not result[0].get("token_secret"):
        raise click.ClickException("Failed to get PAT token from response")

    token = result[0]["token_secret"]
    click.echo("✓ PAT created/rotated successfully")
    return token


def update_envrc(envrc_path: Path, password: str) -> None:
    """Update .envrc file with the new SNOWFLAKE_PASSWORD."""
    if not envrc_path.exists():
        click.echo(f"⚠ {envrc_path} not found, skipping update")
        return

    content = envrc_path.read_text()

    # Create backup
    backup_path = envrc_path.with_suffix(".envrc.bak")
    shutil.copy(envrc_path, backup_path)

    # Replace or add SNOWFLAKE_PASSWORD
    pattern = r"^export SNOWFLAKE_PASSWORD=.*$"
    replacement = f"export SNOWFLAKE_PASSWORD='{password}'"

    if re.search(pattern, content, re.MULTILINE):
        new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    else:
        new_content = content.rstrip() + f"\n{replacement}\n"

    envrc_path.write_text(new_content)
    click.echo(f"✓ Updated {envrc_path} with new SNOWFLAKE_PASSWORD")

    # Run direnv allow
    subprocess.run(["direnv", "allow", str(envrc_path)], check=False)


def verify_connection(user: str, password: str) -> None:
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
    help="Service account role (or set SA_ROLE env var)",
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
    help="Name for the PAT token (default: {user}_pat)",
)
@click.option(
    "--rotate/--no-rotate",
    default=True,
    help="Rotate existing PAT if it exists (default: True)",
)
@click.option(
    "--envrc",
    type=click.Path(path_type=Path),
    default=Path(".envrc"),
    help="Path to .envrc file to update",
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
    db: str,
    pat_name: str | None,
    rotate: bool,
    envrc: Path,
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
    5. Updates .envrc with the new credentials
    6. Verifies the connection works

    Example:

    \b
        # Using environment variables
        export SA_USER=my_service_user
        export SA_ROLE=my_role
        export PAT_OBJECTS_DB=my_db
        python pat.py

        # Using CLI arguments
        python pat.py --user my_user --role my_role --db my_db
    """
    click.echo("=" * 50)
    click.echo("Snowflake PAT Manager")
    click.echo("=" * 50)
    click.echo()

    # Set default pat_name based on user if not provided
    if not pat_name:
        pat_name = f"{user}_pat"

    # Get local IP if not provided
    if not local_ip:
        click.echo("Detecting local IP...")
        local_ip = get_local_ip()
        click.echo(f"✓ Local IP: {local_ip}")

    click.echo()
    click.echo(f"User:     {user}")
    click.echo(f"Role:     {role}")
    click.echo(f"Database: {db}")
    click.echo(f"PAT Name: {pat_name}")
    click.echo()

    # Step 1: Setup service user
    setup_service_user(user, role)

    # Step 2: Setup network policy
    setup_network_policy(user, role, db, local_ip)

    # Step 3: Setup authentication policy
    setup_auth_policy(user, db, default_expiry_days, max_expiry_days)

    # Step 4: Create or rotate PAT
    password = create_or_rotate_pat(user, role, pat_name, rotate=rotate)

    # Step 5: Update .envrc
    update_envrc(envrc, password)

    # Step 6: Verify connection
    if not skip_verify:
        verify_connection(user, password)

    click.echo()
    click.echo("=" * 50)
    click.echo("✓ PAT setup completed successfully!")
    click.echo("=" * 50)


if __name__ == "__main__":
    main()
