#!/usr/bin/env python3
"""
Snowflake External Volume Manager

Creates and configures:
- S3 bucket for Iceberg table storage
- IAM policy and role with trust relationship
- Snowflake external volume
- Updates IAM trust policy with Snowflake's IAM user ARN and external ID
"""

import getpass
import json
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any

import boto3
import click
from botocore.exceptions import ClientError


@dataclass
class SnowCLIOptions:
    """Options for snow CLI commands."""

    verbose: bool = False
    debug: bool = False

    def get_flags(self) -> list[str]:
        """Get CLI flags based on options."""
        flags = []
        if self.debug:
            flags.append("--debug")
        elif self.verbose:
            flags.append("--verbose")
        return flags


# Global options (set by CLI group)
_snow_cli_options = SnowCLIOptions()


def set_snow_cli_options(verbose: bool = False, debug: bool = False) -> None:
    """Set global snow CLI options."""
    global _snow_cli_options
    _snow_cli_options = SnowCLIOptions(verbose=verbose, debug=debug)


@dataclass
class ExternalVolumeConfig:
    """Configuration for external volume setup."""

    bucket_name: str
    role_name: str
    policy_name: str
    volume_name: str
    storage_location_name: str
    external_id: str
    aws_region: str
    allow_writes: bool = True


# =============================================================================
# Naming Utilities
# =============================================================================


def get_current_username() -> str:
    """Get the current username for prefixing resources."""
    return getpass.getuser().lower()


def to_aws_name(name: str, prefix: str | None = None) -> str:
    """
    Convert a name to AWS-compatible format.

    AWS names can contain alphanumeric characters, hyphens, and some allow underscores.
    S3 bucket names: lowercase, 3-63 chars, no dots, alphanumeric and hyphens.
    IAM names: alphanumeric, plus these characters: +=,.@_-
    """
    # Lowercase and replace underscores with hyphens for consistency
    aws_name = name.lower().replace("_", "-")
    # Remove any characters that aren't alphanumeric or hyphens
    aws_name = re.sub(r"[^a-z0-9-]", "", aws_name)
    # Remove consecutive hyphens
    aws_name = re.sub(r"-+", "-", aws_name)
    # Remove leading/trailing hyphens
    aws_name = aws_name.strip("-")

    if prefix:
        prefix = prefix.lower().replace("_", "-")
        prefix = re.sub(r"[^a-z0-9-]", "", prefix)
        aws_name = f"{prefix}-{aws_name}"

    return aws_name


def to_sql_identifier(name: str, prefix: str | None = None) -> str:
    """
    Convert a name to valid Snowflake SQL identifier.

    Snowflake unquoted identifiers: start with letter or underscore,
    contain letters, digits, underscores. Case-insensitive (stored uppercase).
    """
    # Replace hyphens and spaces with underscores
    sql_name = name.replace("-", "_").replace(" ", "_")
    # Remove any characters that aren't alphanumeric or underscores
    sql_name = re.sub(r"[^a-zA-Z0-9_]", "", sql_name)
    # Remove consecutive underscores
    sql_name = re.sub(r"_+", "_", sql_name)
    # Remove leading/trailing underscores
    sql_name = sql_name.strip("_")
    # Ensure it starts with a letter or underscore (not a digit)
    if sql_name and sql_name[0].isdigit():
        sql_name = f"_{sql_name}"

    if prefix:
        prefix = prefix.replace("-", "_").replace(" ", "_")
        prefix = re.sub(r"[^a-zA-Z0-9_]", "", prefix)
        sql_name = f"{prefix}_{sql_name}"

    return sql_name.upper()


def generate_external_id(bucket: str, prefix: str | None = None) -> str:
    """
    Generate a unique external ID for AWS trust policy.

    The external ID is used to prevent the "confused deputy" problem in AWS.
    It combines a readable prefix with a unique suffix for security.

    Format: {PREFIX}_{BUCKET}_EXT_{SHORT_UUID}
    Example: KSAMPATH_ICEBERG_DEMO_EXT_A1B2C3D4
    """
    # Generate a short unique suffix (8 chars from UUID)
    unique_suffix = uuid.uuid4().hex[:8].upper()

    # Build the base name
    base_name = f"{bucket}_ext_{unique_suffix}"

    return to_sql_identifier(base_name, prefix)


def get_aws_account_id(sts_client: Any) -> str:
    """Get the current AWS account ID."""
    return sts_client.get_caller_identity()["Account"]


def run_snow_sql(query: str, *, format: str = "json", check: bool = True) -> dict | list | None:
    """Execute a snow sql command and return parsed JSON output."""
    cmd = ["snow", "sql", *_snow_cli_options.get_flags(), "--query", query, "--format", format]

    if _snow_cli_options.debug:
        click.echo(f"[DEBUG] Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if _snow_cli_options.debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")

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
    cmd = ["snow", "sql", *_snow_cli_options.get_flags(), "--stdin"]

    if _snow_cli_options.debug:
        click.echo(f"[DEBUG] Running: {' '.join(cmd)}")
        click.echo(f"[DEBUG] SQL:\n{sql}")

    result = subprocess.run(cmd, input=sql, capture_output=True, text=True)

    if _snow_cli_options.debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")
    if _snow_cli_options.debug and result.stdout:
        click.echo(f"[DEBUG] stdout: {result.stdout}")

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    return result


# =============================================================================
# S3 Bucket Operations
# =============================================================================


def create_s3_bucket(
    s3_client: Any, bucket_name: str, region: str, versioning: bool = True
) -> bool:
    """Create an S3 bucket with optional versioning."""
    click.echo(f"Creating S3 bucket: {bucket_name}")

    try:
        # Check if bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            click.echo(f"✓ Bucket {bucket_name} already exists")
            return False
        except ClientError as e:
            if e.response["Error"]["Code"] != "404":
                raise

        # Create bucket with location constraint for non-us-east-1 regions
        create_params: dict[str, Any] = {"Bucket": bucket_name}
        if region != "us-east-1":
            create_params["CreateBucketConfiguration"] = {"LocationConstraint": region}

        s3_client.create_bucket(**create_params)
        click.echo(f"✓ Created bucket: {bucket_name}")

        # Enable versioning (recommended for data recovery)
        if versioning:
            s3_client.put_bucket_versioning(
                Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
            )
            click.echo("✓ Enabled bucket versioning")

        return True

    except ClientError as e:
        raise click.ClickException(f"Failed to create bucket: {e}")


def delete_s3_bucket(s3_client: Any, bucket_name: str, force: bool = False) -> None:
    """Delete an S3 bucket (optionally emptying it first)."""
    click.echo(f"Deleting S3 bucket: {bucket_name}")

    try:
        if force:
            # Delete all objects first
            paginator = s3_client.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket_name):
                objects_to_delete = []
                for version in page.get("Versions", []):
                    objects_to_delete.append(
                        {"Key": version["Key"], "VersionId": version["VersionId"]}
                    )
                for marker in page.get("DeleteMarkers", []):
                    objects_to_delete.append(
                        {"Key": marker["Key"], "VersionId": marker["VersionId"]}
                    )
                if objects_to_delete:
                    s3_client.delete_objects(
                        Bucket=bucket_name, Delete={"Objects": objects_to_delete}
                    )

        s3_client.delete_bucket(Bucket=bucket_name)
        click.echo(f"✓ Deleted bucket: {bucket_name}")

    except ClientError as e:
        raise click.ClickException(f"Failed to delete bucket: {e}")


# =============================================================================
# IAM Policy Operations
# =============================================================================


def get_s3_access_policy(bucket_name: str) -> dict:
    """Generate IAM policy document for S3 access."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringLike": {"s3:prefix": ["*"]}},
            },
        ],
    }


def create_iam_policy(iam_client: Any, policy_name: str, bucket_name: str) -> str:
    """Create IAM policy for S3 access and return the policy ARN."""
    click.echo(f"Creating IAM policy: {policy_name}")

    account_id = get_aws_account_id(boto3.client("sts"))
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

    try:
        # Check if policy exists
        try:
            iam_client.get_policy(PolicyArn=policy_arn)
            click.echo(f"✓ Policy {policy_name} already exists")
            return policy_arn
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # Create policy
        policy_document = get_s3_access_policy(bucket_name)
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
            Description=f"Policy for Snowflake external volume access to {bucket_name}",
        )
        policy_arn = response["Policy"]["Arn"]
        click.echo(f"✓ Created policy: {policy_arn}")
        return policy_arn

    except ClientError as e:
        raise click.ClickException(f"Failed to create IAM policy: {e}")


def delete_iam_policy(iam_client: Any, policy_arn: str) -> None:
    """Delete an IAM policy."""
    click.echo(f"Deleting IAM policy: {policy_arn}")

    try:
        iam_client.delete_policy(PolicyArn=policy_arn)
        click.echo(f"✓ Deleted policy: {policy_arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise click.ClickException(f"Failed to delete policy: {e}")


# =============================================================================
# IAM Role Operations
# =============================================================================


def get_initial_trust_policy(account_id: str, external_id: str) -> dict:
    """Generate initial trust policy (before Snowflake user ARN is known)."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def get_snowflake_trust_policy(snowflake_user_arn: str, external_id: str) -> dict:
    """Generate trust policy for Snowflake IAM user."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SnowflakeAccess",
                "Effect": "Allow",
                "Principal": {"AWS": snowflake_user_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def create_iam_role(
    iam_client: Any,
    role_name: str,
    policy_arn: str,
    account_id: str,
    external_id: str,
) -> str:
    """Create IAM role with initial trust policy and return the role ARN."""
    click.echo(f"Creating IAM role: {role_name}")

    try:
        # Check if role exists
        try:
            response = iam_client.get_role(RoleName=role_name)
            role_arn = response["Role"]["Arn"]
            click.echo(f"✓ Role {role_name} already exists")
            return role_arn
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # Create role with initial trust policy
        trust_policy = get_initial_trust_policy(account_id, external_id)
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="IAM role for Snowflake external volume access",
        )
        role_arn = response["Role"]["Arn"]
        click.echo(f"✓ Created role: {role_arn}")

        # Attach policy to role
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        click.echo("✓ Attached policy to role")

        return role_arn

    except ClientError as e:
        raise click.ClickException(f"Failed to create IAM role: {e}")


def update_role_trust_policy(
    iam_client: Any, role_name: str, snowflake_user_arn: str, external_id: str
) -> None:
    """Update IAM role trust policy with Snowflake IAM user ARN."""
    click.echo(f"Updating trust policy for role: {role_name}")

    try:
        trust_policy = get_snowflake_trust_policy(snowflake_user_arn, external_id)
        iam_client.update_assume_role_policy(
            RoleName=role_name, PolicyDocument=json.dumps(trust_policy)
        )
        click.echo(f"✓ Updated trust policy with Snowflake IAM user: {snowflake_user_arn}")

    except ClientError as e:
        raise click.ClickException(f"Failed to update trust policy: {e}")


def delete_iam_role(iam_client: Any, role_name: str, policy_arn: str) -> None:
    """Delete an IAM role (detaching policies first)."""
    click.echo(f"Deleting IAM role: {role_name}")

    try:
        # Detach policy first
        try:
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            click.echo("✓ Detached policy from role")
        except ClientError:
            pass

        iam_client.delete_role(RoleName=role_name)
        click.echo(f"✓ Deleted role: {role_name}")

    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise click.ClickException(f"Failed to delete role: {e}")


# =============================================================================
# Snowflake External Volume Operations
# =============================================================================


def create_external_volume(config: ExternalVolumeConfig, role_arn: str) -> None:
    """Create Snowflake external volume."""
    click.echo(f"Creating Snowflake external volume: {config.volume_name}")

    allow_writes = "TRUE" if config.allow_writes else "FALSE"

    sql = f"""
        CREATE OR REPLACE EXTERNAL VOLUME {config.volume_name}
            STORAGE_LOCATIONS = (
                (
                    NAME = '{config.storage_location_name}'
                    STORAGE_PROVIDER = 'S3'
                    STORAGE_BASE_URL = 's3://{config.bucket_name}/'
                    STORAGE_AWS_ROLE_ARN = '{role_arn}'
                    STORAGE_AWS_EXTERNAL_ID = '{config.external_id}'
                )
            )
            ALLOW_WRITES = {allow_writes};
    """
    run_snow_sql_stdin(sql)
    click.echo(f"✓ Created external volume: {config.volume_name}")


def describe_external_volume(volume_name: str) -> dict[str, str]:
    """Describe external volume and extract AWS IAM user ARN and external ID."""
    click.echo(f"Describing external volume: {volume_name}")

    result = run_snow_sql(f"DESC EXTERNAL VOLUME {volume_name}")

    if not result:
        raise click.ClickException("Failed to describe external volume")

    # Parse the result to find STORAGE_AWS_IAM_USER_ARN and STORAGE_AWS_EXTERNAL_ID
    properties = {}
    for row in result:
        parent_prop = row.get("parent_property", "")
        prop_name = row.get("property", "")
        prop_value = row.get("property_value", "")

        # Storage location details are nested as JSON inside property_value
        if parent_prop == "STORAGE_LOCATIONS" and prop_name.startswith("STORAGE_LOCATION_"):
            try:
                location_data = json.loads(prop_value)
                if "STORAGE_AWS_IAM_USER_ARN" in location_data:
                    properties["iam_user_arn"] = location_data["STORAGE_AWS_IAM_USER_ARN"]
                if "STORAGE_AWS_EXTERNAL_ID" in location_data:
                    properties["external_id"] = location_data["STORAGE_AWS_EXTERNAL_ID"]
            except json.JSONDecodeError:
                pass  # Skip if not valid JSON

    if "iam_user_arn" not in properties:
        raise click.ClickException(
            "Could not find STORAGE_AWS_IAM_USER_ARN in external volume description"
        )

    click.echo(f"✓ Snowflake IAM User ARN: {properties.get('iam_user_arn')}")
    click.echo(f"✓ External ID: {properties.get('external_id')}")

    return properties


def drop_external_volume(volume_name: str) -> None:
    """Drop Snowflake external volume."""
    click.echo(f"Dropping Snowflake external volume: {volume_name}")

    run_snow_sql(f"DROP EXTERNAL VOLUME IF EXISTS {volume_name}")
    click.echo(f"✓ Dropped external volume: {volume_name}")


def verify_external_volume(volume_name: str) -> None:
    """Verify external volume connectivity."""
    click.echo(f"Verifying external volume: {volume_name}")

    result = run_snow_sql(f"SELECT SYSTEM$VERIFY_EXTERNAL_VOLUME('{volume_name}')")

    if not result:
        click.echo("⚠ Could not verify external volume")
        return

    # The result column name may vary based on volume name case
    status_json = None
    for key, value in result[0].items():
        if "SYSTEM$VERIFY_EXTERNAL_VOLUME" in key.upper():
            status_json = value
            break

    if not status_json:
        click.echo("⚠ Could not find verification result")
        return

    # Parse the JSON response
    try:
        verification = json.loads(status_json)
        success = verification.get("success", False)
        storage_result = verification.get("storageLocationSelectionResult", "N/A")

        if success:
            click.echo("✓ External volume verified successfully")
        else:
            click.echo("✗ External volume verification failed")

        click.echo(f"  success: {success}")
        click.echo(f"  storageLocationSelectionResult: {storage_result}")

    except json.JSONDecodeError:
        # Fallback to raw output if not valid JSON
        if "success" in status_json.lower():
            click.echo("✓ External volume verified successfully")
        else:
            click.echo(f"⚠ Verification result: {status_json}")


# =============================================================================
# CLI Commands
# =============================================================================


@click.group()
@click.option(
    "--region",
    "-r",
    envvar="AWS_REGION",
    default="us-west-2",
    help="AWS region (or set AWS_REGION env var)",
)
@click.option(
    "--prefix",
    "-p",
    envvar="EXTVOLUME_PREFIX",
    default=None,
    help="Prefix for AWS resources (default: current username). Use --no-prefix to disable.",
)
@click.option(
    "--no-prefix",
    is_flag=True,
    help="Disable username prefix for AWS resources",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output (info level logging for snow CLI)",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug output (debug level logging for snow CLI, shows SQL)",
)
@click.pass_context
def cli(
    ctx: click.Context, region: str, prefix: str | None, no_prefix: bool, verbose: bool, debug: bool
) -> None:
    """
    Snowflake External Volume Manager

    Setup and manage external volumes for Apache Iceberg tables with S3 storage.

    \b
    By default, AWS resources are prefixed with your username to avoid conflicts
    in shared accounts. Use --no-prefix to disable or --prefix to customize.

    \b
    Debug options:
        --verbose  Show info level output from snow CLI
        --debug    Show debug output including SQL statements

    \b
    Prerequisites:
    - AWS credentials configured (aws configure or environment variables)
    - Snowflake CLI configured (snow connection test)
    - Appropriate permissions in both AWS and Snowflake
    """
    # Set global snow CLI options
    set_snow_cli_options(verbose=verbose, debug=debug)

    ctx.ensure_object(dict)
    ctx.obj["region"] = region

    # Determine prefix: explicit prefix > no-prefix flag > default (username)
    if no_prefix:
        ctx.obj["prefix"] = None
    elif prefix:
        ctx.obj["prefix"] = prefix
    else:
        ctx.obj["prefix"] = get_current_username()

    if ctx.obj["prefix"]:
        click.echo(f"Using prefix: {ctx.obj['prefix']}")


@cli.command()
@click.option(
    "--bucket",
    "-b",
    required=True,
    envvar="BUCKET",
    help="S3 bucket base name (will be prefixed with username)",
)
@click.option(
    "--role-name",
    default=None,
    help="IAM role name (default: {prefix}-{bucket}-snowflake-role)",
)
@click.option(
    "--policy-name",
    default=None,
    help="IAM policy name (default: {prefix}-{bucket}-snowflake-policy)",
)
@click.option(
    "--volume-name",
    envvar="EXTERNAL_VOLUME_NAME",
    default=None,
    help="Snowflake external volume name (default: {PREFIX}_{BUCKET}_EXTERNAL_VOLUME)",
)
@click.option(
    "--storage-location-name",
    default=None,
    help="Storage location name (default: {prefix}-{bucket}-s3-{region})",
)
@click.option(
    "--external-id",
    default=None,
    help="External ID for trust relationship (default: auto-generated unique ID)",
)
@click.option(
    "--no-writes",
    is_flag=True,
    help="Create read-only external volume",
)
@click.option(
    "--skip-verify",
    is_flag=True,
    help="Skip external volume verification",
)
@click.pass_context
def create(
    ctx: click.Context,
    bucket: str,
    role_name: str | None,
    policy_name: str | None,
    volume_name: str | None,
    storage_location_name: str | None,
    external_id: str | None,
    no_writes: bool,
    skip_verify: bool,
) -> None:
    """
    Create S3 bucket, IAM role, and Snowflake external volume.

    \b
    This command:
    1. Creates an S3 bucket with versioning enabled
    2. Creates an IAM policy for S3 access
    3. Creates an IAM role with initial trust policy
    4. Creates a Snowflake external volume
    5. Retrieves Snowflake's IAM user ARN
    6. Updates IAM role trust policy for Snowflake access
    7. Verifies the external volume connectivity

    \b
    AWS resources are prefixed with your username by default.
    Snowflake objects use SQL-safe naming (hyphens become underscores, UPPERCASE).

    \b
    Example:
        extvolume create --bucket iceberg-data
        # Creates: ksampath-iceberg-data (S3), KSAMPATH_ICEBERG_DATA_EXTERNAL_VOLUME (Snowflake)

        extvolume --no-prefix create --bucket my-bucket
        # Creates: my-bucket (S3), MY_BUCKET_EXTERNAL_VOLUME (Snowflake)
    """
    # Validate bucket name (no dots allowed)
    if "." in bucket:
        raise click.ClickException("Bucket names cannot contain dots (S3 SSL limitation)")

    region = ctx.obj["region"]
    prefix = ctx.obj.get("prefix")

    # Generate AWS names (lowercase, hyphens)
    aws_bucket_name = to_aws_name(bucket, prefix)
    aws_role_name = role_name or to_aws_name(f"{bucket}-snowflake-role", prefix)
    aws_policy_name = policy_name or to_aws_name(f"{bucket}-snowflake-policy", prefix)
    aws_storage_location = storage_location_name or to_aws_name(f"{bucket}-s3-{region}", prefix)

    # Generate Snowflake names (uppercase, underscores, SQL-safe)
    sf_volume_name = volume_name or to_sql_identifier(f"{bucket}_external_volume", prefix)
    # Generate a unique external ID for security (prevents confused deputy problem)
    sf_external_id = external_id or generate_external_id(bucket, prefix)

    config = ExternalVolumeConfig(
        bucket_name=aws_bucket_name,
        role_name=aws_role_name,
        policy_name=aws_policy_name,
        volume_name=sf_volume_name,
        storage_location_name=aws_storage_location,
        external_id=sf_external_id,
        aws_region=region,
        allow_writes=not no_writes,
    )

    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Create")
    click.echo("=" * 60)
    click.echo()
    click.echo(f"Prefix:           {prefix or '(none)'}")
    click.echo()
    click.echo("AWS Resources (lowercase, hyphens):")
    click.echo(f"  Bucket:           {config.bucket_name}")
    click.echo(f"  IAM Role:         {config.role_name}")
    click.echo(f"  IAM Policy:       {config.policy_name}")
    click.echo(f"  Storage Location: {config.storage_location_name}")
    click.echo()
    click.echo("Snowflake Objects (UPPERCASE, underscores):")
    click.echo(f"  External Volume:  {config.volume_name}")
    click.echo(f"  External ID:      {config.external_id}")
    click.echo()
    click.echo(f"Region:           {config.aws_region}")
    click.echo(f"Allow Writes:     {config.allow_writes}")
    click.echo()

    # Initialize AWS clients
    s3_client = boto3.client("s3", region_name=region)
    iam_client = boto3.client("iam")
    sts_client = boto3.client("sts")

    account_id = get_aws_account_id(sts_client)
    click.echo(f"AWS Account ID: {account_id}")
    click.echo()

    # Step 1: Create S3 bucket
    click.echo("─" * 40)
    click.echo("Step 1: Create S3 Bucket")
    click.echo("─" * 40)
    create_s3_bucket(s3_client, config.bucket_name, region)
    click.echo()

    # Step 2: Create IAM policy
    click.echo("─" * 40)
    click.echo("Step 2: Create IAM Policy")
    click.echo("─" * 40)
    policy_arn = create_iam_policy(iam_client, config.policy_name, config.bucket_name)
    click.echo()

    # Step 3: Create IAM role with initial trust policy
    click.echo("─" * 40)
    click.echo("Step 3: Create IAM Role")
    click.echo("─" * 40)
    role_arn = create_iam_role(
        iam_client, config.role_name, policy_arn, account_id, config.external_id
    )
    click.echo()

    # Wait a bit for IAM propagation
    click.echo("Waiting for IAM propagation...")
    time.sleep(10)

    # Step 4: Create Snowflake external volume
    click.echo("─" * 40)
    click.echo("Step 4: Create Snowflake External Volume")
    click.echo("─" * 40)
    create_external_volume(config, role_arn)
    click.echo()

    # Step 5: Get Snowflake IAM user ARN
    click.echo("─" * 40)
    click.echo("Step 5: Retrieve Snowflake IAM User")
    click.echo("─" * 40)
    sf_props = describe_external_volume(config.volume_name)
    click.echo()

    # Step 6: Update trust policy
    click.echo("─" * 40)
    click.echo("Step 6: Update IAM Trust Policy")
    click.echo("─" * 40)
    # Use the external ID from Snowflake if different from what we specified
    actual_external_id = sf_props.get("external_id", config.external_id)
    update_role_trust_policy(
        iam_client, config.role_name, sf_props["iam_user_arn"], actual_external_id
    )
    click.echo()

    # Wait for trust policy propagation
    click.echo("Waiting for trust policy propagation...")
    time.sleep(10)

    # Step 7: Verify
    if not skip_verify:
        click.echo("─" * 40)
        click.echo("Step 7: Verify External Volume")
        click.echo("─" * 40)
        verify_external_volume(config.volume_name)
        click.echo()

    click.echo("=" * 60)
    click.echo("✓ External volume setup completed successfully!")
    click.echo("=" * 60)
    click.echo()
    click.echo("You can now create Iceberg tables using:")
    click.echo()
    click.echo("  CREATE OR REPLACE ICEBERG TABLE my_iceberg_table (")
    click.echo("      id INT,")
    click.echo("      name STRING,")
    click.echo("      created_at TIMESTAMP_NTZ,")
    click.echo("      amount DECIMAL(10,2)")
    click.echo("    )")
    click.echo("    CATALOG = 'SNOWFLAKE'")
    click.echo(f"    EXTERNAL_VOLUME = '{config.volume_name}'")
    click.echo("    BASE_LOCATION = 'my_iceberg_table';")
    click.echo()
    click.echo("Or with partitioning:")
    click.echo()
    click.echo("  CREATE OR REPLACE ICEBERG TABLE my_partitioned_table (")
    click.echo("      id INT,")
    click.echo("      category STRING,")
    click.echo("      event_date DATE,")
    click.echo("      data VARIANT")
    click.echo("    )")
    click.echo("    CATALOG = 'SNOWFLAKE'")
    click.echo("    PARTITION BY (category)")
    click.echo(f"    EXTERNAL_VOLUME = '{config.volume_name}'")
    click.echo("    BASE_LOCATION = 'my_partitioned_table';")
    click.echo()
    click.echo("See: https://docs.snowflake.com/user-guide/tables-iceberg-create")


@cli.command()
@click.option(
    "--bucket",
    "-b",
    required=True,
    envvar="BUCKET",
    help="S3 bucket base name (same as used in create)",
)
@click.option(
    "--role-name",
    default=None,
    help="IAM role name (default: {prefix}-{bucket}-snowflake-role)",
)
@click.option(
    "--policy-name",
    default=None,
    help="IAM policy name (default: {prefix}-{bucket}-snowflake-policy)",
)
@click.option(
    "--volume-name",
    envvar="EXTERNAL_VOLUME_NAME",
    default=None,
    help="Snowflake external volume name (default: {PREFIX}_{BUCKET}_EXTERNAL_VOLUME)",
)
@click.option(
    "--delete-bucket",
    is_flag=True,
    help="Also delete the S3 bucket (use with --force to delete non-empty bucket)",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force delete bucket even if not empty",
)
@click.confirmation_option(prompt="Are you sure you want to delete these resources?")
@click.pass_context
def delete(
    ctx: click.Context,
    bucket: str,
    role_name: str | None,
    policy_name: str | None,
    volume_name: str | None,
    delete_bucket: bool,
    force: bool,
) -> None:
    """
    Delete external volume and associated AWS resources.

    \b
    This command:
    1. Drops the Snowflake external volume
    2. Deletes the IAM role
    3. Deletes the IAM policy
    4. Optionally deletes the S3 bucket

    \b
    Uses the same naming conventions as create (with username prefix by default).

    \b
    Example:
        extvolume delete --bucket iceberg-data
        extvolume delete --bucket my-bucket --delete-bucket --force
    """
    region = ctx.obj["region"]
    prefix = ctx.obj.get("prefix")

    # Generate AWS names (lowercase, hyphens)
    aws_bucket_name = to_aws_name(bucket, prefix)
    aws_role_name = role_name or to_aws_name(f"{bucket}-snowflake-role", prefix)
    aws_policy_name = policy_name or to_aws_name(f"{bucket}-snowflake-policy", prefix)

    # Generate Snowflake names (uppercase, underscores, SQL-safe)
    sf_volume_name = volume_name or to_sql_identifier(f"{bucket}_external_volume", prefix)

    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Delete")
    click.echo("=" * 60)
    click.echo()
    click.echo(f"Bucket:          {aws_bucket_name}")
    click.echo(f"IAM Role:        {aws_role_name}")
    click.echo(f"IAM Policy:      {aws_policy_name}")
    click.echo(f"External Volume: {sf_volume_name}")
    click.echo()

    # Initialize AWS clients
    s3_client = boto3.client("s3", region_name=region)
    iam_client = boto3.client("iam")
    sts_client = boto3.client("sts")

    account_id = get_aws_account_id(sts_client)
    policy_arn = f"arn:aws:iam::{account_id}:policy/{aws_policy_name}"

    # Step 1: Drop external volume
    click.echo("─" * 40)
    click.echo("Step 1: Drop External Volume")
    click.echo("─" * 40)
    drop_external_volume(sf_volume_name)
    click.echo()

    # Step 2: Delete IAM role
    click.echo("─" * 40)
    click.echo("Step 2: Delete IAM Role")
    click.echo("─" * 40)
    delete_iam_role(iam_client, aws_role_name, policy_arn)
    click.echo()

    # Step 3: Delete IAM policy
    click.echo("─" * 40)
    click.echo("Step 3: Delete IAM Policy")
    click.echo("─" * 40)
    delete_iam_policy(iam_client, policy_arn)
    click.echo()

    # Step 4: Delete bucket (optional)
    if delete_bucket:
        click.echo("─" * 40)
        click.echo("Step 4: Delete S3 Bucket")
        click.echo("─" * 40)
        delete_s3_bucket(s3_client, aws_bucket_name, force=force)
        click.echo()

    click.echo("=" * 60)
    click.echo("✓ Resources deleted successfully!")
    click.echo("=" * 60)


@cli.command()
@click.option(
    "--volume-name",
    "-v",
    envvar="EXTERNAL_VOLUME_NAME",
    required=True,
    help="Snowflake external volume name",
)
def verify(volume_name: str) -> None:
    """
    Verify an existing external volume.

    \b
    Example:
        extvolume verify --volume-name my_external_volume
    """
    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Verify")
    click.echo("=" * 60)
    click.echo()

    verify_external_volume(volume_name)

    click.echo()
    click.echo("=" * 60)


@cli.command()
@click.option(
    "--volume-name",
    "-v",
    envvar="EXTERNAL_VOLUME_NAME",
    required=True,
    help="Snowflake external volume name",
)
def describe(volume_name: str) -> None:
    """
    Describe an existing external volume.

    \b
    Example:
        extvolume describe --volume-name my_external_volume
    """
    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Describe")
    click.echo("=" * 60)
    click.echo()

    props = describe_external_volume(volume_name)

    click.echo()
    click.echo("Properties:")
    for key, value in props.items():
        click.echo(f"  {key}: {value}")

    click.echo()
    click.echo("=" * 60)


@cli.command(name="update-trust")
@click.option(
    "--bucket",
    "-b",
    envvar="BUCKET",
    default=None,
    help="S3 bucket base name (to derive role and volume names)",
)
@click.option(
    "--role-name",
    "-r",
    default=None,
    help="IAM role name to update (or derived from --bucket)",
)
@click.option(
    "--volume-name",
    "-v",
    envvar="EXTERNAL_VOLUME_NAME",
    default=None,
    help="Snowflake external volume name (or derived from --bucket)",
)
@click.pass_context
def update_trust(
    ctx: click.Context,
    bucket: str | None,
    role_name: str | None,
    volume_name: str | None,
) -> None:
    """
    Update IAM trust policy from existing external volume.

    Use this if you need to re-sync the trust policy after changes.

    \b
    Provide either --bucket (to derive names) or both --role-name and --volume-name.

    \b
    Example:
        extvolume update-trust --bucket iceberg-data
        extvolume update-trust --role-name my-role --volume-name MY_VOLUME
    """
    prefix = ctx.obj.get("prefix")

    # Determine role and volume names
    if bucket:
        aws_role_name = role_name or to_aws_name(f"{bucket}-snowflake-role", prefix)
        sf_volume_name = volume_name or to_sql_identifier(f"{bucket}_external_volume", prefix)
    elif role_name and volume_name:
        aws_role_name = role_name
        sf_volume_name = volume_name
    else:
        raise click.ClickException("Provide either --bucket or both --role-name and --volume-name")

    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Update Trust Policy")
    click.echo("=" * 60)
    click.echo()
    click.echo(f"IAM Role:        {aws_role_name}")
    click.echo(f"External Volume: {sf_volume_name}")
    click.echo()

    iam_client = boto3.client("iam")

    # Get Snowflake IAM user from external volume
    props = describe_external_volume(sf_volume_name)
    click.echo()

    # Update trust policy
    update_role_trust_policy(
        iam_client,
        aws_role_name,
        props["iam_user_arn"],
        props.get("external_id", ""),
    )

    click.echo()
    click.echo("=" * 60)
    click.echo("✓ Trust policy updated successfully!")
    click.echo("=" * 60)


if __name__ == "__main__":
    cli()
