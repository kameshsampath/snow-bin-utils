# Snow Utils

A collection of utilities for managing various Snowflake objects including External Volumes and Programmatic Access Tokens (PATs). Automates the creation of S3 buckets, IAM roles/policies, and Snowflake external volumes with proper trust relationships.

## Features

- **External Volume Management** - Create, verify, and delete Snowflake external volumes with S3 storage
- **AWS Resource Automation** - Automatically provisions S3 buckets, IAM roles, and policies
- **PAT Management** - Create and rotate Programmatic Access Tokens for service accounts
- **Smart Naming** - Resources are prefixed with your username to avoid conflicts in shared accounts
- **One-Command Setup** - Quick start commands for common workflows

## Prerequisites

- [Task](https://taskfile.dev/) - Task runner (`brew install go-task`)
- [uv](https://docs.astral.sh/uv/) - Python package manager (`brew install uv`)
- [Snowflake CLI](https://docs.snowflake.com/en/developer-guide/snowflake-cli/index) - `snow` command
- [AWS CLI](https://aws.amazon.com/cli/) - Configured with appropriate permissions
- Python 3.11+

## Installation

### 1. Clone and Setup

```bash
git clone https://github.com/kameshsampath/snow-bin-utils
cd snow-bin-utils

# Setup Python environment
task setup
```

### 2. Install as Global Command (Optional)

Create a symlink to use `snow-utils` from anywhere:

```bash
ln -sf "$(pwd)/snow-utils" ~/.local/bin/snow-utils
```

> Ensure `~/.local/bin` is in your `PATH`

### 3. Configure Environment

Create a `.env` file with your settings:

```bash
# Snowflake connection
SNOWFLAKE_DEFAULT_CONNECTION_NAME=default
SNOWFLAKE_ROLE=ACCOUNTADMIN
SNOWFLAKE_DATABASE=MY_DATABASE

# AWS region (optional, defaults to us-west-2)
AWS_REGION=us-west-2

# External Volume defaults (optional)
BUCKET=iceberg-demo
EXTERNAL_VOLUME_NAME=MY_EXTERNAL_VOLUME
```

## Quick Start

```bash
# Show all available commands
snow-utils --help

# Create an external volume with defaults (bucket: iceberg-demo)
snow-utils extvolume:up

# Create with custom bucket name
snow-utils extvolume:up BUCKET=my-data

# Tear down everything
snow-utils extvolume:down
```

## Commands Reference

### External Volume Management

| Command | Description |
|---------|-------------|
| `extvolume:up` | Quick start - create bucket and external volume with defaults |
| `extvolume:down` | Tear down - delete bucket and external volume |
| `extvolume:create` | Create S3 bucket, IAM role, and Snowflake external volume |
| `extvolume:delete` | Delete external volume and AWS resources |
| `extvolume:verify` | Verify external volume connectivity |
| `extvolume:describe` | Describe external volume properties |
| `extvolume:update-trust` | Update IAM trust policy from external volume |

#### Examples

```bash
# Quick start with defaults (uses BUCKET from env or 'iceberg-demo')
snow-utils extvolume:up

# Create with custom bucket
snow-utils extvolume:create BUCKET=my-data

# Create without username prefix
snow-utils extvolume:create BUCKET=my-data -- --no-prefix

# Create with custom prefix
snow-utils extvolume:create BUCKET=my-data -- --prefix myproject

# Verify volume connectivity (uses EXTERNAL_VOLUME_NAME from env)
snow-utils extvolume:verify
snow-utils extvolume:verify VOLUME=MY_EXTERNAL_VOLUME

# Describe volume (uses EXTERNAL_VOLUME_NAME from env)
snow-utils extvolume:describe

# Delete (keeps S3 bucket, uses BUCKET from env)
snow-utils extvolume:delete

# Delete everything including S3 bucket
snow-utils extvolume:delete BUCKET=my-data -- --delete-bucket --force
```

### PAT Management

| Command | Description |
|---------|-------------|
| `pat` | Create/rotate PAT for service user |
| `pat:no-rotate` | Create PAT without rotating existing |

#### Examples

```bash
# Create/rotate PAT
snow-utils pat SA_USER=my_service_user SA_ROLE=my_role PAT_OBJECTS_DB=my_db

# Create without rotating existing PAT
snow-utils pat:no-rotate SA_USER=my_service_user SA_ROLE=my_role PAT_OBJECTS_DB=my_db
```

### Snowflake CLI Shortcuts

| Command | Description |
|---------|-------------|
| `snow:test` | Test Snowflake connection |
| `snow:sql` | Run SQL query |
| `snow:volumes` | List all external volumes |
| `snow:pats` | List programmatic access tokens (optionally for a specific user) |

#### Examples

```bash
# Test connection
snow-utils snow:test

# Run SQL query
snow-utils snow:sql -- "SELECT CURRENT_TIMESTAMP()"

# List external volumes
snow-utils snow:volumes

# List your PATs
snow-utils snow:pats

# List PATs for a specific user
snow-utils snow:pats PAT_USER=my_service_user
```

### AWS CLI Shortcuts

| Command | Description |
|---------|-------------|
| `aws:whoami` | Show current AWS identity |
| `aws:buckets` | List S3 buckets (filtered by username prefix) |
| `aws:roles` | List IAM roles (filtered by snowflake) |

### Development

| Command | Description |
|---------|-------------|
| `setup` | Setup development environment with uv |
| `install` | Install dependencies |
| `lint` | Run linting |
| `format` | Format code |

### Help

| Command | Description |
|---------|-------------|
| `help` | Show usage guide and quick start |
| `help:naming` | Explain prefix and naming conventions |
| `help:extvolume` | Show extvolume CLI options |
| `help:pat` | Show pat CLI options |

## Naming Conventions

Resources are **prefixed with your username** by default to avoid conflicts in shared AWS accounts.

### Example (BUCKET=iceberg-demo, user: ksampath)

**AWS Resources** (lowercase, hyphens):

| Resource | Name |
|----------|------|
| S3 Bucket | `ksampath-iceberg-demo` |
| IAM Role | `ksampath-iceberg-demo-snowflake-role` |
| IAM Policy | `ksampath-iceberg-demo-snowflake-policy` |

**Snowflake Objects** (UPPERCASE, underscores):

| Resource | Name |
|----------|------|
| External Volume | `KSAMPATH_ICEBERG_DEMO_EXTERNAL_VOLUME` |
| External ID | `KSAMPATH_ICEBERG_DEMO_EXTERNAL_ID` |

### Prefix Options

```bash
# Default: username prefix
snow-utils extvolume:create BUCKET=data
# → ksampath-data

# No prefix
snow-utils extvolume:create BUCKET=data -- --no-prefix
# → data

# Custom prefix
snow-utils extvolume:create BUCKET=data -- --prefix myproject
# → myproject-data
```

## Environment Variables

All variables can be set in a `.env` file or exported in your shell.

### Snowflake Connection

| Variable | Description | Default |
|----------|-------------|---------|
| `SNOWFLAKE_DEFAULT_CONNECTION_NAME` | Snowflake connection profile | - |
| `SNOWFLAKE_ROLE` | Snowflake role to use | - |
| `SNOWFLAKE_DATABASE` | Default database | - |

### AWS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for resources | `us-west-2` |

### External Volume Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BUCKET` | S3 bucket base name | `iceberg-demo` |
| `EXTERNAL_VOLUME_NAME` | Snowflake external volume name | - |

When these are set, you can run commands without parameters:

```bash
# With env vars set, no need to pass BUCKET
snow-utils extvolume:create
snow-utils extvolume:verify
snow-utils extvolume:describe
```

### PAT-specific Variables

| Variable | Description |
|----------|-------------|
| `SA_USER` | Service account username |
| `SA_ROLE` | Service account role |
| `PAT_OBJECTS_DB` | Database for PAT objects |

## Getting Help

```bash
# List all tasks
snow-utils --help

# Get detailed help for a specific task
snow-utils <task-name> --summary

# Example
snow-utils extvolume:create --summary
```

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
