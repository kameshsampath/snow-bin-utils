# Snow Utils

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A command-line toolkit for automating Snowflake infrastructure setup — specifically **External Volumes** for Apache Iceberg tables and **Programmatic Access Tokens (PATs)** for service accounts.

## Why This Tool?

Setting up Snowflake external volumes requires coordinating multiple AWS and Snowflake resources with specific trust relationships. Similarly, PAT management involves network policies, authentication policies, and proper role restrictions. This tool automates these complex workflows into simple commands.

**Without this tool:** 10+ manual steps across AWS Console, IAM, S3, and Snowflake UI.

**With this tool:** One command.

## TL;DR — Common Workflows

```bash
# 🚀 Setup external volume for Iceberg tables
snow-utils extvolume:up

# 🔑 Create PAT for a service account
snow-utils pat:create SA_USER=my_sa SA_ROLE=my_role PAT_OBJECTS_DB=my_db

# 🗑️ Tear everything down
snow-utils extvolume:down
snow-utils pat:remove
```

## Features

| Feature | Description |
|---------|-------------|
| **External Volume Management** | Create, verify, and delete Snowflake external volumes with S3 storage |
| **AWS Resource Automation** | Automatically provisions S3 buckets, IAM roles, and policies |
| **PAT Management** | Create, rotate, and remove Programmatic Access Tokens |
| **Smart Naming** | Resources prefixed with your username to avoid conflicts |
| **Environment-Driven** | Configure once in `.env`, run commands without parameters |

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| [Task](https://taskfile.dev/) | Task runner | `brew install go-task` |
| [uv](https://docs.astral.sh/uv/) | Python package manager | `brew install uv` |
| [Snowflake CLI](https://docs.snowflake.com/en/developer-guide/snowflake-cli/index) | `snow` command | `pip install snowflake-cli-labs` |
| [AWS CLI](https://aws.amazon.com/cli/) | AWS operations | `brew install awscli` |
| Python 3.11+ | Runtime | - |

> **Windows Users:** This tool requires a Unix-like shell. Please use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) (Windows Subsystem for Linux) or Git Bash.

**Required permissions:**

- **AWS:** S3 full access, IAM role/policy management
- **Snowflake:** `ACCOUNTADMIN` or role with external volume privileges

---

## Installation

### 1. Clone and Setup

```bash
git clone https://github.com/kameshsampath/snow-bin-utils
cd snow-bin-utils

# Setup Python environment
task setup
```

### 2. Install as Global Command (Optional)

```bash
ln -sf "$(pwd)/snow-utils" ~/.local/bin/snow-utils
```

> Ensure `~/.local/bin` is in your `PATH`

### 3. Enable Tab Completion (Optional)

**Zsh** (save to your completions directory):

```bash
snow-utils --completion zsh > ~/.config/zsh/completions/_snow-utils
# Or wherever your fpath completions are stored
```

> Ensure your `~/.zshrc` has the completions directory in `fpath` before `compinit`:
>
> ```zsh
> fpath+=/path/to/completions
> autoload -Uz compinit && compinit
> ```

**Bash** (append to `.bashrc`):

```bash
snow-utils --completion bash >> ~/.bashrc
source ~/.bashrc
```

### 4. Configure Environment

Create a `.env` file (or copy from `.env.example`):

```bash
# Snowflake connection
SNOWFLAKE_DEFAULT_CONNECTION_NAME=default
SNOWFLAKE_ROLE=ACCOUNTADMIN
SNOWFLAKE_DATABASE=MY_DATABASE

# AWS (optional, defaults to us-west-2)
AWS_REGION=us-west-2

# External Volume (optional)
BUCKET=iceberg-demo

# PAT Management (optional)
SA_USER=my_service_user
SA_ROLE=demo_role
SA_ADMIN_ROLE=sysadmin
PAT_OBJECTS_DB=my_db
```

### 5. Verify Installation

```bash
# Check snow-utils is available
snow-utils --help

# Test Snowflake connection
snow-utils snow:test

# Test AWS credentials
snow-utils aws:whoami
```

---

## External Volume Management

> **📚 Documentation:**
>
> - [Configure an External Volume](https://docs.snowflake.com/user-guide/tables-iceberg-configure-external-volume)
> - [Configure an External Volume for Amazon S3](https://docs.snowflake.com/user-guide/tables-iceberg-configure-external-volume-s3)
> - [Create Iceberg Tables with Snowflake Catalog](https://docs.snowflake.com/user-guide/tables-iceberg-create#label-tables-iceberg-create-snowflake-catalog)

### What Gets Created

When you run `extvolume:create`, the following resources are provisioned:

```
┌─────────────────────────────────────────────────────────────┐
│                         AWS                                 │
├─────────────────────────────────────────────────────────────┤
│  S3 Bucket:     {username}-{bucket}                         │
│  IAM Policy:    {username}-{bucket}-snowflake-policy        │
│  IAM Role:      {username}-{bucket}-snowflake-role          │
│                 └── Trust policy → Snowflake IAM user       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      Snowflake                              │
├─────────────────────────────────────────────────────────────┤
│  External Volume: {USERNAME}_{BUCKET}_EXTERNAL_VOLUME       │
│                   └── References S3 bucket via IAM role     │
└─────────────────────────────────────────────────────────────┘
```

### Commands

| Command | Description |
|---------|-------------|
| `extvolume:up` | Quick start — create bucket and external volume with defaults |
| `extvolume:down` | Tear down — delete bucket and external volume |
| `extvolume:create` | Create S3 bucket, IAM role, and Snowflake external volume |
| `extvolume:delete` | Delete external volume and AWS resources |
| `extvolume:verify` | Verify external volume connectivity |
| `extvolume:describe` | Describe external volume properties |
| `extvolume:update-trust` | Update IAM trust policy from external volume |

### Examples

```bash
# Quick start with defaults (uses BUCKET from env or 'iceberg-demo')
snow-utils extvolume:up

# Create with custom bucket
snow-utils extvolume:create BUCKET=my-data

# Create without username prefix
snow-utils extvolume:create BUCKET=my-data -- --no-prefix

# Create with custom prefix
snow-utils extvolume:create BUCKET=my-data -- --prefix myproject

# Verify volume connectivity
snow-utils extvolume:verify VOLUME=MY_EXTERNAL_VOLUME

# Delete (keeps S3 bucket)
snow-utils extvolume:delete BUCKET=my-data

# Delete everything including S3 bucket
snow-utils extvolume:delete BUCKET=my-data -- --delete-bucket --force
```

> **Note:** The `--` separates Task variables (`VAR=value`) from CLI flags (`--flag`).

---

## PAT Management

> **📚 Documentation:**
>
> - [Using Programmatic Access Tokens](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)
> - [ALTER USER ... ADD PROGRAMMATIC ACCESS TOKEN](https://docs.snowflake.com/en/sql-reference/sql/alter-user-add-programmatic-access-token)

### What Gets Created

When you run `pat`, the following resources are provisioned:

```
┌─────────────────────────────────────────────────────────────┐
│                      Snowflake                              │
├─────────────────────────────────────────────────────────────┤
│  Service User:       {SA_USER} (TYPE=SERVICE)               │
│                      └── Granted role: {SA_ROLE}            │
│                                                             │
│  Network Rule:       {SA_USER}_NETWORK_RULE                 │
│                      └── Allows your current IP             │
│                                                             │
│  Network Policy:     {SA_USER}_NETWORK_POLICY               │
│                      └── References network rule            │
│                                                             │
│  Auth Policy:        {SA_USER}_AUTH_POLICY                  │
│                      └── PAT-only authentication            │
│                                                             │
│  PAT:                {SA_USER}_PAT                          │
│                      └── Role restriction: {SA_ROLE}        │
└─────────────────────────────────────────────────────────────┘
```

### Commands

| Command | Description |
|---------|-------------|
| `pat:create` | Create/rotate PAT for service user |
| `pat:no-rotate` | Remove existing PAT and create new (allows changing role) |
| `pat:remove` | Remove PAT and associated objects |

### Two Roles Explained

| Role | Purpose | Example |
|------|---------|---------|
| `SA_ROLE` | Role restriction for the PAT — what the service account can do | `DEMO_ROLE` |
| `SA_ADMIN_ROLE` | Role for creating policies/rules — needs elevated privileges | `SYSADMIN` |

### Examples

```bash
# Create PAT with separate admin role
snow-utils pat:create SA_USER=my_sa SA_ROLE=demo_role SA_ADMIN_ROLE=sysadmin PAT_OBJECTS_DB=my_db

# Create PAT (admin-role defaults to SA_ROLE)
snow-utils pat:create SA_USER=my_sa SA_ROLE=my_role PAT_OBJECTS_DB=my_db

# Create using env vars from .env file
snow-utils pat:create

# Remove and recreate PAT (to change role restriction)
snow-utils pat:no-rotate

# Remove PAT and policies (keeps user)
snow-utils pat:remove SA_USER=my_sa PAT_OBJECTS_DB=my_db

# Remove only the PAT (keep network/auth policies)
snow-utils pat:remove -- --pat-only

# Remove everything including the service user
snow-utils pat:remove -- --drop-user
```

### Using the PAT

After creation, the PAT token is saved to your `.env` file as `SNOWFLAKE_PASSWORD`. Use it:

```bash
# In your application
export SNOWFLAKE_USER=$SA_USER
export SNOWFLAKE_PASSWORD='<pat_token>'
export SNOWFLAKE_ACCOUNT='<your_account>'

# Or with snow CLI
snow sql --user $SA_USER --account $ACCOUNT -q "SELECT 1"
```

---

## Snowflake & AWS Shortcuts

### Snowflake Commands

| Command | Description |
|---------|-------------|
| `snow:test` | Test Snowflake connection |
| `snow:sql` | Run SQL query |
| `snow:volumes` | List all external volumes |
| `snow:pats` | List programmatic access tokens |

```bash
snow-utils snow:test
snow-utils snow:sql -- "SELECT CURRENT_TIMESTAMP()"
snow-utils snow:volumes
snow-utils snow:pats PAT_USER=my_service_user
```

### AWS Commands

| Command | Description |
|---------|-------------|
| `aws:whoami` | Show current AWS identity |
| `aws:buckets` | List S3 buckets (filtered by username prefix) |
| `aws:roles` | List IAM roles (filtered by snowflake) |

---

## Naming Conventions

Resources are **prefixed with your username** by default to avoid conflicts in shared accounts.

### Example (BUCKET=iceberg-demo, user: ksampath)

| Type | Resource | Name |
|------|----------|------|
| AWS | S3 Bucket | `ksampath-iceberg-demo` |
| AWS | IAM Role | `ksampath-iceberg-demo-snowflake-role` |
| AWS | IAM Policy | `ksampath-iceberg-demo-snowflake-policy` |
| Snowflake | External Volume | `KSAMPATH_ICEBERG_DEMO_EXTERNAL_VOLUME` |

### Customizing Prefixes

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

---

## Environment Variables Reference

All variables can be set in `.env` or exported in your shell.

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

### External Volume

| Variable | Description | Default |
|----------|-------------|---------|
| `BUCKET` | S3 bucket base name | `iceberg-demo` |
| `EXTERNAL_VOLUME_NAME` | Snowflake external volume name | - |

### PAT Management

| Variable | Description | Default |
|----------|-------------|---------|
| `SA_USER` | Service account username | - |
| `SA_ROLE` | Role restriction for PAT | - |
| `SA_ADMIN_ROLE` | Admin role for creating policies | `SA_ROLE` |
| `PAT_OBJECTS_DB` | Database for PAT objects | - |
| `DOT_ENV_FILE` | Path to .env file for credentials | `.env` |

---

## Debugging

Both `pat.py` and `extvolume.py` support verbose and debug modes for troubleshooting:

```bash
# Verbose mode - shows info level output from snow CLI
snow-utils --verbose extvolume:create BUCKET=my-data
snow-utils pat:create -v SA_USER=my_sa ...

# Debug mode - shows SQL statements and full output
snow-utils --debug extvolume:create BUCKET=my-data
snow-utils pat:create -d SA_USER=my_sa ...
```

| Flag | Short | Effect |
|------|-------|--------|
| `--verbose` | `-v` | Info level logging from snow CLI |
| `--debug` | `-d` | Debug output including SQL statements |

**Note:** Place the flag **before** the subcommand (e.g., `snow-utils --debug extvolume:create`).

---

## Troubleshooting

### External Volume Issues

**"STORAGE_AWS_IAM_USER_ARN not found"**

```bash
# Re-sync the trust policy
snow-utils extvolume:update-trust BUCKET=my-data
```

**"External volume verification failed"**

```bash
# Check IAM trust policy is correct
aws iam get-role --role-name {username}-{bucket}-snowflake-role

# Verify external volume settings
snow-utils extvolume:describe VOLUME=MY_VOLUME
```

### PAT Issues

**"PAT authentication failed"**

- Ensure network policy allows your IP
- Check PAT hasn't expired: `snow-utils snow:pats`
- Verify role is granted to user

**"DOT_ENV_FILE not updating the right file"**

```bash
# Specify absolute path
snow-utils pat DOT_ENV_FILE=/absolute/path/to/project/.env
```

### General Issues

**"snow command not found"**

```bash
pip install snowflake-cli-labs
```

**"Task not found"**

```bash
brew install go-task
```

**"Permission denied" on AWS operations**

- Verify AWS credentials: `snow-utils aws:whoami`
- Check IAM permissions for S3 and IAM operations

---

## Getting Help

```bash
# List all tasks
snow-utils --help

# Get detailed help for a specific task
snow-utils <task-name> --summary

# Examples
snow-utils extvolume:create --summary
snow-utils pat:create --summary
snow-utils help:naming
```

---

## Development

```bash
# Setup environment
task setup              # or: uv venv && uv sync

# Install dependencies
task install            # or: uv sync

# Lint code
uv run ruff check .

# Format code
uv run ruff format .

# Lint and fix
uv run ruff check . --fix
```

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

Copyright 2024 Kamesh Sampath
