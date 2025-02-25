# aws-creds

`aws-creds` is a lightweight tool designed to simplify the AWS credentials management.

**Table of Contents**

- [Motivation](#motivation)
- [Background](#background)
  - [Primary AWS Credential Types](#primary-aws-credential-types)
  - [Standard AWS Credentials Management](#standard-aws-credentials-management)
  - [How `aws-creds` Simplifies AWS Credentials Management](#how-aws-creds-simplifies-aws-credentials-management)
- [Implementation](#implementation)
- [Installation](#installation)
- [Usage](#usage)
  - [`aws-creds`](#aws-creds)
  - [`aws-creds describe-creds`](#aws-creds-describe-creds)
  - [`aws-creds scan-local`](#aws-creds-scan-local)
  - [`aws-creds scan-ic`](#aws-creds-scan-ic)
  - [`aws-creds session-ic`](#aws-creds-session-ic)
  - [`aws-creds session-access-key`](#aws-creds-session-access-key)
- [Tips and Tricks](#tips-and-tricks)
  - [Saving the Shell Functions Guide](#saving-the-shell-functions-guide)
  - [Automating AWS Region Detection](#automating-aws-region-detection)

## Motivation

Imagine you're an engineer who frequently works with multiple AWS accounts or roles. Each time you switch between them,
you must ensure you're using the correct credentials, which can be challenging and time-consuming. The real
hassle isn't the initial setup but the constant need to switch between different credentials, especially when
managing multiple environments or projects. Keeping track of which account or role you're using and ensuring you have
the right permissions for each task can quickly become overwhelming and prone to errors.

Meet `aws-creds` — a tool designed to make your life easier by automating this process and allowing you to focus on
what really matters: building and deploying applications.

## Background

### Primary AWS Credential Types

Before diving into `aws-creds`, it's helpful to understand the most common AWS credentials types and how they're used:

1. AWS IAM Identity Center allows users to authenticate through a centralized access management
   system and retrieve temporary credentials for AWS CLI usage.
2. IAM Users consist of an access key ID and a secret access key, used for programmatic access to AWS services via the
   CLI. MFA (Multi-Factor Authentication) could be enabled as an additional security layer that can be configured to
   require a second form of verification in addition to the access key.
3. IAM Roles are used to delegate access to IAM users that normally don't have access to AWS resources, often used for
   cross-account access or to grant limited access to specific resources. When a role is assumed, temporary security
   credentials are created and used to access the resources.

### Standard AWS Credentials Management

The standard approaches to managing AWS credentials are the following:

1. **Using AWS IAM Identity Center**
    - AWS IAM Identity Center is a centralized access management system that allows you to manage access to multiple AWS
      accounts and roles. After setting up, you can use `aws sso login` to authenticate and retrieve temporary
      credentials.
    - While this approach simplifies access management, it requires you to run multiple commands to authenticate and set
      up your environment, especially if you use MFA or assume roles.

2. **Using AWS CLI Configuration Files**
    - The AWS CLI typically uses configuration files located in `~/.aws/config` and `~/.aws/credentials` to manage
      different profiles. Each profile can store access keys, secret keys, default regions, and output formats.
    - You can switch between these profiles using the `--profile` flag when running AWS CLI commands. While this is a
      straightforward method, it requires you to manually manage and switch between profiles, which can become
      cumbersome if you handle multiple accounts or roles.

These standard methods provide flexibility, but they often involve a lot of manual steps and can be tedious, especially
when managing multiple AWS environments. Please refer to the official AWS documentation for more information on these:

- [AWS Sign-In](https://docs.aws.amazon.com/signin/latest/userguide/what-is-sign-in.html)
- [AWS Command Line Interface Authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-authentication.html)
- [IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html)

### How `aws-creds` Simplifies AWS Credentials Management

`aws-creds` minimizes the manual actions needed to use specific AWS credentials by wrapping each credential in a
separate shell function. These functions can be easily invoked to authenticate and set up the necessary environment
variables for the AWS CLI, Terraform, or other tools. By automating the process of retrieving and exporting AWS
credentials, `aws-creds` streamlines the management of your AWS connections.

**How does it work?**

1. **Starting Point:** you begin by asking `aws-creds` to scan for specific credential sources. These could be existing
   configurations on your local machine ([`aws-creds scan-local`](#aws-creds-scan-local)) or an AWS IAM Identity Center
   URL ([`aws-creds scan-ic`](#aws-creds-scan-ic)).
2. **Shell Function Generation:** Based on the information it finds, `aws-creds` generates shell functions for each
   credential. These functions act as shortcuts that you can use to quickly authenticate and set up your environment
   when needed.
3. **Saving the Functions:** To make sure these functions are always at your fingertips, you save them to your shell
   configuration file (see [Saving the Shell Functions Guide](#saving-the-shell-functions-guide) for the details). This
   ensures that every time you start a new shell session, your functions are ready to use.

## Implementation

`aws-creds` is a Python script that uses `boto3` to interact with AWS APIs. Each time you run a shell
function, `aws-creds` communicates with AWS to retrieve the necessary credentials and sets them in your shell
environment. Designed to be lightweight and easy to use, all you need is Python 3.8 or above.

Upon successful authentication, the following AWS-related environment variables are set:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_DEFAULT_REGION`
- `AWS_REGION`
- `AWS_DEFAULT_OUTPUT`

> For more details, visit the official [AWS environment variables documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list).

Additionally, `aws-creds` automatically adjusts the shell prompt to display the active session, similar to how Python or
Ruby virtual environments update their interactive prompts. This feature is optional and can be disabled using
the `--no-prompt-update` flag.

If you need to clear the session, simply run `aws-creds-clear-session` to unset the environment variables.
Running `aws-creds` without arguments will display the current session details.

Moreover, `aws-creds` supports safe overrides, allowing you to replace the active credentials with new ones by running
the appropriate shell function.

## Installation

The latest version can be installed using the following command:

```shell
# install to the '/usr/local/bin' directory
curl -sSL https://raw.githubusercontent.com/bees-hive/aws-creds/main/install.sh | bash
# install to the custom directory
curl -sSL https://raw.githubusercontent.com/bees-hive/aws-creds/main/install.sh | INSTALL_DIR=/some/path bash
```

For Brew users, just run `brew install bees-hive/hive/aws-creds`.

## Usage

### `aws-creds`

```shell
~ aws-creds --help
usage: aws-creds [-h] [--version]
                 {describe-creds,scan-local,scan-ic,session-ic,session-access-key} ...

Painless CLI authentication using various AWS identities.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

Commands:
  {describe-creds,scan-local,scan-ic,session-ic,session-access-key}
    describe-creds      describes the AWS credentials in the current shell session
    scan-local          generates shell functions for the local AWS CLI configuration
    scan-ic             generates shell functions for an AWS IAM Identity Center
    session-ic          authenticates an AWS Identity Center role
    session-access-key  authenticates an access key
```

### `aws-creds describe-creds`

```shell
~ aws-creds describe-creds --help
usage: aws-creds describe-creds [-h]

This command displays the current AWS credentials by inspecting the relevant environment variables
in the shell session. Additionally, it executes automatically whenever aws-creds is run without any
arguments.

options:
  -h, --help  show this help message and exit
```

### `aws-creds scan-local`

```shell
~ aws-creds scan-local --help
usage: aws-creds scan-local [-h]

This command starts an interactive workflow to create aws-creds shell functions based on your local
AWS CLI configuration. Save the desired functions to your shell profile file for future use.

options:
  -h, --help  show this help message and exit
```

### `aws-creds scan-ic`

```shell
~ aws-creds scan-ic --help
usage: aws-creds scan-ic [-h] [--ic-start-url URL] [--ic-region region]

This command generates all possible aws-creds shell functions for each available account and role in
AWS IAM Identity Center. Save the desired functions to your shell profile file for future use.

options:
  -h, --help          show this help message and exit
  --ic-start-url URL  AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)
  --ic-region region  AWS IAM Identity Center region (like `us-east-1`)
```

### `aws-creds session-ic`

```shell
~ aws-creds session-ic --help
usage: aws-creds session-ic [-h] --ic-start-url URL --ic-region region --account-id id
                            --role-name name [--aws-region region]
                            [--output {json,text,table,yaml,yaml-stream}] [--no-prompt-update]
                            [--prompt-text text] [--prompt-color color]

This command exports environment variables needed to authenticate CLI tools by initiating an AWS
login session based on the AWS IAM Identity Center role.

options:
  -h, --help            show this help message and exit
  --ic-start-url URL    AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)
  --ic-region region    AWS IAM Identity Center region (like `us-east-1`)
  --account-id id       AWS Account ID
  --role-name name      Role name
  --aws-region region   An AWS region where the AWS resources are located ('--ic-region' value is
                        used if unset).
  --output {json,text,table,yaml,yaml-stream}
                        An output format (default: 'json').
  --no-prompt-update    Disables a shell prompt modification if specified
  --prompt-text text    Custom text to show in shell prompt (default: role@account)
  --prompt-color color  Specifies the shell prompt color either by a numeric tput color code or by
                        one of these predefined names: black, red, green, yellow, blue, magenta,
                        cyan, or white
```

### `aws-creds session-access-key`

```shell
~ aws-creds session-access-key --help
usage: aws-creds session-access-key [-h] --session-name name --access-key key
                                    --secret-access-key secret-key --region region
                                    [--assume-role-arn role]
                                    [--output {json,text,table,yaml,yaml-stream}]
                                    [--no-prompt-update] [--prompt-text text] [--prompt-color color]

This command exports the environment variables required to authenticate CLI tools by creating an AWS
login session using the AWS Access Key. If an MFA device is configured, it will prompt for an MFA
code.

options:
  -h, --help                       show this help message and exit
  --session-name name              A name
  --access-key key                 Access Key
  --secret-access-key secret-key   Secret Access Key
  --region region                  AWS Region
  --assume-role-arn role           A role to assume
  --output {json,text,table,yaml,yaml-stream}
                                   An output format (default: 'json').
  --no-prompt-update               Disables a shell prompt update if specified
  --prompt-text text               Custom text to show in shell prompt (default: session name)
  --prompt-color color             Specifies the shell prompt color either by a numeric tput color
                                   code or by one of these predefined names: black, red, green,
                                   yellow, blue, magenta, cyan, or white
```

## Tips and Tricks

### Saving the Shell Functions Guide

Once `aws-creds` generates the shell functions for your AWS connections, the next crucial step is to save these
functions
so that they're always available when you need them. This section walks you through the process of adding new functions
to your shell configuration profile and how to use them effectively.

1. **Locate your Shell configuration file**: Depending on the shell you use (e.g., Bash, Zsh), the configuration file
   where you need to save the functions might vary: for Bash users, the file is usually `~/.bashrc`; for Zsh users, the
   file is typically `~/.zshrc`. If you're using a different shell, find the appropriate configuration file where
   functions and environment variables are set during the start of a new shell session.
2. **Add functions**: Carefully read the output of any `aws-creds scan-*` commands and copy the desired generated
   functions to the shell configuration file.
   It typically provides them in a format like this:

   ```shell
   aws-creds-profile1() {
     eval "$(
       aws-creds ...
     )"
   }
   aws-creds-profile2() {
     eval "$(
       aws-creds ...
     )"
   }
   ```

3. **Activate functions:** Save and close the configuration file. You can start new terminal sessions to see the new
   functions available. Or to apply the changes immediately without having to close and reopen your terminal, reload the
   shell configuration
   file with the following command: `source ~/.bashrc` or `source ~/.zshrc` depending on your shell.
4. **Using the functions**: Now that the functions are set up, you can easily switch between different AWS profiles by
   simply typing the corresponding function name in your terminal. For example: `aws-creds-profile1`.
   Running this command will automatically authenticate using the specified profile and export the necessary AWS
   environment variables to your current session. You can start typing `aws-creds-` and press Tab to see and select from
   the available
   functions.

### Automating AWS Region Detection

In some scenarios, you may need to switch between AWS regions using the same credentials. You can either create multiple
shell functions with the same credentials but different regions or automate region detection. The Bash function below is
designed to identify the AWS region based on the current working directory, or prompt the user for input if the region
cannot be detected:

```bash
__directory_region() {
  local directory="$(basename $(pwd))"
  local regions=(
    "us-east-1"
    "us-east-2"
    "eu-west-1"
  )
  # Attempt to detect the AWS region by checking if the current directory name contains a region code.
  for region in "${regions[@]}"; do
    if [[ $directory == *"$region"* ]]; then
      echo "$region"
      return 0
    fi
  done
  # If no region is found in the directory name, prompt the user for input with a default option.
  local default_region="us-east-1"
  while true; do
    echo -n "Enter the region (default: ${default_region}): " >&2
    read -r user_region
    local region=${user_region:-$default_region}
    # Validate user input against the predefined list of regions.
    if [[ ${regions[*]} =~ ${region} ]]; then
      echo "$region"
      return 0
    fi
  done
  echo "No region detected in the folder name: ${directory}" >&2
  exit 1
}
```

You can combine this region detection function (or any other) with `aws-creds` for automatic AWS region selection like:

```shell
aws-creds-profile1() {
  eval "$(
    aws-creds session-ic \
      ... \
      --aws-region $(__directory_region) \
      ...
  )"
}
```
