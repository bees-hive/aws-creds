# AWS Credentials

`aws-creds` configures your CLI access to AWS services by setting the environment variables in your shell based on
- IAM Identity Center authentication; or
- IAM user (access key and secret key) (work in progress).

**How does it work?**

You ask `aws-creds` to scan specific connection sources (such as the current local AWS configuration,
AWS IAM Identity Center URL, etc.), and it generates shell aliases for you. Those aliases should be saved
to the shell configuration profile file like `.bashrc`, `.zshrc`, etc. Once done, the next time
you need to authenticate a specific connection, you run the appropriate alias. It authenticates depending on
the configuration and exports the AWS session environment variables to the current shell session. The tools
such as `aws`, `terraform`, `boto3`, and others will automatically use those variables while executing
requested commands.

## Installation

The latest version can be installed using the following command:
`curl -sSL https://raw.githubusercontent.com/bees-hive/aws-creds/main/install.sh | bash`

For Brew users, just run `brew install bees-hive/hive/aws-creds`.

## Usage

`aws-creds` has the following CLI interface:

```shell
~ aws-creds --help
usage: aws-creds [-h] {describe-creds,scan-local,scan-ic,session-ic} ...

Painless CLI authentication using various AWS identities.

options:
  -h, --help            show this help message and exit

Commands:
  {describe-creds,scan-local,scan-ic,session-ic}
    describe-creds      describes the AWS credentials in the currrent shell session
    scan-local          generates shell aliases for the local AWS CLI configuration
    scan-ic             generates shell aliases for an AWS IAM Identity Center
    session-ic          authenticates an AWS Identity Center role

```

Below you can find more detailed explanations of the commands.

### `aws-creds describe-creds`

This command describes the current credentials by looking at the environment variables. It is configured as the default
command, so you can run `aws-creds` without any arguments to see the current credentials.

## `aws-creds scan-local`

If the AWS CLI is installed and configured, you can convert the existing connections to the `aws-creds` aliases
by running the `aws-creds scan` command. It runs an interactive alias generation process that allows you to decide
which connections to convert.

> Only AWS IAM Identity Center aliases are generated now.

### `aws-creds scan-ic`

If you have the AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`) and
its region (like `us-east-1`), the `aws-creds scan-ic https://xxxxxx.awsapps.com/start us-east-1` command
generates all possible login aliases for this AWS IAM Identity Center (AWS SSO). Pick those you want and save them
to the shell configuration profile file. Once you run an alias, it will open the browser and ask you to authenticate.
After successful authentication, it will export the AWS session environment variables to the current shell session.

### `aws-creds session-ic`

Any AWS IAM Identity Center-related alias uses this command to authenticate the AWS session.
You should not use it directly, but it is available for manual use.
