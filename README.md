# AWS Credentials

`aws-creds` configures your CLI access to AWS services by setting the environment variables in your shell based on
- IAM Identity Center credentials; or
- IAM User credentials (access key)
  - Automatic MFA support
  - Assume role support

**How does it work?**

You ask `aws-creds` to scan specific connection sources (such as the current local AWS configuration,
AWS IAM Identity Center URL, etc.), and it generates shell aliases for you. Those aliases should be saved
to the shell configuration profile file like `.bashrc`, `.zshrc`, etc. Once done, the next time
you need to authenticate a specific connection, you run the appropriate alias. It authenticates depending on
the configuration and exports the AWS session environment variables to the current shell session. The tools
such as `aws`, `terraform`, `boto3`, and others will automatically use those variables while executing
requested commands. Once you no longer need the session, you can run `aws-creds-clear-session`
to unset the environment variables.

After the successful authentication, the following AWS-related environment variables are set:
- `AWS_ACCESS_KEY_ID`
- `AWS_DEFAULT_REGION`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

Please visit [this AWS page](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html#envvars-list) for details.

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
usage: aws-creds [-h] {describe-creds,scan-local,scan-ic,session-ic,session-access-key} ...

Painless CLI authentication using various AWS identities.

options:
  -h, --help            show this help message and exit

Commands:
  {describe-creds,scan-local,scan-ic,session-ic,session-access-key}
    describe-creds      describes the AWS credentials in the current shell session
    scan-local          generates shell aliases for the local AWS CLI configuration
    scan-ic             generates shell aliases for an AWS IAM Identity Center
    session-ic          authenticates an AWS Identity Center role
    session-access-key  authenticates an access key
```

### `aws-creds describe-creds`
```shell
~ aws-creds describe-creds --help
usage: aws-creds describe-creds [-h]

The command describes the AWS credentials in the current shell session by looking at the environment
variables. Besides, this command runs every time you run `aws-creds` without arguments.

options:
  -h, --help  show this help message and exit
```
### `aws-creds scan-local`
```shell
~ aws-creds scan-local --help
usage: aws-creds scan-local [-h]

The command runs an interactive workflow to create the `aws-creds` shell aliases based on the local
AWS CLI config. Pick those aliases you want and save them to your shell configuration profile file.
Once you run an alias, it will authenticate a session and export the AWS session environment
variables to the current shell session.

options:
  -h, --help  show this help message and exit
```

### `aws-creds scan-ic`
```shell
~ aws-creds scan-ic --help
usage: aws-creds scan-ic [-h] --ic-start-url URL --ic-region region

The command generates all possible `aws-creds` shell aliases for each role available in an AWS IAM
Identity Center. Pick those aliases you want and save them to your shell configuration profile file.
Once you run an alias, it will authenticate a session and export the AWS session environment
variables to the current shell session.

options:
  -h, --help          show this help message and exit
  --ic-start-url URL  AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)
  --ic-region region  AWS IAM Identity Center region (like `us-east-1`)
```

### `aws-creds session-ic`
```shell
~ aws-creds session-ic --help
usage: aws-creds session-ic [-h] --ic-start-url URL --ic-region region --account-id id --role-name
                            name

The command exports the environment variables suitable for authenticating CLI tools by creating an
AWS login session based on the AWS IAM Identity Center role. Any AWS IAM Identity Center alias will
use this command to authenticate.

options:
  -h, --help          show this help message and exit
  --ic-start-url URL  AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)
  --ic-region region  AWS IAM Identity Center region (like `us-east-1`)
  --account-id id     AWS Account ID
  --role-name name    Role name
```

### `aws-creds session-access-key`
```shell
~ aws-creds session-access-key --help
usage: aws-creds session-access-key [-h] --session-name name --access-key key --secret-access-key
                                    secret-key --region region [--assume-role-arn role]

The command exports the environment variables suitable for authenticating CLI tools by creating an
AWS login session based on the AWS Access Key. It asks to provide an MFA code if an MFA device is
configured. Any AWS Access Key alias will use this command to authenticate.

options:
  -h, --help                      show this help message and exit
  --session-name name             A name
  --access-key key                Access Key
  --secret-access-key secret-key  Secret Access Key
  --region region                 AWS Region
  --assume-role-arn role          A role to assume
```
