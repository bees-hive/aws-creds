# AWS Credentials

`aws-creds` configures your CLI access to AWS services by setting some
environment variables in your shell based on
- IAM Identity Center authentication; or
- IAM user (access key and secret key) (TODO)

**How does it work?**

You ask `aws-creds` to scan specific connection sources (such as AWS IAM Identity Center URL,
current local AWS config, etc.), and it generates shell aliases for you (alternatively, you can
create aliases on your own). Those aliases should be saved to the shell configuration profile
file like `.bashrc`, `.zshrc`, etc. Once done, the next time you need to authenticate a specific
connection, you run the appropriate alias. It authenticates depending on the configuration
and exports the AWS session environment variables to the current shell session. The tools such
as `aws`, `terraform`, `boto3`, and others will automatically use those variables while executing
requested commands.


## Installation

The latest version can be installed using the following command:
`curl -sSL https://raw.githubusercontent.com/bees-hive/aws-creds/main/install.sh | bash`

## Getting Started

### AWS IAM Identity Center (AWS SSO)

You should have the IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)
and its region (like `us-east-1`). `aws-creds scan-ic https://xxxxxx.awsapps.com/start us-east-1` command
generates all possible login aliases. Pick those you want and save them to the shell configuration profile file.
Once you run an alias, it will open the browser and ask you to authenticate. After successful authentication,
it will export the AWS session environment variables to the current shell session.
