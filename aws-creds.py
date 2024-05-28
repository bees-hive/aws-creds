#!/usr/bin/env python3
from abc import abstractmethod
from pathlib import Path
from dataclasses import dataclass
from argparse import ArgumentParser, HelpFormatter
from hashlib import sha1
import os
import sys
from typing import Dict, Optional

_prog = Path(__file__).name.split(".")[0]
_dependencies_home = Path.home().joinpath(".cache").joinpath(_prog)


def _remove_contents(directory: Path) -> None:
    for entry in directory.iterdir():
        if entry.is_dir():
            _remove_contents(entry)
            entry.rmdir()
        else:
            if str(entry).startswith(".ic."):
                continue
            entry.unlink()


def pip_wtf(dependencies: str) -> None:
    sys.path = [p for p in sys.path if "-packages" not in p] + [str(_dependencies_home)]
    os.environ["PATH"] += os.pathsep + str(_dependencies_home.joinpath("bin"))
    os.environ["PYTHONPATH"] = os.pathsep.join(sys.path)
    dependencies_hash = _dependencies_home.joinpath(f".d.{sha1(dependencies.encode()).hexdigest()}")
    if dependencies_hash.exists():
        return
    print("Cache directory:", _dependencies_home)
    _dependencies_home.mkdir(exist_ok=True)
    _remove_contents(_dependencies_home)
    dependencies_hash.touch(exist_ok=True)
    os.system(" ".join([sys.executable, "-m", "pip", "install", "--target", str(_dependencies_home), dependencies]))


if sys.version_info < (3, 7):
    print("Support Python 3.7 or above", file=sys.stderr)
    exit(1)

pip_wtf("boto3==1.34.40")
from botocore.session import Session  # noqa: E402


@dataclass
class IdentityCenter:
    ic_start_url: str
    ic_region: str

    def cache_file(self) -> Path:
        return _dependencies_home.joinpath(f".ic.{sha1(bytes(self.ic_start_url, 'utf-8')).hexdigest()}")


def _new_session_token(identity_center: IdentityCenter) -> str:
    sso_oidc = Session().create_client("sso-oidc", region_name=identity_center.ic_region)
    client_creds = sso_oidc.register_client(clientName=_prog, clientType="public", scopes=["sso:account:access"])
    device_authorization = sso_oidc.start_device_authorization(
        clientId=client_creds["clientId"],
        clientSecret=client_creds["clientSecret"],
        startUrl=identity_center.ic_start_url,
    )
    url = device_authorization["verificationUriComplete"]
    device_code = device_authorization["deviceCode"]
    expires_in = device_authorization["expiresIn"]
    interval = device_authorization["interval"]
    import webbrowser

    webbrowser.open(url, autoraise=True)
    code_line = "Authorization code: " + device_authorization["userCode"]
    print(code_line, end="\r", file=sys.stderr)
    from time import sleep

    message = code_line
    for n in range(1, expires_in // interval + 1):
        sleep(interval)
        message = code_line + f" (awaiting {n} seconds)"
        print(message, end="\r", file=sys.stderr)
        try:
            response = sso_oidc.create_token(
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_code,
                clientId=client_creds["clientId"],
                clientSecret=client_creds["clientSecret"],
            )
            print(" " * len(message), end="\r", file=sys.stderr)
            return response["accessToken"]
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass


def _cached_token(access_token_file_name: Path) -> str:
    with open(access_token_file_name, "r") as access_token_file:
        return access_token_file.readline()


def _new_token(identity_center: IdentityCenter) -> str:
    with open(identity_center.cache_file(), "w") as access_token_file:
        access_token = _new_session_token(identity_center)
        access_token_file.write(access_token)
        return access_token


def _token(identity_center: IdentityCenter) -> str:
    print("AWS IAM Identity Center URL: ", identity_center.ic_start_url, file=sys.stderr)  # noqa: F821
    while True:
        if identity_center.cache_file().exists():
            print("Previous session found...", file=sys.stderr)
            access_token = _cached_token(identity_center.cache_file())
        else:
            print("Initializing new session...", file=sys.stderr)
            access_token = _new_token(identity_center)
        try:
            Session().create_client("sso", region_name=identity_center.ic_region).list_accounts(
                accessToken=access_token, maxResults=1
            )
            return access_token
        except Exception as error:  # botocore.errorfactory.UnauthorizedException
            if "UnauthorizedException" not in str(error):
                raise error
            identity_center.cache_file().unlink()
            print("Previous session expired...", file=sys.stderr)


def _identity_center_scan(ic: IdentityCenter) -> None:
    sso = Session().create_client("sso", region_name=ic.ic_region)
    token = _token(ic)
    print("Generated shell aliases:", file=sys.stdout)
    for account in sso.list_accounts(accessToken=token, maxResults=100)["accountList"]:
        account_name = account["accountName"]
        account_id = account["accountId"]
        account_roles = sso.list_account_roles(accessToken=token, accountId=account_id)
        for role in account_roles["roleList"]:
            _print_identity_center_alias(ic, account_id, account_name, role["roleName"])


def _print_identity_center_alias(
    ic: IdentityCenter, account_id: str, account_name: str, role_name: str, *, file=sys.stdout
) -> None:
    print(
        f"{account_name}-{role_name}".lower().replace(" ", "-").replace(".", ""),
        "() {\n",
        '  eval "$(\n',
        f"    {_prog} session-ic \\\n",
        f"      --ic-start-url {ic.ic_start_url} \\\n",
        f"      --ic-region {ic.ic_region} \\\n",
        f"      --account-id {account_id} \\\n",
        f"      --role-name {role_name}\n",
        '  )"\n}',
        sep="",
        file=file,
    )


def _session_ic(ic: IdentityCenter, account_id: str, role: str) -> None:
    sso = Session().create_client("sso", region_name=ic.ic_region)
    token = _token(ic)
    role_creds = sso.get_role_credentials(roleName=role, accountId=account_id, accessToken=token)["roleCredentials"]
    account_name = ""
    for account in sso.list_accounts(accessToken=token, maxResults=100)["accountList"]:
        if account["accountId"] != account_id:
            continue
        account_name = account["accountName"]
        break
    print('export AWS_CREDS_SESSION_TYPE="ic"', file=sys.stdout)
    print(f'export AWS_CREDS_ACCOUNT_NAME="{account_name}"', file=sys.stdout)
    print(f'export AWS_CREDS_ACCOUNT_ID="{account_id}"', file=sys.stdout)
    print(f'export AWS_CREDS_ROLE_NAME="{role}"', file=sys.stdout)
    print(f'export AWS_DEFAULT_REGION="{ic.ic_region}"', file=sys.stdout)
    print(f'export AWS_ACCESS_KEY_ID="{role_creds["accessKeyId"]}"', file=sys.stdout)
    print(f'export AWS_SECRET_ACCESS_KEY="{role_creds["secretAccessKey"]}"', file=sys.stdout)
    print(f'export AWS_SESSION_TOKEN="{role_creds["sessionToken"]}"', file=sys.stdout)
    print("AWS environment variables are exported!", file=sys.stderr)
    _print_ic_information(account_name, account_id, role)


def _print_ic_information(account_name: str, account_id: str, role_name: str) -> None:
    print("Auth type:  AWS IAM Identity Center", file=sys.stderr)
    print(f"Account  :  {account_name} ({account_id})", file=sys.stderr)  # noqa: E999
    print("Used role: ", role_name, file=sys.stderr)


def _access_key(name: str, access_key: str, secret_key: str, region: str) -> None:
    try:
        arn = (
            Session()
            .create_client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            .get_caller_identity()["Arn"]
        )
    except Exception as error:  # botocore.exceptions.ClientError
        if "The security token included in the request is invalid." in str(error):
            print("Invalid access key or secret access key!", file=sys.stderr)
            return
        raise error
    print(f"Generated shell alias (IAM user: '{arn.split(':user/')[-1]}'):", file=sys.stdout)
    print(
        f"{name}".lower().replace(" ", "-").replace(".", ""),
        "() {\n",
        '  eval "$(\n',
        f"    {_prog} session-access-key \\\n",
        f"      --session-name {name} \\\n",
        f"      --access-key {access_key} \\\n",
        f"      --secret-access-key {secret_key} \\\n",
        f"      --region {region} \\\n",
        '  )"\n}',
        sep="",
        file=sys.stdout,
    )


def _access_key_assume_role(name: str, access_key: str, secret_key: str, region: str, role_arn: str) -> None:
    try:
        arn = (
            Session()
            .create_client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            .get_caller_identity()["Arn"]
        )
    except Exception as error:  # botocore.exceptions.ClientError
        if "The security token included in the request is invalid." in str(error):
            print("Invalid access key or secret access key!", file=sys.stderr)
            return
        raise error
    print(f"Generated shell alias (IAM user: '{arn.split(':user/')[-1]}'):", file=sys.stdout)
    print(
        f"{name}".lower().replace(" ", "-").replace(".", ""),
        "() {\n",
        '  eval "$(\n',
        f"    {_prog} session-access-key \\\n",
        f"      --session-name {name} \\\n",
        f"      --access-key {access_key} \\\n",
        f"      --secret-access-key {secret_key} \\\n",
        f"      --region {region} \\\n",
        f"      --assume-role-arn {role_arn} \\\n",
        '  )"\n}',
        sep="",
        file=sys.stdout,
    )


class _Auth:
    @abstractmethod
    def perform(self, mfa_device: Optional[str], mfa_code: Optional[str]) -> None:
        pass


def _print_assume_role(session_name: str, user: str, account_id: str, region: str, role: str) -> None:
    print("Auth type:  Assume role via AWS Access Key", file=sys.stderr)
    print(f"Profile  :  {session_name}", file=sys.stderr)
    print(f"IAM user :  {user}", file=sys.stderr)  # noqa: E999
    print(f"Account  :  {account_id}", file=sys.stderr)  # noqa: E999
    print(f"Role     :  {role}", file=sys.stderr)  # noqa: E999
    print(f"Region   :  {region}", file=sys.stderr)  # noqa: E999


class _AssumeRole(_Auth):
    def __init__(self, sts, session_name: str, user_name: str, account_id: str, region: str, role_arn: str) -> None:
        self._sts = sts
        self._session_name = session_name
        self._user_name = user_name
        self._role_arn = role_arn
        self._account_id = account_id
        self._region = region

    def perform(self, mfa_device: Optional[str], mfa_code: Optional[str]) -> None:
        if mfa_device and mfa_code:
            session = self._sts.assume_role(
                RoleArn=self._role_arn, RoleSessionName=self._session_name, SerialNumber=mfa_device, TokenCode=mfa_code
            )
        else:
            session = self._sts.assume_role(RoleArn=self._role_arn, RoleSessionName=self._session_name)
        temp_credentials = session["Credentials"]
        print('export AWS_CREDS_SESSION_TYPE="ar"', file=sys.stdout)
        print(f'export AWS_CREDS_SESSION_NAME="{self._session_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_SESSION_ROLE="{self._role_arn}"', file=sys.stdout)
        print(f'export AWS_CREDS_USER_NAME="{self._user_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_ACCOUNT_ID="{self._account_id}"', file=sys.stdout)
        print(f'export AWS_ACCESS_KEY_ID="{temp_credentials["AccessKeyId"]}"', file=sys.stdout)
        print(f'export AWS_SECRET_ACCESS_KEY="{temp_credentials["SecretAccessKey"]}"', file=sys.stdout)
        print(f'export AWS_SESSION_TOKEN="{temp_credentials["SessionToken"]}"', file=sys.stdout)
        print(f'export AWS_DEFAULT_REGION="{self._region}"', file=sys.stdout)
        print("AWS environment variables are exported!", file=sys.stderr)
        _print_assume_role(self._session_name, self._user_name, self._account_id, self._region, self._role_arn)


def _print_access_key(session_name: str, user: str, account_id: str, region: str) -> None:
    print("Auth type:  AWS Access Key", file=sys.stderr)
    print(f"Profile  :  {session_name}", file=sys.stderr)
    print(f"IAM user :  {user}", file=sys.stderr)  # noqa: E999
    print(f"Account  :  {account_id}", file=sys.stderr)  # noqa: E999
    print(f"Region   :  {region}", file=sys.stderr)  # noqa: E999


class _AccessKey(_Auth):
    def __init__(self, sts, session_name: str, user_name: str, account_id: str, region: str) -> None:
        self._sts = sts
        self._session_name = session_name
        self._user_name = user_name
        self._account_id = account_id
        self._region = region

    def perform(self, mfa_device: Optional[str], mfa_code: Optional[str]) -> None:
        if mfa_device and mfa_code:
            session = self._sts.get_session_token(SerialNumber=mfa_device, TokenCode=mfa_code)
        else:
            session = self._sts.get_session_token()
        temp_credentials = session["Credentials"]
        print('export AWS_CREDS_SESSION_TYPE="ak"', file=sys.stdout)
        print(f'export AWS_CREDS_SESSION_NAME="{self._session_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_USER_NAME="{self._user_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_ACCOUNT_ID="{self._account_id}"', file=sys.stdout)
        print(f'export AWS_ACCESS_KEY_ID="{temp_credentials["AccessKeyId"]}"', file=sys.stdout)
        print(f'export AWS_SECRET_ACCESS_KEY="{temp_credentials["SecretAccessKey"]}"', file=sys.stdout)
        print(f'export AWS_SESSION_TOKEN="{temp_credentials["SessionToken"]}"', file=sys.stdout)
        print(f'export AWS_DEFAULT_REGION="{self._region}"', file=sys.stdout)
        print("AWS environment variables are exported!", file=sys.stderr)
        _print_access_key(self._session_name, self._user_name, self._account_id, self._region)


def _session_access_key(name: str, access_key: str, secret_key: str, region: str, role_arn: Optional[str]) -> None:
    sts = Session().create_client(
        "sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region
    )
    try:
        caller_identity = sts.get_caller_identity()
    except Exception as error:  # botocore.exceptions.ClientError
        if "The security token included in the request is invalid." in str(error):
            print("Invalid access key or secret access key!", file=sys.stderr)
            exit(1)
        raise error
    arn = caller_identity["Arn"]  # noqa: F841
    account_id = caller_identity["Account"]
    iam_user = arn.split(":user/")[-1]
    if role_arn:
        auth = _AssumeRole(sts, name, iam_user, account_id, region, role_arn)
    else:
        auth = _AccessKey(sts, name, iam_user, account_id, region)
    mfas: Dict[str, str] = {
        mfa["SerialNumber"].split("/")[-1]: mfa["SerialNumber"]
        for mfa in Session()
        .create_client("iam", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        .list_mfa_devices(UserName=arn.split("/")[-1])["MFADevices"]
        if ":mfa/" in mfa["SerialNumber"]
    }
    if mfas:
        if len(mfas) > 1:
            mfa_name = ""
            while mfa_name not in mfas.keys():
                print("Multiple MFA devices found:", mfas.keys(), file=sys.stderr)
                print("Type a name of the desired device: ", file=sys.stderr, end="")
                mfa_name = input()
        else:
            mfa_name = list(mfas.keys())[0]
        print(f"Enter MFA code (device: {mfa_name}): ", file=sys.stderr, end="")
        auth.perform(mfa_device=mfas[mfa_name], mfa_code=input())
    else:
        auth.perform(mfa_device=None, mfa_code=None)


def _describe_credentials() -> None:
    session_type = os.getenv("AWS_CREDS_SESSION_TYPE", "")
    if session_type == "ic":
        _print_ic_information(
            os.getenv("AWS_CREDS_ACCOUNT_NAME"), os.getenv("AWS_CREDS_ACCOUNT_ID"), os.getenv("AWS_CREDS_ROLE_NAME")
        )
    elif session_type == "ak":
        _print_access_key(
            os.getenv("AWS_CREDS_SESSION_NAME"),
            os.getenv("AWS_CREDS_USER_NAME"),
            os.getenv("AWS_CREDS_ACCOUNT_ID"),
            os.getenv("AWS_DEFAULT_REGION"),
        )
    elif session_type == "ar":
        _print_assume_role(
            os.getenv("AWS_CREDS_SESSION_NAME"),
            os.getenv("AWS_CREDS_USER_NAME"),
            os.getenv("AWS_CREDS_ACCOUNT_ID"),
            os.getenv("AWS_DEFAULT_REGION"),
            os.getenv("AWS_CREDS_SESSION_ROLE"),
        )
    else:
        print(f"Cannot find AWS credentials configured by '{_prog}'.", file=sys.stderr)


def _scan_local():
    local_config = Session().full_config
    print("Scanning the local AWS config files...", file=sys.stdout)
    for key, details in local_config.get("sso_sessions", {}).items():
        print("\nLooking for the next record...", file=sys.stdout)
        print(
            f"The '{key}' AWS IAM Identity Center identified: {details['sso_start_url']} ({details['sso_region']})",
            file=sys.stdout,
        )
        if "y" not in input("Do you want to generate shell aliases? y/n ").lower():
            continue
        _identity_center_scan(IdentityCenter(details["sso_start_url"], details["sso_region"]))
    for key, details in local_config.get("profiles", {}).items():
        if "sso_session" in details:
            continue
        print("\nLooking for the next record...", file=sys.stdout)
        if "role_arn" in details:
            role_arn = details["role_arn"]
            print(f"The '{key}' AWS profile identified that assumes the '{role_arn}' role.", file=sys.stderr)
            if "y" not in input("Do you want to generate shell alias? y/n ").lower():
                continue
            source_profile_alias = details["source_profile"]
            source_profile = local_config.get("profiles", {}).get(source_profile_alias, {})
            if not source_profile:
                print(f"'{source_profile_alias}' source profile not found!", file=sys.stderr)
                continue
            _access_key_assume_role(
                key,
                source_profile["aws_access_key_id"],
                source_profile["aws_secret_access_key"],
                details["region"] or source_profile["region"],
                role_arn,
            )
        else:
            print(f"The '{key}' access key identified.", file=sys.stdout)
            if "y" not in input("Do you want to generate shell alias? y/n ").lower():
                continue
            _access_key(key, details["aws_access_key_id"], details["aws_secret_access_key"], details["region"])
    print("\nScanning completed!", file=sys.stdout)


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "session-ic":
        print(f"The positional arguments are deprecated for the `{_prog} session-ic`!", file=sys.stderr)  # noqa: F821
        print("Please update the alias as follows:\n", file=sys.stderr)  # noqa: F821
        identity_center = IdentityCenter(sys.argv[2], sys.argv[3])
        _print_identity_center_alias(identity_center, sys.argv[4], "account-name", sys.argv[5], file=sys.stderr)  # noqa: F821
        print("\n\n", file=sys.stderr)  # noqa: F821
        _session_ic(identity_center, sys.argv[4], sys.argv[5])
        exit(0)
    parser = ArgumentParser(
        description="Painless CLI authentication using various AWS identities.",
        prog=_prog,
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )
    subparsers = parser.add_subparsers(title="Commands", dest="subcommand")

    subparsers.add_parser(
        "describe-creds",
        description="The command describes the AWS credentials in the current shell session if available.",
        help="describes the AWS credentials in the current shell session",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )

    subparsers.add_parser(
        "scan-local",
        description=f"""
            The command runs an interactive '{_prog}’ shell aliases creation based on
            the local AWS CLI config.
            """,
        help="generates shell aliases for the local AWS CLI configuration",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )

    scan_ic = subparsers.add_parser(
        "scan-ic",
        description="""
        The command generates login aliases for each role available in the AWS IAM Identity Center.
        The aliases should be saved to the to relevant shell configuration file.
        """,
        help="generates shell aliases for an AWS IAM Identity Center",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )
    scan_ic.add_argument("--ic-start-url", metavar="URL", required=True, help="AWS IAM Identity Center start URL")
    scan_ic.add_argument("--ic-region", metavar="region", required=True, help="AWS IAM Identity Center region")

    session_ic = subparsers.add_parser(
        "session-ic",
        description="""
        The command exports the environment variables suitable for authenticating CLI tools
        by creating a AWS login session based on the AWS IAM Identity Center role.
        """,
        help="authenticates an AWS Identity Center role",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )
    session_ic.add_argument("--ic-start-url", metavar="URL", required=True, help="AWS IAM Identity Center start URL")
    session_ic.add_argument("--ic-region", metavar="region", required=True, help="AWS IAM Identity Center region")
    session_ic.add_argument("--account-id", metavar="id", required=True, help="AWS Account ID")
    session_ic.add_argument("--role-name", metavar="name", required=True, help="Role name")

    session_ic = subparsers.add_parser(
        "session-access-key",
        description="""
            The command exports the environment variables suitable for authenticating CLI tools
            by creating an AWS login session based on the Access Key and Secret Access Key.
            It asks to provide an MFA code if there is an MFA device configured.
            """,
        help="authenticates an access key",
        formatter_class=lambda prog: HelpFormatter(prog, max_help_position=35, width=100),
    )
    session_ic.add_argument("--session-name", metavar="name", required=True, help="A name")
    session_ic.add_argument("--access-key", metavar="key", required=True, help="Access Key")
    session_ic.add_argument("--secret-access-key", metavar="secret-key", required=True, help="Secret Access Key")
    session_ic.add_argument("--region", metavar="region", required=True, help="AWS Region")
    session_ic.add_argument("--assume-role-arn", metavar="role", required=False, help="A role to assume")

    args = parser.parse_args()

    if args.subcommand == "scan-ic":
        _identity_center_scan(IdentityCenter(args.ic_start_url, args.ic_region))
    elif args.subcommand == "session-ic":
        _session_ic(IdentityCenter(args.ic_start_url, args.ic_region), args.account_id, args.role_name)
    elif args.subcommand == "session-access-key":
        _session_access_key(
            args.session_name, args.access_key, args.secret_access_key, args.region, args.assume_role_arn
        )
    elif args.subcommand == "describe-creds":
        _describe_credentials()
    elif args.subcommand == "scan-local":
        _scan_local()
    else:
        _describe_credentials()


if __name__ == "__main__":
    main()
