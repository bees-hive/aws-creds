#!/usr/bin/env python3
from pathlib import Path
from dataclasses import dataclass
from argparse import ArgumentParser, HelpFormatter
from hashlib import sha1
import os
import sys

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
    client_creds = sso_oidc.register_client(clientName="myapp", clientType="public")
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
            return sso_oidc.create_token(
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_code,
                clientId=client_creds["clientId"],
                clientSecret=client_creds["clientSecret"],
            )["accessToken"]
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
    for account in sso.list_accounts(accessToken=token, maxResults=100)["accountList"]:
        account_name = account["accountName"]
        account_id = account["accountId"]
        account_roles = sso.list_account_roles(accessToken=token, accountId=account_id)
        for role in account_roles["roleList"]:
            print(
                "alias "
                + f"{account_name}-{role['roleName']}".lower().replace(" ", "-").replace(".", "")
                + f"='eval \"$({_prog} session-ic {ic.ic_start_url} {ic.ic_region} {account_id} {role['roleName']})\"'"
            )


def _connect(ic: IdentityCenter, account_id: str, role: str) -> None:
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


def _describe_credentials() -> None:
    sessiont_type = os.getenv("AWS_CREDS_SESSION_TYPE")
    if sessiont_type == "ic":
        print("Auth type:  AWS IAM Identity Center", file=sys.stderr)
        print(
            "Account  :  {} ({})".format(
                os.getenv("AWS_CREDS_ACCOUNT_NAME"),
                os.getenv("AWS_CREDS_ACCOUNT_ID"),
            ),
            file=sys.stderr,
        )
        print("Used role: ", os.getenv("AWS_CREDS_ROLE_NAME"), file=sys.stderr)

    else:
        print(f"Cannot find AWS credentials configured by {_prog}.", file=sys.stderr)


def main():
    parser = ArgumentParser(
        description="Painless CLI authentication using various AWS identities.",
        prog=_prog,
        formatter_class=lambda prog: HelpFormatter(prog, width=72),
    )
    subparsers = parser.add_subparsers(title="Commands", dest="subcommand")
    scan_parser = subparsers.add_parser(
        "scan-ic",
        description="""
        The command generates login aliases for each role available in the AWS IAM Identity Center.
        The aliases should be saved to the to relevant shell configuration file.
        """,
        help="generates shell authentication aliases for an AWS Identity Center",
        formatter_class=lambda prog: HelpFormatter(prog, width=72),
    )
    scan_parser.add_argument("ic_start_url", help="AWS IAM Identity Center start URL")
    scan_parser.add_argument("ic_region", help="AWS IAM Identity Center region")

    session_parser = subparsers.add_parser(
        "session-ic",
        description="""
        The command exports the environment variables suitable for authenticating CLI tools
        by creating a AWS login sessing based on the AWS Identity Center role.
        """,
        help="authenticates an AWS Identity Center role",
        formatter_class=lambda prog: HelpFormatter(prog, width=72),
    )
    session_parser.add_argument("ic_start_url", help="AWS IAM Identity Center start URL")
    session_parser.add_argument("ic_region", help="AWS IAM Identity Center region")
    session_parser.add_argument("account_id", help="Account ID")
    session_parser.add_argument("role_name", help="Role")

    session_parser = subparsers.add_parser(
        "describe-creds",
        description="""
            The command describes the current credentials if available.""",
        help="describes the current credentials if available",
        formatter_class=lambda prog: HelpFormatter(prog, width=72),
    )

    args = parser.parse_args()

    if args.subcommand == "scan-ic":
        _identity_center_scan(IdentityCenter(args.ic_start_url, args.ic_region))
    elif args.subcommand == "session-ic":
        _connect(
            IdentityCenter(args.ic_start_url, args.ic_region),
            args.account_id,
            args.role_name,
        )
        _describe_credentials()
    elif args.subcommand == "describe-creds":
        _describe_credentials()
    else:
        _describe_credentials()


if __name__ == "__main__":
    main()
