#!/usr/bin/env python3
from abc import abstractmethod
from pathlib import Path
from dataclasses import dataclass
from argparse import ArgumentParser, HelpFormatter
from hashlib import sha1
import os
import sys
from typing import Dict, Optional, Literal, TextIO

__version__ = "0.7.1+20240821-122541"
_prog = Path(__file__).name.split(".")[0]
_dependencies_home = Path.home().joinpath(".cache").joinpath(_prog)
_clear_session_function_name = f"{_prog}-clear-session"


def _remove_contents(directory: Path) -> None:
    for entry in directory.iterdir():
        if entry.is_dir():
            _remove_contents(entry)
            entry.rmdir()
        else:
            if ".ic." in str(entry):
                continue
            entry.unlink()


def pip_wtf(dependencies: str) -> None:
    sys.path = [p for p in sys.path if "-packages" not in p] + [str(_dependencies_home)]
    os.environ["PATH"] += os.pathsep + str(_dependencies_home.joinpath("bin"))
    os.environ["PYTHONPATH"] = os.pathsep.join(sys.path)
    dependencies_hash = _dependencies_home.joinpath(f".d.{sha1(dependencies.encode()).hexdigest()}")
    if dependencies_hash.exists():
        return
    _dependencies_home.mkdir(exist_ok=True)
    _remove_contents(_dependencies_home)
    dependencies_hash.touch(exist_ok=True)
    os.system(
        " ".join(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--quiet",
                "--target",
                str(_dependencies_home),
                dependencies,
            ]
        )
    )


if sys.version_info < (3, 7):
    print("Support Python 3.7 or above", file=sys.stderr)
    exit(1)

pip_wtf("boto3==1.34.135")
from botocore.session import Session  # noqa: E402


class Printer:
    def __init__(self, mode: Literal["realtime", "end"], out_file: TextIO) -> None:
        self._mode = mode
        self._messages = []
        self._out_file = out_file

    def append(self, message: str) -> None:
        if self._mode == "realtime":
            print(message, file=self._out_file)
        self._messages.append(message)

    def print_all(self, /, always: bool = False) -> None:
        if self._mode == "end" or always:
            for message in self._messages:
                print(message, file=self._out_file)


@dataclass
class IdentityCenter:
    ic_start_url: str
    ic_region: str

    def cache_file(self) -> Path:
        return _dependencies_home.joinpath(f".ic.{sha1(bytes(self.ic_start_url, 'utf-8')).hexdigest()}")

    def __str__(self) -> str:
        return f"AWS IAM Identity Center ({self.ic_start_url}, {self.ic_region})"


class ShellPrompt:
    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled

    def update(self, default_prefix: str) -> None:
        if not self._enabled:
            return
        variable_ = """
        current_shell=$(ps -p $$ | awk "NR==2" | awk '{ print $4 }' | tr -d '-')
        if [[ $current_shell == 'bash' ]]; then
          export AWS_CREDS_PROMPT_PREFIX='\\[\\e[1;31m\\]('${FUNCNAME[0]}')\\[\\e[0m\\]'
        elif [[ $current_shell == 'zsh' ]]; then
          export AWS_CREDS_PROMPT_PREFIX='%B%F{red}('$funcstack[2]')%f%b'
        else
          export AWS_CREDS_PROMPT_PREFIX="({default})"
        fi
        current_prompt="${AWS_CREDS_ORIGIN_PS1:-${PS1:-}}"
        export AWS_CREDS_ORIGIN_PS1="${current_prompt}"
        export PS1="${AWS_CREDS_PROMPT_PREFIX} ${current_prompt}"
        """
        print(variable_.replace("{default}", default_prefix), file=sys.stdout)


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

    print("Opening a browser to authenticate...", file=sys.stderr)
    print(f"Verification URL: {url}", file=sys.stderr)
    webbrowser.open(url, autoraise=True)
    code_line = "Verification code: " + device_authorization["userCode"]
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
    while True:
        if identity_center.cache_file().exists():
            print("Previous AWS IAM Identity Center session found...", file=sys.stderr)
            access_token = _cached_token(identity_center.cache_file())
        else:
            print("Initializing new AWS IAM Identity Center session...", file=sys.stderr)
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
            print("Previous AWS IAM Identity Center session expired...", file=sys.stderr)


def _identity_center_scan(ic: IdentityCenter, printer: Printer) -> None:
    sso = Session().create_client("sso", region_name=ic.ic_region)
    token = _token(ic)
    printer.append(f"# {ic}")
    for account in sso.list_accounts(accessToken=token, maxResults=100)["accountList"]:
        account_name = account["accountName"]
        account_id = account["accountId"]
        account_roles = sso.list_account_roles(accessToken=token, accountId=account_id)
        for role in account_roles["roleList"]:
            _print_identity_center_alias(printer, ic, account_id, account_name, role["roleName"])


def _print_identity_center_alias(
    printer: Printer, ic: IdentityCenter, account_id: str, account_name: str, role_name: str
) -> None:
    printer.append(
        f"{_prog}-{account_name}-{role_name}".lower().replace(" ", "-").replace(".", "")
        + "() {\n"
        + '  eval "$(\n'
        + f"    {_prog} session-ic \\\n"
        + f"      --ic-start-url {ic.ic_start_url} \\\n"
        + f"      --ic-region {ic.ic_region} \\\n"
        + f"      --account-id {account_id} \\\n"
        + f"      --aws-region {ic.ic_region} \\\n"
        + f"      --role-name {role_name}\n"
        + '  )"\n'
        + "}"
    )


def _clear_session_function(prompt_variable: str, *variables: str) -> str:
    return "\n".join(
        [
            f"{_clear_session_function_name}() {{",
            f'  if test -n "${{{prompt_variable}}}"; then',
            f'    export PS1="${{{prompt_variable}-}}"',
            f"    unset {prompt_variable}",
            "  fi",
            "\n".join([f"  unset {variable}" for variable in variables]),
            "}",
        ]
    )


def _print_session_commands_footer():
    print("\nUseful tips:", file=sys.stderr)
    print(f"1. Run `{_prog}` describes current CLI credentials.", file=sys.stderr)
    print(f"2. Run `{_clear_session_function_name}` resets current CLI credentials.", file=sys.stderr)


def _session_ic(
    ic: IdentityCenter, account_id: str, role: str, aws_region: str, output: str, prompt: ShellPrompt
) -> None:
    sso = Session().create_client("sso", region_name=ic.ic_region)
    token = _token(ic)
    role_creds = sso.get_role_credentials(roleName=role, accountId=account_id, accessToken=token)["roleCredentials"]
    account_name = ""
    for account in sso.list_accounts(accessToken=token, maxResults=100)["accountList"]:
        if account["accountId"] != account_id:
            continue
        account_name = account["accountName"]
        break
    prompt.update(f"{role}@{account_name}")
    print('export AWS_CREDS_SESSION_TYPE="ic"', file=sys.stdout)
    print(f'export AWS_CREDS_ACCOUNT_NAME="{account_name}"', file=sys.stdout)
    print(f'export AWS_CREDS_ACCOUNT_ID="{account_id}"', file=sys.stdout)
    print(f'export AWS_CREDS_ROLE_NAME="{role}"', file=sys.stdout)
    print(f'export AWS_DEFAULT_REGION="{aws_region}"', file=sys.stdout)
    print(f'export AWS_REGION="{aws_region}"', file=sys.stdout)
    print(f'export AWS_DEFAULT_OUTPUT="{output}"', file=sys.stdout)
    print(f'export AWS_ACCESS_KEY_ID="{role_creds["accessKeyId"]}"', file=sys.stdout)
    print(f'export AWS_SECRET_ACCESS_KEY="{role_creds["secretAccessKey"]}"', file=sys.stdout)
    print(f'export AWS_SESSION_TOKEN="{role_creds["sessionToken"]}"', file=sys.stdout)
    print("AWS environment variables are exported!\n", file=sys.stderr)
    _print_ic_information(account_name, account_id, role, aws_region)
    print(
        _clear_session_function(
            "AWS_CREDS_ORIGIN_PS1",
            "AWS_CREDS_PROMPT_PREFIX",
            "AWS_CREDS_SESSION_TYPE",
            "AWS_CREDS_ACCOUNT_NAME",
            "AWS_CREDS_ACCOUNT_ID",
            "AWS_CREDS_ROLE_NAME",
            "AWS_DEFAULT_REGION",
            "AWS_REGION",
            "AWS_DEFAULT_OUTPUT",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ),
        file=sys.stdout,
    )
    _print_session_commands_footer()


def _print_ic_information(account_name: str, account_id: str, role_name: str, aws_region: str) -> None:
    print("Auth type:  AWS IAM Identity Center", file=sys.stderr)
    print(f"Account  :  {account_name} ({account_id})", file=sys.stderr)  # noqa: E999
    print("Used role: ", role_name, file=sys.stderr)
    print("Region   : ", aws_region, file=sys.stderr)


def _access_key(name: str, access_key: str, secret_key: str, region: str, printer: Printer) -> None:
    try:
        identity = (
            Session()
            .create_client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            .get_caller_identity()
        )
    except Exception as error:  # botocore.exceptions.ClientError
        if "The security token included in the request is invalid." in str(error):
            print("Invalid access key or secret access key!", file=sys.stderr)
            return
        raise error
    printer.append(f"# IAM user ({identity['Arn'].split(':user/')[-1]}) at {name} ({identity['Account']}) account")
    printer.append(
        f"{_prog}-{name}".lower().replace(" ", "-").replace(".", "")
        + "() {\n"
        + '  eval "$(\n'
        + f"    {_prog} session-access-key \\\n"
        + f"      --session-name {name} \\\n"
        + f"      --access-key {access_key} \\\n"
        + f"      --secret-access-key {secret_key} \\\n"
        + f"      --region {region} \\\n"
        + '  )"\n}'
    )


def _access_key_assume_role(
    name: str, access_key: str, secret_key: str, region: str, role_arn: str, printer: Printer
) -> None:
    try:
        identity = (
            Session()
            .create_client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            .get_caller_identity()
        )
    except Exception as error:  # botocore.exceptions.ClientError
        if "The security token included in the request is invalid." in str(error):
            print("Invalid access key or secret access key!", file=sys.stderr)
            return
        raise error
    printer.append(
        f"# IAM user ({identity['Arn'].split(':user/')[-1]}) at {name} account through the '{role_arn}' role"
    )
    printer.append(
        f"{_prog}-{name}".lower().replace(" ", "-").replace(".", "")
        + "() {\n"
        + '  eval "$(\n'
        + f"    {_prog} session-access-key \\\n"
        + f"      --session-name {name} \\\n"
        + f"      --access-key {access_key} \\\n"
        + f"      --secret-access-key {secret_key} \\\n"
        + f"      --region {region} \\\n"
        + f"      --assume-role-arn {role_arn} \\\n"
        + '  )"\n}'
    )


class _Auth:
    @abstractmethod
    def perform(self, mfa_device: Optional[str], mfa_code: Optional[str]) -> None:
        pass


def _print_assume_role(session_name: str, user: str, account_id: str, region: str, role: str) -> None:
    print("Auth type:  Assume role via AWS Access Key", file=sys.stderr)
    print(f"Session  :  {session_name}", file=sys.stderr)
    print(f"IAM user :  {user}", file=sys.stderr)  # noqa: E999
    print(f"Account  :  {account_id}", file=sys.stderr)  # noqa: E999
    print(f"Role     :  {role}", file=sys.stderr)  # noqa: E999
    print(f"Region   :  {region}", file=sys.stderr)  # noqa: E999


class _AssumeRole(_Auth):
    def __init__(
        self,
        sts,
        session_name: str,
        user_name: str,
        account_id: str,
        region: str,
        role_arn: str,
        prompt: ShellPrompt,
        output: str,
    ) -> None:
        self._sts = sts
        self._session_name = session_name
        self._user_name = user_name
        self._role_arn = role_arn
        self._account_id = account_id
        self._region = region
        self._prompt = prompt
        self._output = output

    def perform(self, mfa_device: Optional[str], mfa_code: Optional[str]) -> None:
        if mfa_device and mfa_code:
            session = self._sts.assume_role(
                RoleArn=self._role_arn, RoleSessionName=self._session_name, SerialNumber=mfa_device, TokenCode=mfa_code
            )
        else:
            session = self._sts.assume_role(RoleArn=self._role_arn, RoleSessionName=self._session_name)
        temp_credentials = session["Credentials"]
        self._prompt.update(self._session_name)
        print('export AWS_CREDS_SESSION_TYPE="ar"', file=sys.stdout)
        print(f'export AWS_CREDS_SESSION_NAME="{self._session_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_SESSION_ROLE="{self._role_arn}"', file=sys.stdout)
        print(f'export AWS_CREDS_USER_NAME="{self._user_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_ACCOUNT_ID="{self._account_id}"', file=sys.stdout)
        print(f'export AWS_ACCESS_KEY_ID="{temp_credentials["AccessKeyId"]}"', file=sys.stdout)
        print(f'export AWS_SECRET_ACCESS_KEY="{temp_credentials["SecretAccessKey"]}"', file=sys.stdout)
        print(f'export AWS_SESSION_TOKEN="{temp_credentials["SessionToken"]}"', file=sys.stdout)
        print(f'export AWS_DEFAULT_REGION="{self._region}"', file=sys.stdout)
        print(f'export AWS_REGION="{self._region}"', file=sys.stdout)
        print(f'export AWS_DEFAULT_OUTPUT="{self._output}"', file=sys.stdout)
        print("AWS environment variables are exported!\n", file=sys.stderr)
        _print_assume_role(self._session_name, self._user_name, self._account_id, self._region, self._role_arn)
        print(
            _clear_session_function(
                "AWS_CREDS_ORIGIN_PS1",
                "AWS_CREDS_PROMPT_PREFIX",
                "AWS_CREDS_SESSION_TYPE",
                "AWS_CREDS_SESSION_NAME",
                "AWS_CREDS_SESSION_ROLE",
                "AWS_CREDS_USER_NAME",
                "AWS_CREDS_ACCOUNT_ID",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_DEFAULT_OUTPUT",
            ),
            file=sys.stdout,
        )
        _print_session_commands_footer()


def _print_access_key(session_name: str, user: str, account_id: str, region: str) -> None:
    print("Auth type:  AWS Access Key", file=sys.stderr)
    print(f"Session  :  {session_name}", file=sys.stderr)
    print(f"IAM user :  {user}", file=sys.stderr)  # noqa: E999
    print(f"Account  :  {account_id}", file=sys.stderr)  # noqa: E999
    print(f"Region   :  {region}", file=sys.stderr)  # noqa: E999


class _AccessKey(_Auth):
    def __init__(
        self, sts, session_name: str, user_name: str, account_id: str, region: str, prompt: ShellPrompt, output: str
    ) -> None:
        self._sts = sts
        self._session_name = session_name
        self._user_name = user_name
        self._account_id = account_id
        self._region = region
        self._prompt = prompt
        self._output = output

    def perform(self, mfa_device: Optional[str], mfa_code: Optional[str]) -> None:
        if mfa_device and mfa_code:
            session = self._sts.get_session_token(SerialNumber=mfa_device, TokenCode=mfa_code)
        else:
            session = self._sts.get_session_token()
        temp_credentials = session["Credentials"]
        self._prompt.update(self._session_name)
        print('export AWS_CREDS_SESSION_TYPE="ak"', file=sys.stdout)
        print(f'export AWS_CREDS_SESSION_NAME="{self._session_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_USER_NAME="{self._user_name}"', file=sys.stdout)
        print(f'export AWS_CREDS_ACCOUNT_ID="{self._account_id}"', file=sys.stdout)
        print(f'export AWS_ACCESS_KEY_ID="{temp_credentials["AccessKeyId"]}"', file=sys.stdout)
        print(f'export AWS_SECRET_ACCESS_KEY="{temp_credentials["SecretAccessKey"]}"', file=sys.stdout)
        print(f'export AWS_SESSION_TOKEN="{temp_credentials["SessionToken"]}"', file=sys.stdout)
        print(f'export AWS_DEFAULT_REGION="{self._region}"', file=sys.stdout)
        print(f'export AWS_REGION="{self._region}"', file=sys.stdout)
        print(f'export AWS_DEFAULT_OUTPUT="{self._output}"', file=sys.stdout)
        print("AWS environment variables are exported!\n", file=sys.stderr)
        _print_access_key(self._session_name, self._user_name, self._account_id, self._region)
        print(
            _clear_session_function(
                "AWS_CREDS_ORIGIN_PS1",
                "AWS_CREDS_PROMPT_PREFIX",
                "AWS_CREDS_SESSION_TYPE",
                "AWS_CREDS_SESSION_NAME",
                "AWS_CREDS_USER_NAME",
                "AWS_CREDS_ACCOUNT_ID",
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_DEFAULT_OUTPUT",
            ),
            file=sys.stdout,
        )
        _print_session_commands_footer()


def _session_access_key(
    name: str, access_key: str, secret_key: str, region: str, output: str, role_arn: Optional[str], prompt: ShellPrompt
) -> None:
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
        auth = _AssumeRole(sts, name, iam_user, account_id, region, role_arn, prompt, output)
    else:
        auth = _AccessKey(sts, name, iam_user, account_id, region, prompt, output)
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
            os.getenv("AWS_CREDS_ACCOUNT_NAME"),
            os.getenv("AWS_CREDS_ACCOUNT_ID"),
            os.getenv("AWS_CREDS_ROLE_NAME"),
            os.getenv("AWS_REGION"),
        )
    elif session_type == "ak":
        _print_access_key(
            os.getenv("AWS_CREDS_SESSION_NAME"),
            os.getenv("AWS_CREDS_USER_NAME"),
            os.getenv("AWS_CREDS_ACCOUNT_ID"),
            os.getenv("AWS_REGION"),
        )
    elif session_type == "ar":
        _print_assume_role(
            os.getenv("AWS_CREDS_SESSION_NAME"),
            os.getenv("AWS_CREDS_USER_NAME"),
            os.getenv("AWS_CREDS_ACCOUNT_ID"),
            os.getenv("AWS_REGION"),
            os.getenv("AWS_CREDS_SESSION_ROLE"),
        )
    else:
        print(f"Cannot find AWS credentials configured by '{_prog}'.", file=sys.stderr)


def _scan_local(alias_printer: Printer) -> None:
    local_config = Session().full_config
    print("Scanning the local AWS config files...", file=sys.stdout)
    for key, details in local_config.get("sso_sessions", {}).items():
        ic = IdentityCenter(details["sso_start_url"], details["sso_region"])
        print(f"\nThe '{key}' {ic} identified.", file=sys.stdout, end="")
        if "y" not in input(" Generate aliases? (y/n): ").lower():
            continue
        _identity_center_scan(ic, alias_printer)
    for key, details in local_config.get("profiles", {}).items():
        if "sso_session" in details:
            continue
        print(f"\nThe '{key}' access key identified.", file=sys.stdout, end="")
        if "y" not in input(" Generate alias? (y/n): ").lower():
            continue
        if "role_arn" in details:
            role_arn = details["role_arn"]
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
                alias_printer,
            )
        else:
            _access_key(
                key, details["aws_access_key_id"], details["aws_secret_access_key"], details["region"], alias_printer
            )
    print("\nScanning completed!", file=sys.stdout)


def _clear_session() -> None:
    print(f"{_clear_session_function_name} &> /dev/null 2>&1", file=sys.stdout)


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "session-ic":
        print(f"The positional arguments are deprecated for the `{_prog} session-ic`!", file=sys.stderr)  # noqa: F821
        print("Please update the alias as follows:\n", file=sys.stderr)  # noqa: F821
        identity_center = IdentityCenter(sys.argv[2], sys.argv[3])
        _print_identity_center_alias(
            Printer("realtime", sys.stderr), identity_center, sys.argv[4], "account-name", sys.argv[5]
        )
        print("\n\n", file=sys.stderr)  # noqa: F821
        _clear_session()
        _session_ic(identity_center, sys.argv[4], sys.argv[5], sys.argv[3], ShellPrompt(enabled=False))
        exit(0)
    parser = ArgumentParser(
        description="Painless CLI authentication using various AWS identities.",
        prog=_prog,
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )
    parser.add_argument("--version", action="version", version=f"{_prog} {__version__}")
    subparsers = parser.add_subparsers(title="Commands", dest="subcommand")

    subparsers.add_parser(
        "describe-creds",
        description=f"""
        The command describes the AWS credentials in the current shell session by looking at the environment variables.
        Besides, this command runs every time you run `{_prog}` without arguments.
        """,
        help="describes the AWS credentials in the current shell session",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )

    subparsers.add_parser(
        "scan-local",
        description=f"""
        The command runs an interactive workflow to create the `{_prog}` shell aliases based on the local AWS CLI config.
        Pick those aliases you want and save them to your shell configuration profile file. Once you run an alias,
        it will authenticate a session and export the AWS session environment variables to the current shell session.
        """,
        help="generates shell aliases for the local AWS CLI configuration",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )

    scan_ic = subparsers.add_parser(
        "scan-ic",
        description=f"""
        The command generates all possible `{_prog}` shell aliases for each role available in an AWS IAM Identity Center.
        Pick those aliases you want and save them to your shell configuration profile file. Once you run an alias,
        it will authenticate a session and export the AWS session environment variables to the current shell session.
        """,
        help="generates shell aliases for an AWS IAM Identity Center",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )
    scan_ic.add_argument(
        "--ic-start-url",
        metavar="URL",
        required=True,
        help="AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)",
    )
    scan_ic.add_argument(
        "--ic-region", metavar="region", required=True, help="AWS IAM Identity Center region (like `us-east-1`)"
    )

    session_ic = subparsers.add_parser(
        "session-ic",
        description="""
        The command exports the environment variables suitable for authenticating CLI tools by creating an
        AWS login session based on the AWS IAM Identity Center role. Any AWS IAM Identity Center alias will
        use this command to authenticate.
        """,
        help="authenticates an AWS Identity Center role",
        formatter_class=lambda prog: HelpFormatter(prog, width=100),
    )
    session_ic.add_argument(
        "--ic-start-url",
        metavar="URL",
        required=True,
        help="AWS IAM Identity Center start URL (like `https://xxxxxx.awsapps.com/start`)",
    )
    session_ic.add_argument(
        "--ic-region", metavar="region", required=True, help="AWS IAM Identity Center region (like `us-east-1`)"
    )
    session_ic.add_argument("--account-id", metavar="id", required=True, help="AWS Account ID")
    session_ic.add_argument("--role-name", metavar="name", required=True, help="Role name")
    session_ic.add_argument(
        "--aws-region",
        metavar="region",
        default=None,
        help="An AWS region where the AWS resources are located ('--ic-region' value is used if unset).",
    )
    session_ic.add_argument(
        "--output",
        default="json",
        choices=["json", "text", "table", "yaml", "yaml-stream"],
        help="An output format (default: 'json').",
    )
    session_ic.add_argument(
        "--no-prompt-update", action="store_true", help="Disables a shell prompt modification if specified"
    )

    session_ak = subparsers.add_parser(
        "session-access-key",
        description="""
        The command exports the environment variables suitable for authenticating CLI tools by creating
        an AWS login session based on the AWS Access Key. It asks to provide an MFA code if an MFA device is configured.
        Any AWS Access Key alias will use this command to authenticate.
        """,
        help="authenticates an access key",
        formatter_class=lambda prog: HelpFormatter(prog, max_help_position=35, width=100),
    )
    session_ak.add_argument("--session-name", metavar="name", required=True, help="A name")
    session_ak.add_argument("--access-key", metavar="key", required=True, help="Access Key")
    session_ak.add_argument("--secret-access-key", metavar="secret-key", required=True, help="Secret Access Key")
    session_ak.add_argument("--region", metavar="region", required=True, help="AWS Region")
    session_ak.add_argument("--assume-role-arn", metavar="role", required=False, help="A role to assume")
    session_ak.add_argument(
        "--output",
        default="json",
        choices=["json", "text", "table", "yaml", "yaml-stream"],
        help="An output format (default: 'json').",
    )
    session_ak.add_argument(
        "--no-prompt-update", action="store_true", help="Disables a shell prompt update if specified"
    )

    args = parser.parse_args()

    if args.subcommand == "scan-ic":
        _identity_center_scan(IdentityCenter(args.ic_start_url, args.ic_region), Printer("realtime", sys.stdout))
    elif args.subcommand == "session-ic":
        _clear_session()
        if args.aws_region is None:
            args.aws_region = args.ic_region
        _session_ic(
            IdentityCenter(args.ic_start_url, args.ic_region),
            args.account_id,
            args.role_name,
            args.aws_region,
            args.output,
            ShellPrompt(enabled=not args.no_prompt_update),
        )
    elif args.subcommand == "session-access-key":
        _clear_session()
        _session_access_key(
            args.session_name,
            args.access_key,
            args.secret_access_key,
            args.region,
            args.output,
            args.assume_role_arn,
            ShellPrompt(enabled=not args.no_prompt_update),
        )
    elif args.subcommand == "describe-creds":
        _describe_credentials()
    elif args.subcommand == "scan-local":
        answer = ""
        while "y" not in answer and "n" not in answer:
            answer = input("Do you want to print all aliases at the end? (y/n): ").lower()
        if answer == "y":
            _out = Printer("end", sys.stdout)
            _out.append("\nGenerated aliases: ")
        else:
            _out = Printer("realtime", sys.stdout)
        _scan_local(_out)
        _out.print_all()
        if answer == "n":
            print("\nThere are multiple aliases generated.", file=sys.stdout)
            if "y" in input("Do you want to print them all at once? (y/n): ").lower():
                _out.print_all(always=True)
    else:
        _describe_credentials()


if __name__ == "__main__":
    main()
