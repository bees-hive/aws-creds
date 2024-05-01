#!/usr/bin/env bash
set -o errexit
set -o pipefail
# installation
DOWNLOAD_URL="https://raw.githubusercontent.com/bees-hive/aws-creds/main/aws-creds.py"
: INSTALL_DIR="${INSTALL_DIR:="/usr/local/bin"}"
echo "Installing to the '$INSTALL_DIR'..."
mkdir -p "$INSTALL_DIR"
INSTALLATION="$INSTALL_DIR/aws-creds"
curl -sSLo "$INSTALLATION" "$DOWNLOAD_URL"
chmod +x "$INSTALLATION"
# verification: binary
"${INSTALLATION}" 2>/dev/null || (
  echo "Installation failed!"
  echo "Please submit the issue at https://github.com/bees-hive/aws-creds/issues."
  exit 1
)
echo "Successfully installed!"
# verification: PATH
CORRECT_PATH=""
case ${PATH} in
*${INSTALL_DIR}*)
  CORRECT_PATH="yes"
  ;;
esac
if test -z "${CORRECT_PATH}"; then
  echo "Seems the '${INSTALL_DIR}' directory is not the PATH. Please update."
else
  echo "The '${INSTALL_DIR}' directory is in the PATH."
fi
# warning
echo "You might need to re-start the shell to use 'aws-creds'."
