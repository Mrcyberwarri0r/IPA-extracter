#!/usr/bin/env bash
# One-shot setup for iph: creates the venv, installs Python deps, and checks
# for the Homebrew CLI tools the tool leans on.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "==> Creating virtualenv (.venv)"
python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
echo "==> Installing Python dependencies"
./.venv/bin/pip install --quiet -r requirements.txt

echo "==> Checking Homebrew CLI tools"
missing=()
for t in ideviceinstaller idevice_id ideviceinfo iproxy; do
  command -v "$t" >/dev/null 2>&1 || missing+=("libimobiledevice")
done
command -v ipatool  >/dev/null 2>&1 || missing+=("ipatool")
command -v sshpass  >/dev/null 2>&1 || missing+=("sshpass")

if [ "${#missing[@]}" -gt 0 ]; then
  uniq=$(printf "%s\n" "${missing[@]}" | sort -u | tr '\n' ' ')
  echo "    Optional tools missing. To enable every feature:"
  echo "      brew install $uniq"
fi

echo
echo "==> Done. Run the tool with:"
echo "      $HERE/bin/iph doctor"
echo "    (optionally add it to PATH:  ln -s $HERE/bin/iph /opt/homebrew/bin/iph )"
