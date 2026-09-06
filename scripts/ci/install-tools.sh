#!/usr/bin/env bash
# Linux CI needs only the secret scanner and the artifact signature verifier.
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
tool_dir="$(mktemp -d)"
trap 'rm -rf -- "$tool_dir"' EXIT
mode="${1:-}"
[[ "$mode" == scan || "$mode" == verify ]]
install_dir="${RUNNER_TEMP:?}/application-tools"
mkdir -p "$install_dir"
if [[ "$mode" == scan ]]; then
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 120 --retry 2 --output "$tool_dir/gitleaks.tgz" \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$tool_dir/gitleaks.tgz" | sha256sum --check --status
tar -xzf "$tool_dir/gitleaks.tgz" -C "$tool_dir" gitleaks
install -m 0755 "$tool_dir/gitleaks" "$install_dir/gitleaks"
else
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 120 --retry 2 --output "$tool_dir/cosign" \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64
printf '%s  %s\n' 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 "$tool_dir/cosign" | sha256sum --check --status
install -m 0755 "$tool_dir/cosign" "$install_dir/cosign"
fi
printf '%s\n' "$install_dir" >> "${GITHUB_PATH:?}"
