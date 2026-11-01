#!/usr/bin/env bash
# Linux CI needs checksum-pinned secret, signature and vulnerability scanners.
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
tool_dir="$(mktemp -d)"
trap 'rm -rf -- "$tool_dir"' EXIT
mode="${1:-}"
[[ "$mode" == scan || "$mode" == verify || "$mode" == vulnerabilities ]]
install_dir="${RUNNER_TEMP:?}/application-tools"
mkdir -p "$install_dir"
if [[ "$mode" == scan ]]; then
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 120 --retry 2 --output "$tool_dir/gitleaks.tgz" \
  https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb "$tool_dir/gitleaks.tgz" | sha256sum --check --status
tar -xzf "$tool_dir/gitleaks.tgz" -C "$tool_dir" gitleaks
install -m 0755 "$tool_dir/gitleaks" "$install_dir/gitleaks"
elif [[ "$mode" == verify ]]; then
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 120 --retry 2 --output "$tool_dir/cosign" \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64
printf '%s  %s\n' 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 "$tool_dir/cosign" | sha256sum --check --status
install -m 0755 "$tool_dir/cosign" "$install_dir/cosign"
else
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --max-time 120 --retry 2 --output "$tool_dir/trivy.tgz" \
  https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz
printf '%s  %s\n' c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 "$tool_dir/trivy.tgz" | sha256sum --check --status
tar -xzf "$tool_dir/trivy.tgz" -C "$tool_dir" trivy
install -m 0755 "$tool_dir/trivy" "$install_dir/trivy"
fi
printf '%s\n' "$install_dir" >> "${GITHUB_PATH:?}"
