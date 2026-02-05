#!/usr/bin/env bash
set -euo pipefail

# CpAgent end-to-end installer and runner for a fresh VM
# - Installs required system dependencies (dotnet, python build deps)
# - Sets up Barbican environment via setup-barbican-env.sh
# - Runs CpAgent (Development mode)

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; NC="\033[0m"
log() { echo -e "${GREEN}[ok]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
err() { echo -e "${RED}[err]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CPAGENT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

install_dotnet() {
  if command -v dotnet >/dev/null 2>&1; then
    log "dotnet already installed: $(dotnet --version)"
    return
  fi
  if command -v apt >/dev/null 2>&1; then
    sudo apt update
    sudo apt install -y wget apt-transport-https
    wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb || true
    sudo dpkg -i /tmp/packages-microsoft-prod.deb || true
    sudo apt update
    sudo apt install -y dotnet-sdk-8.0
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y dotnet-sdk-8.0 || {
      warn "dnf dotnet install failed. Refer to Microsoft docs for your distro."
    }
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y dotnet-sdk-8.0 || {
      warn "yum dotnet install failed. Refer to Microsoft docs for your distro."
    }
  else
    err "Unknown package manager. Install .NET SDK 8.0 manually and re-run."
    exit 1
  fi
  log "Installed dotnet SDK: $(dotnet --version)"
}

install_other_tools() {
  if command -v apt >/dev/null 2>&1; then
    sudo apt update
    sudo apt install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y curl ca-certificates || true
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y curl ca-certificates || true
  fi
  log "Basic tools installed."
}

setup_barbican_env() {
  bash "$CPAGENT_ROOT/scripts/setup-barbican-env.sh"
}

run_agent_dev() {
  pushd "$CPAGENT_ROOT" >/dev/null
  dotnet restore
  dotnet build
  log "Starting CpAgent (Development mode)."
  sudo dotnet run
  popd >/dev/null
}

main() {
  install_other_tools
  install_dotnet
  setup_barbican_env
  run_agent_dev
}

main "$@"
