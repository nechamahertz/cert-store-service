#!/usr/bin/env bash
set -euo pipefail

# Build a Debian package for CpAgent + Barbican using fpm
# Creates staging layout and invokes fpm to produce a .deb

APP_NAME="cpagent-barbican"
VERSION="${1:-1.0.0}"
ARCH="amd64"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
STAGING_DIR="${DIST_DIR}/fpm-staging"
PUBLISH_DIR="${ROOT_DIR}/bin/Release/net8.0/linux-x64/publish"
CPAGENT_BIN_SRC="${PUBLISH_DIR}/CpAgent"
VENV_SRC=""
CFG_SRC=""
PLUGIN_SRC="${ROOT_DIR}/../barbican-vtpm-crypto"

# Ensure fpm is installed
if ! command -v fpm >/dev/null 2>&1; then
  echo "ERROR: fpm not found. Install with:"
  echo "  sudo apt update && sudo apt install -y ruby-full && sudo gem install fpm"
  exit 1
fi

# Always publish fresh CpAgent (self-contained linux-x64)
echo "Publishing CpAgent (self-contained linux-x64)..."
rm -rf "${PUBLISH_DIR}" || true
dotnet publish "${ROOT_DIR}/CpAgent.csproj" \
  -c Release \
  -r linux-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:PublishTrimmed=false \
  -p:UseAppHost=true \
  -o "${PUBLISH_DIR}"

# Determine venv and config sources (force repo root venv)
VENV_SRC="${ROOT_DIR}/barbican-env"
if [[ ! -x "${VENV_SRC}/bin/barbican-wsgi-api" ]]; then
  echo "ERROR: repo venv missing or incomplete at ${VENV_SRC}. Ensure barbican-env exists and contains barbican." >&2
  exit 1
fi

# Preinstall vTPM plugin into the venv so no pip runs at install time
if [[ -d "${PLUGIN_SRC}" ]]; then
  echo "Installing vTPM plugin into venv..."
  if [[ -x "${VENV_SRC}/bin/python" ]]; then
    "${VENV_SRC}/bin/python" -m pip install --no-deps "${PLUGIN_SRC}"
  else
    echo "WARNING: Python interpreter not found in venv; skipping vTPM plugin install." >&2
  fi
fi

if [[ -d "${PUBLISH_DIR}/barbican-config" ]]; then
  CFG_SRC="${PUBLISH_DIR}/barbican-config"
else
  CFG_SRC="${ROOT_DIR}/barbican-config"
fi

# Prepare staging layout
rm -rf "${STAGING_DIR}" "${DIST_DIR}"/cpagent-barbican_*.deb
mkdir -p "${STAGING_DIR}/usr/bin"
mkdir -p "${STAGING_DIR}/opt/cpagent"
mkdir -p "${STAGING_DIR}/etc/barbican"
mkdir -p "${STAGING_DIR}/var/lib/barbican" "${STAGING_DIR}/var/log/barbican"
mkdir -p "${STAGING_DIR}/lib/systemd/system"

# Copy CpAgent binary and config to /opt/cpagent
cp "${CPAGENT_BIN_SRC}" "${STAGING_DIR}/opt/cpagent/cpagent"
chmod +x "${STAGING_DIR}/opt/cpagent/cpagent"

# Patch ELF interpreter for Snap SDK builds
# Using custom python script because patchelf fails on .NET + Snap binaries
echo "Patching ELF interpreter..."
python3 "${ROOT_DIR}/packaging/fpm/patch_binary.py" "${STAGING_DIR}/opt/cpagent/cpagent"

# Copy appsettings.json if present
if [[ -f "${PUBLISH_DIR}/appsettings.json" ]]; then
  cp "${PUBLISH_DIR}/appsettings.json" "${STAGING_DIR}/opt/cpagent/"
fi

# Symlink to /usr/bin for convenience
ln -s "/opt/cpagent/cpagent" "${STAGING_DIR}/usr/bin/cpagent"

# Copy barbican venv
if [[ -d "${VENV_SRC}" ]]; then
  cp -a "${VENV_SRC}" "${STAGING_DIR}/opt/cpagent/barbican-env"
else
  echo "ERROR: barbican-env not found at ${VENV_SRC}"
  exit 1
fi

# Copy configs into /etc/barbican (if available)
if [[ -d "${CFG_SRC}" ]]; then
  # Common files
  for f in barbican.conf barbican-api-paste.ini api_audit_map.conf policy.json healthcheck_disable; do
    if [[ -f "${CFG_SRC}/${f}" ]]; then
      cp "${CFG_SRC}/${f}" "${STAGING_DIR}/etc/barbican/"
    fi
  done
fi

# vTPM plugin is preinstalled into the venv; no source copy needed.

# Systemd unit file (CpAgent only). Barbican is managed internally by CpAgent.
cp "${ROOT_DIR}/packaging/fpm/cpagent.service" "${STAGING_DIR}/lib/systemd/system/cpagent.service"

echo "Ensuring prebuilt venv is present..."
if [[ ! -d "${VENV_SRC}" ]] || [[ ! -x "${VENV_SRC}/bin/barbican-wsgi-api" ]]; then
  echo "ERROR: Missing or incomplete barbican-env at ${VENV_SRC}. Build it before packaging (scripts/setup-barbican-env.sh)." >&2
  exit 1
fi

# Build .deb via fpm
OUT_DEB="${DIST_DIR}/${APP_NAME}_${VERSION}_${ARCH}.deb"
mkdir -p "${DIST_DIR}"

fpm -s dir -t deb \
  -n "${APP_NAME}" \
  -v "${VERSION}" \
  --iteration 1 \
  --architecture "${ARCH}" \
  --depends "python3" \
  --after-install "${ROOT_DIR}/packaging/fpm/postinst.sh" \
  -C "${STAGING_DIR}" \
  --prefix / \
  -p "${OUT_DEB}"

# Quick metadata check
if command -v dpkg-deb >/dev/null 2>&1; then
  echo "\nPackage metadata:"
  dpkg-deb -I "${OUT_DEB}" || true
fi

echo "\nBuilt package: ${OUT_DEB}"
