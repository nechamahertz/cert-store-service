#!/usr/bin/env bash
set -e

CONFIG_DIR="/etc/barbican"
DATA_DIR="/var/lib/barbican"
SQLITE_DB="${DATA_DIR}/barbican.sqlite"
VENV_DIR="/opt/cpagent/barbican-env"
MASTER_HANDLE="0x81010002"
REAL_USER="${SUDO_USER:-$(id -un)}"

# Ensure directories exist
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}" /var/log/barbican
chown -R "${REAL_USER}":"${REAL_USER}" "${CONFIG_DIR}" "${DATA_DIR}" /var/log/barbican || true

# Ensure configs exist and are sane
if [[ ! -f "${CONFIG_DIR}/barbican.conf" ]] || grep -q "/home/adminuser/" "${CONFIG_DIR}/barbican.conf"; then
  cat > "${CONFIG_DIR}/barbican.conf" <<CONF
[DEFAULT]
transport_url = rabbit://guest:guest@127.0.0.1:5672/
host_href = http://127.0.0.1:9311
debug = True
log_file = barbican.log
log_dir = /var/log/barbican
use_stderr = False

[database]
connection = sqlite:///${SQLITE_DB}

[crypto]
enabled_crypto_plugins = vtpm

[crypto:vtpm]
plugin_class = barbican_vtpm_crypto.plugin.VtpmCryptoPlugin

[vtpm_plugin]
master_key_handle = ${MASTER_HANDLE}
timeout = 30

[keystone_authtoken]
auth_type = none

[context]
admin_role = admin
CONF
fi

if [[ ! -f "${CONFIG_DIR}/barbican-api-paste.ini" ]]; then
  cat > "${CONFIG_DIR}/barbican-api-paste.ini" <<PASTE
[composite:main]
use = egg:Paste#urlmap
/: barbican_version
/healthcheck: healthcheck
/v1: barbican_api

[pipeline:barbican_api]
pipeline = cors request_id http_proxy_to_wsgi unauthenticated-context microversion apiapp

[app:apiapp]
paste.app_factory = barbican.api.app:create_main_app

[filter:unauthenticated-context]
paste.filter_factory = barbican.api.middleware.context:UnauthenticatedContextMiddleware.factory

[filter:microversion]
paste.filter_factory = barbican.api.middleware.microversion:MicroversionMiddleware.factory

[filter:cors]
paste.filter_factory = oslo_middleware.cors:filter_factory
oslo_config_project = barbican

[filter:request_id]
paste.filter_factory = oslo_middleware.request_id:RequestId.factory

[filter:http_proxy_to_wsgi]
paste.filter_factory = oslo_middleware:HTTPProxyToWSGI.factory

[app:healthcheck]
paste.app_factory = oslo_middleware:Healthcheck.app_factory
backends = disable_by_file
disable_by_file_path = /etc/barbican/healthcheck_disable

[pipeline:barbican_version]
pipeline = cors request_id http_proxy_to_wsgi microversion versionapp

[app:versionapp]
paste.app_factory = barbican.api.app:create_version_app
PASTE
fi

touch "${CONFIG_DIR}/api_audit_map.conf"
touch "${CONFIG_DIR}/healthcheck_disable"
if [[ ! -f "${CONFIG_DIR}/policy.json" ]]; then echo '{}' > "${CONFIG_DIR}/policy.json"; fi

# TPM device detection
if [ -e /dev/tpmrm0 ]; then
  TPM_DEV="/dev/tpmrm0"
elif [ -e /dev/tpm0 ]; then
  TPM_DEV="/dev/tpm0"
else
  echo "Warning: No TPM device detected. Skipping TPM provisioning." >&2
  TPM_DEV=""
fi
export TPM2TOOLS_TCTI="device:${TPM_DEV}"
export TPM2_TCTI="device:${TPM_DEV}"
chmod 666 "${TPM_DEV}" || true

# Create master key if missing
if [ -n "${TPM_DEV}" ]; then
  if ! tpm2_readpublic -c "${MASTER_HANDLE}" > /dev/null 2>&1; then
    tpm2_createprimary -C o -c /tmp/primary.ctx -G ecc256 || true
    tpm2_create -C /tmp/primary.ctx -G ecc256:ecdh -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt" -u /tmp/key.pub -r /tmp/key.priv || true
    tpm2_load -C /tmp/primary.ctx -u /tmp/key.pub -r /tmp/key.priv -c /tmp/key.ctx || true
    tpm2_evictcontrol -C o -c /tmp/key.ctx "${MASTER_HANDLE}" || true
    rm -f /tmp/primary.ctx /tmp/key.pub /tmp/key.priv /tmp/key.ctx || true
  fi
fi

# Verify venv exists and Barbican entrypoint is present (must be bundled in deb)
if [ ! -d "${VENV_DIR}" ] || [ ! -x "${VENV_DIR}/bin/barbican-wsgi-api" ]; then
  echo "ERROR: Barbican venv missing or incomplete at ${VENV_DIR}. Package must include prebuilt venv with barbican-wsgi-api." >&2
  exit 1
fi

# Normalize shebangs in key venv console scripts to this machine's path
PYBIN="${VENV_DIR}/bin/python3"
if [ ! -x "${PYBIN}" ]; then
  PYBIN="${VENV_DIR}/bin/python"
fi
rewrite_shebang() {
  local script="$1"
  [ -f "$script" ] || return 0
  [ -x "$PYBIN" ] || return 0
  local first
  first=$(head -n1 "$script" 2>/dev/null || echo "")
  if echo "$first" | grep -q "^#!.*python"; then
    local tmp
    tmp=$(mktemp)
    printf "#!%s\n" "$PYBIN" > "$tmp" && tail -n +2 "$script" >> "$tmp" && mv "$tmp" "$script" || rm -f "$tmp"
    chmod +x "$script" || true
  fi
}
rewrite_shebang "${VENV_DIR}/bin/barbican-manage"
rewrite_shebang "${VENV_DIR}/bin/barbican-wsgi-api"
rewrite_shebang "${VENV_DIR}/bin/gunicorn"

# Run DB migrations using bundled barbican-manage
export BARBICAN_SETTINGS="${CONFIG_DIR}/barbican.conf"
if [ -f "${VENV_DIR}/bin/barbican-manage" ]; then
  # Prefer console script; if exec fails, run it via python explicitly
  "${VENV_DIR}/bin/barbican-manage" --config-file "${CONFIG_DIR}/barbican.conf" db upgrade 2>/dev/null || \
  ([ -x "${PYBIN}" ] && "${PYBIN}" "${VENV_DIR}/bin/barbican-manage" --config-file "${CONFIG_DIR}/barbican.conf" db upgrade) || true
else
  # As a last resort, try the module runner
  ([ -x "${PYBIN}" ] && "${PYBIN}" -m barbican.cmd.manage --config-file "${CONFIG_DIR}/barbican.conf" db upgrade) || true
fi

# Systemd setup
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true

  # Always enable CpAgent
  systemctl enable cpagent.service || true


  systemctl restart cpagent.service || true
fi

echo "CpAgent Barbican installed and ready!"
