#!/usr/bin/env bash
# =============================================================================
# Wazuh Threat-Intel Updater — Cron Installation Script
# =============================================================================
# Installs a daily cron job that runs update_rules.py to refresh CDB lists
# from public threat-intel feeds.
#
# Run as root on the Wazuh manager:
#   bash cron_setup.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPDATER_SCRIPT="${SCRIPT_DIR}/update_rules.py"
LOG_FILE="/var/log/wazuh-intel-update.log"
CRON_FILE="/etc/cron.d/wazuh-intel-updater"
PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root." >&2
    exit 1
fi

if [[ ! -f "${UPDATER_SCRIPT}" ]]; then
    echo "[ERROR] update_rules.py not found at ${UPDATER_SCRIPT}" >&2
    exit 1
fi

chmod +x "${UPDATER_SCRIPT}"

cat > "${CRON_FILE}" <<EOF
# Wazuh Threat-Intel CDB List Updater
# Runs daily at 02:00 UTC — updates IOC lists from public feeds and reloads Wazuh
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily full update at 02:00
0 2 * * * root ${PYTHON_BIN} ${UPDATER_SCRIPT} --output-dir /var/ossec/etc/lists >> ${LOG_FILE} 2>&1

# Feodo C2 IP list refreshed every 6 hours (changes frequently)
0 */6 * * * root ${PYTHON_BIN} ${UPDATER_SCRIPT} --feed feodo_ips --output-dir /var/ossec/etc/lists >> ${LOG_FILE} 2>&1
EOF

chmod 644 "${CRON_FILE}"
echo "[OK] Cron job installed: ${CRON_FILE}"
echo "[OK] Logs will be written to: ${LOG_FILE}"
echo ""
echo "To test immediately (dry-run):"
echo "  ${PYTHON_BIN} ${UPDATER_SCRIPT} --dry-run"
echo ""
echo "To run immediately (live):"
echo "  ${PYTHON_BIN} ${UPDATER_SCRIPT}"
