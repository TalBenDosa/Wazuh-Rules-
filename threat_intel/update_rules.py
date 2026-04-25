#!/usr/bin/env python3
"""
Wazuh Threat-Intel Rule Updater
================================
Fetches fresh IOCs from public threat-intel feeds and regenerates
the Wazuh CDB list files used by detection rules.

Supported feeds:
  - abuse.ch URLhaus (malicious URLs / domains)
  - abuse.ch Feodo Tracker (botnet C2 IPs)
  - AlienVault OTX (domains + IPs via public pulse API)
  - Emerging Threats (Suricata-format; domains extracted)

Usage:
  python3 update_rules.py [--dry-run] [--feed <name>] [--output-dir <path>]

Schedule via cron (daily at 02:00):
  0 2 * * * /usr/bin/python3 /var/ossec/etc/rules/threat_intel/update_rules.py \
            --output-dir /var/ossec/etc/lists >> /var/log/wazuh-intel-update.log 2>&1

After updating lists, the script triggers a Wazuh manager reload so
rules that reference the CDB lists pick up the new entries immediately.
"""

import argparse
import csv
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT_DIR = Path("/var/ossec/etc/lists")
BACKUP_DIR = Path("/var/ossec/etc/lists/backups")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

FEEDS: dict[str, dict] = {
    "urlhaus_domains": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "description": "abuse.ch URLhaus — recent malicious domains",
        "output_file": "known_bad_domains.txt",
        "parser": "urlhaus_csv",
        "field_index": 2,        # URL column; domain extracted from it
        "enabled": True,
    },
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "description": "abuse.ch Feodo Tracker — botnet C2 IPs",
        "output_file": "known_bad_ips.txt",
        "parser": "feodo_csv",
        "field_index": 1,        # dst_ip column
        "enabled": True,
    },
    "otx_domains": {
        "url": "https://otx.alienvault.com/taxii/collections/malware-domains/objects/",
        "description": "AlienVault OTX — malware domains (public)",
        "output_file": "known_bad_domains.txt",
        "parser": "otx_stix",
        "enabled": False,        # requires API key — set OTX_API_KEY env var to enable
    },
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("wazuh-intel-updater")


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

def _extract_domain_from_url(url: str) -> Optional[str]:
    """Return the hostname portion of a URL string, or None if unparseable."""
    try:
        # urllib.parse not imported to keep stdlib footprint minimal
        url = url.strip().strip('"')
        if "://" in url:
            url = url.split("://", 1)[1]
        host = url.split("/")[0].split("?")[0].split(":")[0]
        if host and "." in host and len(host) < 254:
            return host.lower()
    except Exception:
        pass
    return None


def parse_urlhaus_csv(content: str, field_index: int) -> list[str]:
    """Parse URLhaus CSV export; extract unique domains from URL column."""
    domains: set[str] = set()
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        try:
            domain = _extract_domain_from_url(row[field_index])
            if domain:
                domains.add(domain)
        except IndexError:
            continue
    return sorted(domains)


def parse_feodo_csv(content: str, field_index: int) -> list[str]:
    """Parse Feodo Tracker CSV; extract C2 IP addresses."""
    ips: set[str] = set()
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        try:
            ip = row[field_index].strip().strip('"')
            if ip and ip.count(".") == 3:
                ips.add(ip)
        except IndexError:
            continue
    return sorted(ips)


def parse_otx_stix(content: str, _field_index: int) -> list[str]:
    """Parse OTX STIX bundle; extract domain-name indicator values."""
    domains: set[str] = set()
    try:
        bundle = json.loads(content)
        for obj in bundle.get("objects", []):
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                if "domain-name:value" in pattern:
                    # pattern: [domain-name:value = 'example.com']
                    value = pattern.split("'")[1] if "'" in pattern else ""
                    if value and "." in value:
                        domains.add(value.lower())
    except Exception as exc:
        log.warning("OTX STIX parse error: %s", exc)
    return sorted(domains)


PARSERS = {
    "urlhaus_csv": parse_urlhaus_csv,
    "feodo_csv": parse_feodo_csv,
    "otx_stix": parse_otx_stix,
}


# ---------------------------------------------------------------------------
# CDB list writer
# ---------------------------------------------------------------------------

def write_cdb_list(entries: list[str], output_path: Path, dry_run: bool) -> int:
    """
    Write Wazuh CDB list format (key: per line).
    Returns the count of entries written.
    """
    header = (
        f"# Auto-generated by wazuh-intel-updater\n"
        f"# Updated: {datetime.now(timezone.utc).isoformat()}\n"
        f"# Entries: {len(entries)}\n"
    )
    content = header + "".join(f"{e}:\n" for e in entries if e)

    if dry_run:
        log.info("[DRY-RUN] Would write %d entries to %s", len(entries), output_path)
        return len(entries)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Backup existing list before overwriting
    if output_path.exists():
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup = BACKUP_DIR / f"{output_path.name}.{ts}.bak"
        shutil.copy2(output_path, backup)
        log.info("Backed up %s → %s", output_path.name, backup)

    output_path.write_text(content, encoding="utf-8")
    log.info("Wrote %d entries to %s", len(entries), output_path)
    return len(entries)


# ---------------------------------------------------------------------------
# Feed fetcher
# ---------------------------------------------------------------------------

def fetch_feed(url: str, timeout: int = 30) -> Optional[str]:
    """Download feed content; returns text or None on error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "wazuh-intel-updater/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        log.error("Failed to fetch %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Wazuh manager reload
# ---------------------------------------------------------------------------

def reload_wazuh_manager(dry_run: bool) -> None:
    """Send SIGHUP to wazuh-manager to reload CDB lists without full restart."""
    if dry_run:
        log.info("[DRY-RUN] Would reload Wazuh manager (ossec-control reload)")
        return
    try:
        result = subprocess.run(
            ["/var/ossec/bin/ossec-control", "reload"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            log.info("Wazuh manager reloaded successfully")
        else:
            log.warning("Wazuh reload returned code %d: %s", result.returncode, result.stderr)
    except FileNotFoundError:
        log.warning("ossec-control not found — skipping manager reload")
    except Exception as exc:
        log.error("Manager reload failed: %s", exc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Wazuh CDB list threat-intel updater")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and parse feeds but do not write files")
    parser.add_argument("--feed", metavar="NAME",
                        help="Only update a specific feed (default: all enabled feeds)")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"CDB list output directory (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--no-reload", action="store_true",
                        help="Skip Wazuh manager reload after updating lists")
    args = parser.parse_args()

    selected_feeds = {
        name: cfg for name, cfg in FEEDS.items()
        if cfg["enabled"] and (args.feed is None or args.feed == name)
    }

    if not selected_feeds:
        log.error("No enabled feeds match the selection. Check --feed argument.")
        return 1

    # Accumulate entries per output file (multiple feeds may write to same list)
    file_entries: dict[str, set[str]] = {}
    errors = 0

    for feed_name, cfg in selected_feeds.items():
        log.info("Processing feed: %s — %s", feed_name, cfg["description"])
        content = fetch_feed(cfg["url"])
        if content is None:
            errors += 1
            continue

        parse_fn = PARSERS.get(cfg["parser"])
        if parse_fn is None:
            log.error("Unknown parser '%s' for feed '%s'", cfg["parser"], feed_name)
            errors += 1
            continue

        entries = parse_fn(content, cfg.get("field_index", 0))
        log.info("  Parsed %d entries from %s", len(entries), feed_name)

        out_file = cfg["output_file"]
        file_entries.setdefault(out_file, set()).update(entries)

    # Write merged entries per output file
    updated_files = 0
    for filename, entries in file_entries.items():
        output_path = args.output_dir / filename
        count = write_cdb_list(sorted(entries), output_path, args.dry_run)
        if count > 0:
            updated_files += 1

    log.info("Updated %d CDB list file(s), %d feed error(s)", updated_files, errors)

    if updated_files > 0 and not args.no_reload:
        reload_wazuh_manager(args.dry_run)

    return 0 if errors == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
