#!/usr/bin/env python3
"""
CIS Benchmark Checker — Checks a Linux system (or mock config file) against
CIS Benchmark Level 1 controls: password policy, SSH config, file permissions,
logging, and cron jobs.

Usage:
    python cis_benchmark_checker.py --live        # check running system (requires read permissions)
    python cis_benchmark_checker.py --mock        # use bundled mock config for demo
    python cis_benchmark_checker.py --output report.json
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    cis_id: str
    title: str
    status: str        # PASS | FAIL | WARN | SKIP
    finding: str
    recommendation: str
    level: int = 1     # CIS Benchmark Level 1 or 2


MOCK_CONFIG = {
    "passwd_maxdays": "90",
    "passwd_mindays": "7",
    "passwd_minlen": "14",
    "passwd_warn_age": "7",
    "ssh_root_login": "no",
    "ssh_protocol": "2",
    "ssh_max_auth_tries": "6",       # CIS says 4 max — this will FAIL
    "ssh_permit_empty_pw": "no",
    "ssh_x11_forwarding": "yes",     # CIS says no — this will FAIL
    "ssh_allow_tcp_forwarding": "no",
    "ssh_client_alive_interval": "300",
    "ssh_client_alive_count": "0",
    "ssh_log_level": "INFO",
    "ssh_host_based_auth": "no",
    "ssh_ignore_rhosts": "yes",
    "rsyslog_enabled": "yes",
    "auditd_enabled": "yes",
    "cron_allow_exists": "yes",
    "cron_deny_exists": "no",
    "umask": "027",
    "sticky_bit_world_writable": "yes",
    "nopasswd_sudo": "no",
    "shadow_file_perm": "640",       # CIS says 000 — this will FAIL
    "passwd_file_perm": "644",
    "sshd_config_perm": "600",
    "firewall_enabled": "yes",
    "ipv6_disabled": "no",
}


def _run(cmd: list[str]) -> str:
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text()
    except (FileNotFoundError, PermissionError):
        return ""


def _sshd_value(key: str, config_text: str) -> str:
    m = re.search(rf"^\s*{key}\s+(\S+)", config_text, re.MULTILINE | re.IGNORECASE)
    return m.group(1) if m else ""


def _login_defs_value(key: str, text: str) -> str:
    m = re.search(rf"^\s*{key}\s+(\d+)", text, re.MULTILINE)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Live system checks
# ---------------------------------------------------------------------------

def check_live() -> dict:
    config = {}

    # /etc/login.defs
    login_defs = _read_file("/etc/login.defs")
    config["passwd_maxdays"] = _login_defs_value("PASS_MAX_DAYS", login_defs)
    config["passwd_mindays"] = _login_defs_value("PASS_MIN_DAYS", login_defs)
    config["passwd_minlen"] = _login_defs_value("PASS_MIN_LEN", login_defs)
    config["passwd_warn_age"] = _login_defs_value("PASS_WARN_AGE", login_defs)

    # sshd_config
    sshd = _read_file("/etc/ssh/sshd_config")
    config["ssh_root_login"] = _sshd_value("PermitRootLogin", sshd).lower()
    config["ssh_protocol"] = _sshd_value("Protocol", sshd)
    config["ssh_max_auth_tries"] = _sshd_value("MaxAuthTries", sshd)
    config["ssh_permit_empty_pw"] = _sshd_value("PermitEmptyPasswords", sshd).lower()
    config["ssh_x11_forwarding"] = _sshd_value("X11Forwarding", sshd).lower()
    config["ssh_allow_tcp_forwarding"] = _sshd_value("AllowTcpForwarding", sshd).lower()
    config["ssh_client_alive_interval"] = _sshd_value("ClientAliveInterval", sshd)
    config["ssh_client_alive_count"] = _sshd_value("ClientAliveCountMax", sshd)
    config["ssh_log_level"] = _sshd_value("LogLevel", sshd).upper()
    config["ssh_host_based_auth"] = _sshd_value("HostbasedAuthentication", sshd).lower()
    config["ssh_ignore_rhosts"] = _sshd_value("IgnoreRhosts", sshd).lower()

    # Services
    rsyslog = _run(["systemctl", "is-active", "rsyslog"])
    config["rsyslog_enabled"] = "yes" if "active" in rsyslog else "no"
    auditd = _run(["systemctl", "is-active", "auditd"])
    config["auditd_enabled"] = "yes" if "active" in auditd else "no"

    # Cron allow/deny
    config["cron_allow_exists"] = "yes" if Path("/etc/cron.allow").exists() else "no"
    config["cron_deny_exists"] = "yes" if Path("/etc/cron.deny").exists() else "no"

    # umask
    profile = _read_file("/etc/profile")
    umask_m = re.search(r"umask\s+(\d+)", profile)
    config["umask"] = umask_m.group(1) if umask_m else "022"

    # Sudo nopasswd
    sudoers = _run(["grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/"])
    config["nopasswd_sudo"] = "yes" if "NOPASSWD" in sudoers else "no"

    # Shadow file permissions
    shadow_stat = _run(["stat", "-c", "%a", "/etc/shadow"])
    config["shadow_file_perm"] = shadow_stat

    # Firewall
    ufw_status = _run(["ufw", "status"])
    config["firewall_enabled"] = "yes" if "active" in ufw_status.lower() else "no"

    return config


# ---------------------------------------------------------------------------
# CIS check functions
# ---------------------------------------------------------------------------

def run_checks(config: dict) -> list[CheckResult]:
    results = []

    def chk(cis_id: str, title: str, passed: bool, finding: str, recommendation: str, level: int = 1) -> None:
        results.append(CheckResult(
            cis_id=cis_id,
            title=title,
            status="PASS" if passed else "FAIL",
            finding=finding,
            recommendation=recommendation,
            level=level,
        ))

    # 5.4 — Password policy
    max_days = int(config.get("passwd_maxdays") or 999)
    chk("5.4.1.1", "Ensure password expiration is 365 days or less",
        max_days <= 365, f"PASS_MAX_DAYS = {max_days}",
        "Set PASS_MAX_DAYS 365 in /etc/login.defs and run: chage --maxdays 365 <user>")

    min_days = int(config.get("passwd_mindays") or 0)
    chk("5.4.1.2", "Ensure minimum days between password changes >= 1",
        min_days >= 1, f"PASS_MIN_DAYS = {min_days}",
        "Set PASS_MIN_DAYS 1 in /etc/login.defs")

    warn_age = int(config.get("passwd_warn_age") or 0)
    chk("5.4.1.3", "Ensure password expiry warning >= 7 days",
        warn_age >= 7, f"PASS_WARN_AGE = {warn_age}",
        "Set PASS_WARN_AGE 7 in /etc/login.defs")

    # 5.3 — SSH
    chk("5.2.8", "Ensure SSH root login is disabled",
        config.get("ssh_root_login") in ("no", "prohibit-password"),
        f"PermitRootLogin = {config.get('ssh_root_login', 'not set')}",
        "Set PermitRootLogin no in /etc/ssh/sshd_config")

    max_auth = int(config.get("ssh_max_auth_tries") or 6)
    chk("5.2.7", "Ensure SSH MaxAuthTries is 4 or fewer",
        max_auth <= 4, f"MaxAuthTries = {max_auth}",
        "Set MaxAuthTries 4 in /etc/ssh/sshd_config")

    chk("5.2.4", "Ensure SSH X11 forwarding is disabled",
        config.get("ssh_x11_forwarding", "yes") == "no",
        f"X11Forwarding = {config.get('ssh_x11_forwarding', 'yes')}",
        "Set X11Forwarding no in /etc/ssh/sshd_config")

    chk("5.2.5", "Ensure SSH AllowTcpForwarding is disabled",
        config.get("ssh_allow_tcp_forwarding", "yes") == "no",
        f"AllowTcpForwarding = {config.get('ssh_allow_tcp_forwarding', 'yes')}",
        "Set AllowTcpForwarding no in /etc/ssh/sshd_config")

    chk("5.2.3", "Ensure SSH PermitEmptyPasswords is disabled",
        config.get("ssh_permit_empty_pw", "yes") == "no",
        f"PermitEmptyPasswords = {config.get('ssh_permit_empty_pw', 'yes')}",
        "Set PermitEmptyPasswords no in /etc/ssh/sshd_config")

    interval = int(config.get("ssh_client_alive_interval") or 0)
    chk("5.2.16", "Ensure SSH idle timeout (ClientAliveInterval) <= 300",
        0 < interval <= 300, f"ClientAliveInterval = {interval}",
        "Set ClientAliveInterval 300 in /etc/ssh/sshd_config")

    chk("5.2.6", "Ensure SSH IgnoreRhosts is enabled",
        config.get("ssh_ignore_rhosts", "no") == "yes",
        f"IgnoreRhosts = {config.get('ssh_ignore_rhosts', 'no')}",
        "Set IgnoreRhosts yes in /etc/ssh/sshd_config")

    # Logging
    chk("4.1.2", "Ensure rsyslog is installed and running",
        config.get("rsyslog_enabled", "no") == "yes",
        f"rsyslog active: {config.get('rsyslog_enabled', 'no')}",
        "Install and enable rsyslog: apt install rsyslog && systemctl enable rsyslog")

    chk("4.1.1.1", "Ensure auditd is installed and running",
        config.get("auditd_enabled", "no") == "yes",
        f"auditd active: {config.get('auditd_enabled', 'no')}",
        "Install and enable auditd: apt install auditd && systemctl enable auditd")

    # Cron
    chk("5.1.8", "Ensure cron.allow restricts cron access",
        config.get("cron_allow_exists", "no") == "yes",
        f"/etc/cron.allow exists: {config.get('cron_allow_exists', 'no')}",
        "Create /etc/cron.allow with approved users: echo 'root' > /etc/cron.allow; chmod 600 /etc/cron.allow")

    # Permissions
    shadow_perm = config.get("shadow_file_perm", "640")
    chk("6.1.3", "Ensure /etc/shadow permissions are 000 or 640",
        shadow_perm in ("000", "640"), f"/etc/shadow permissions: {shadow_perm}",
        "Run: chmod 000 /etc/shadow && chown root:shadow /etc/shadow")

    # Sudo
    chk("5.3.2", "Ensure sudo does not have NOPASSWD",
        config.get("nopasswd_sudo", "yes") == "no",
        f"NOPASSWD in sudoers: {config.get('nopasswd_sudo', 'unknown')}",
        "Remove NOPASSWD from /etc/sudoers — require password for all sudo")

    # Firewall
    chk("3.6.1", "Ensure a firewall is active",
        config.get("firewall_enabled", "no") == "yes",
        f"Firewall active: {config.get('firewall_enabled', 'no')}",
        "Enable UFW: ufw enable, or configure iptables/nftables")

    return results


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(results: list[CheckResult]) -> None:
    passed = [r for r in results if r.status == "PASS"]
    failed = [r for r in results if r.status == "FAIL"]

    print(f"\n{'═'*75}")
    print(f"  CIS BENCHMARK LEVEL 1 — LINUX ASSESSMENT")
    print(f"{'═'*75}")
    print(f"  Total Checks : {len(results)}")
    print(f"  ✅ PASS      : {len(passed)}")
    print(f"  ❌ FAIL      : {len(failed)}")
    print(f"  Score        : {100 * len(passed) // len(results)}%")
    print(f"{'─'*75}")

    print(f"\n  FAILED CHECKS:")
    for r in failed:
        print(f"\n  ❌ [{r.cis_id}] {r.title}")
        print(f"     Finding : {r.finding}")
        print(f"     Fix     : {r.recommendation}")

    print(f"\n  PASSED CHECKS:")
    for r in passed:
        print(f"  ✅ [{r.cis_id}] {r.title} — {r.finding}")

    print(f"\n{'═'*75}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check Linux system against CIS Benchmark Level 1 controls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="Check the running system")
    mode.add_argument("--mock", action="store_true", help="Use bundled demo config")
    parser.add_argument("--output", type=Path, help="Write JSON report to file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.live:
        logger.info("Running live system checks (requires sufficient read permissions)")
        config = check_live()
    else:
        logger.info("Using mock configuration for demonstration")
        config = MOCK_CONFIG

    results = run_checks(config)
    print_report(results)

    if args.output:
        report = {
            "mode": "live" if args.live else "mock",
            "total": len(results),
            "passed": sum(1 for r in results if r.status == "PASS"),
            "failed": sum(1 for r in results if r.status == "FAIL"),
            "checks": [
                {
                    "cis_id": r.cis_id,
                    "title": r.title,
                    "status": r.status,
                    "finding": r.finding,
                    "recommendation": r.recommendation,
                }
                for r in results
            ],
        }
        with args.output.open("w") as fh:
            json.dump(report, fh, indent=2)
        logger.info("Report written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
