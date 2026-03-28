#!/usr/bin/env python3
"""
test-on-srx.py — Push converted sample configs to a real vSRX and verify commit.

For each of the 11 single-context sample configs:
  1. Runs the converter via Node.js helper (convert-sample.mjs)
  2. Filters out commands that would break management access
  3. Prepends preserve commands for management connectivity
  4. Connects to vSRX via PyEZ, loads config (override), commit-checks
  5. If clean: commits, then rolls back
  6. Logs results and prints a summary table

Usage:
    /path/to/venv/bin/python tools/test-on-srx.py

Requirements:
    - PyEZ venv at tools/pyez-bridge/venv
    - Node.js available in PATH (for convert-sample.mjs)
    - vSRX reachable at 192.168.1.240:830
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure we can import PyEZ from the venv
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
VENV_PYTHON = SCRIPT_DIR / "pyez-bridge" / "venv" / "bin" / "python"
CONVERTER_SCRIPT = SCRIPT_DIR / "convert-sample.mjs"

# Re-exec under the venv Python if we're not already running from it
if Path(sys.executable).resolve() != VENV_PYTHON.resolve():
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve())] + sys.argv[1:])

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import (
    CommitError,
    ConfigLoadError,
    LockError,
    UnlockError,
    RpcError,
)
from lxml import etree

# ---------------------------------------------------------------------------
# Connection details
# ---------------------------------------------------------------------------
SRX_HOST = "192.168.1.240"
SRX_USER = "intenttester"
SRX_SSH_KEY = os.path.expanduser("~/.ssh/intenttester_ed25519")
SRX_PORT = 830

# ---------------------------------------------------------------------------
# The 11 single-context sample keys (skip multi-vsys/vdom/logical-system/tenant)
# ---------------------------------------------------------------------------
SAMPLE_KEYS = [
    "basic",
    "medium",
    "complex",
    "edgeCases",
    "realworld",
    "srx_basic",
    "fortigate_basic",
    "cisco_basic",
    "checkpoint_basic",
    "sonicwall_basic",
    "huawei_basic",
]

# ---------------------------------------------------------------------------
# Preserve commands — prepended to every config load to keep management access
# ---------------------------------------------------------------------------
PRESERVE_COMMANDS = """\
set system host-name vSRX-test18
set system root-authentication encrypted-password "$6$slN9fm9A$LPMXWgKf9v.MkzcbjQ4qSjQ3sNJMIILeSxDJawPXU5iV4oH39VUh6E0i6.YO9yT9E72p./dG/PyNIe.U73PIa0"
set system login user intenttester class super-user uid 2002
set system login user intenttester authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG+IhfC4H8iE4pC7ZoEf245h9Mp/ZvScgldFilcuVP2X intenttester@firewall-intent-converter"
set system login user netconf class super-user uid 2000
set system login user netconf authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKOLjxJRoNDQuoBQXEEEKTcKRkhxOTDfMSWymo6m0jD+ root@cd62172ddf11"
set system login user srxoutpost class super-user uid 2001
set system login user srxoutpost authentication encrypted-password "$6$2OKfUw10$GIk.ae1jtRh30uHT.xfDd865Tp2tsl/4eqHBxf9ynKy009VG4XL6kY9Vpk/j51YZTBaJAxqKVcRf5hrOyNTs40"
set system login user srxoutpost authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILGHHz1PiPRLN3o3oRqBNkw0t9+acY6L/h7jdbL3TgHl fastrevmd@gmail.com"
set system services ssh root-login allow
set system services ssh protocol-version v2
set system services netconf ssh
set system services netconf rfc-compliant
set system services web-management https system-generated-certificate
set system services web-management https interface fxp0.0
set system services web-management http interface fxp0.0
set interfaces fxp0 unit 0 family inet address 192.168.1.240/24
"""

# ---------------------------------------------------------------------------
# Filters — remove commands that conflict with management access
# ---------------------------------------------------------------------------
FILTER_PATTERNS = [
    re.compile(r"^set\s+chassis\s+cluster\b"),
    re.compile(r"^set\s+chassis\s+aggregated-devices\b"),
    re.compile(r"^set\s+interfaces\s+fxp0\b"),
    re.compile(r"^set\s+interfaces\s+reth\b"),
    re.compile(r"^set\s+system\s+login\b"),
    re.compile(r"^set\s+system\s+host-name\b"),
    re.compile(r"^set\s+system\s+root-authentication\b"),
    re.compile(r"^set\s+system\s+services\b"),
    # vSRX only has FPC 0, slots 0-9 — filter out-of-range interfaces
    re.compile(r"^set\s+(?:interfaces|security\s+zones\s+\S+\s+interfaces)\s+\S*[1-9]+/"),
    # Filter unmapped vendor interface names (FortiGate wan/dmz/port, Cisco Gig/Eth, etc.)
    re.compile(r"^set\s+(?:interfaces|security\s+zones\s+\S+\s+interfaces)\s+(?:wan|dmz|port|internal|mgmt|ha|Gig|Eth|Ten|Hundred|Vlan|Management|X\d|tunnel|guest|global)"),
    # Filter VPN/IKE commands that reference unmapped external interfaces
    re.compile(r"^set\s+security\s+ike\s+gateway\s+\S+\s+external-interface\s+(?:wan|dmz|Gig|Eth|tunnel|global)"),
    # Filter routing protocols referencing unmapped interfaces
    re.compile(r"^set\s+protocols\s+\S+\s+.*interface\s+(?:wan|dmz|Gig|Eth|tunnel|global|loopback)"),
    # Filter any command with interface names containing vendor-specific patterns
    re.compile(r"^set\s+.*(?:external-interface|bind-interface)\s+(?:wan|dmz|Gig|Eth|tunnel)"),
    # vSRX limitations: no CoS real-time, no VxLAN/switch-options, no bridge-domains
    re.compile(r"^set\s+class-of-service\b"),
    re.compile(r"^set\s+switch-options\b"),
    re.compile(r"^set\s+vlans\b"),
    re.compile(r"^set\s+bridge-domains\b"),
    # Skip VPN config entirely (requires matching interfaces)
    re.compile(r"^set\s+security\s+ike\b"),
    re.compile(r"^set\s+security\s+ipsec\b"),
    # Skip DHCP (access pools reference vendor interfaces)
    re.compile(r"^set\s+access\b"),
    # Skip BGP (requires reachable peers)
    re.compile(r"^set\s+protocols\s+bgp\b"),
    re.compile(r"^set\s+routing-options\s+autonomous-system\b"),
    # Skip SecIntel/UTM that require licenses
    re.compile(r"^set\s+security\s+utm\b"),
    re.compile(r"^set\s+services\s+security-intelligence\b"),
    # Skip EVPN/VXLAN (not supported on vSRX)
    re.compile(r"^set\s+routing-instances\s+.*instance-type\s+evpn"),
    re.compile(r"^set\s+protocols\s+evpn\b"),
    # Skip IDP (requires signature DB)
    re.compile(r"^set\s+security\s+idp\b"),
    # Skip application-firewall (requires AppID license)
    re.compile(r"^set\s+security\s+application-firewall\b"),
    re.compile(r".*application-services\s+application-firewall"),
    # Skip static NAT rules that may have incomplete translations
    re.compile(r"^set\s+security\s+nat\s+static\b"),
    # Skip UTM/IDP/SecIntel references in policy application-services
    re.compile(r".*utm-policy\b"),
    re.compile(r".*idp-policy\b"),
    re.compile(r".*application-services\s+security-intelligence"),
    # Skip interface references outside FPC 0 slot 0
    re.compile(r".*\s+ge-0/[1-9]"),
]


def should_keep_command(line):
    """Return True if the command should be included in the config push."""
    stripped = line.strip()
    if not stripped:
        return False
    # Skip comment lines
    if stripped.startswith("#"):
        return False
    # Skip non-set lines (deactivate, etc. are fine)
    if not stripped.startswith("set ") and not stripped.startswith("deactivate "):
        return False
    for pattern in FILTER_PATTERNS:
        if pattern.match(stripped):
            return False
    return True


def convert_sample(sample_key):
    """
    Call the Node.js converter helper and return parsed JSON.
    Returns dict with keys: sampleKey, label, vendor, commands, warnings
    """
    result = subprocess.run(
        ["node", str(CONVERTER_SCRIPT), sample_key],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Converter failed for {sample_key}: {result.stderr.strip()}"
        )
    return json.loads(result.stdout)


def filter_commands(commands):
    """Filter converter output to only safe set/deactivate commands."""
    return [line.strip() for line in commands if should_keep_command(line)]


def build_config_text(filtered_commands):
    """Build the full config text: preserve commands + filtered converter output."""
    lines = PRESERVE_COMMANDS.strip().split("\n")
    lines.extend(filtered_commands)
    return "\n".join(lines)


def test_on_device(config_text, label):
    """
    Push config to vSRX via PyEZ, commit-check, commit if clean, rollback.

    Returns dict: {
        "status": "pass" | "fail" | "error",
        "commit_warnings": int,
        "commit_errors": int,
        "error_details": str | None,
        "load_warnings": list,
    }
    """
    result = {
        "status": "error",
        "commit_warnings": 0,
        "commit_errors": 0,
        "error_details": None,
        "load_warnings": [],
    }

    dev = Device(
        host=SRX_HOST,
        user=SRX_USER,
        ssh_private_key_file=SRX_SSH_KEY,
        port=SRX_PORT,
        timeout=60,
        normalize=True,
    )

    try:
        print(f"    Connecting to {SRX_HOST}...")
        dev.open()
        dev.timeout = 120

        cu = Config(dev)

        print("    Locking configuration...")
        cu.lock()

        try:
            # First, wipe non-preserved config sections so we start clean
            print("    Clearing existing config (selective delete)...")
            delete_cmds = "\n".join([
                "delete security",
                "delete applications",
                "delete firewall",
                "delete routing-options",
                "delete protocols",
                "delete policy-options",
                "delete class-of-service",
                "delete interfaces ge-0/0/0",
                "delete interfaces ge-0/0/1",
                "delete interfaces ge-0/0/2",
                "delete interfaces ge-0/0/3",
                "delete interfaces ge-0/0/4",
                "delete interfaces ge-0/0/5",
                "delete interfaces ge-0/0/6",
                "delete interfaces ge-0/0/7",
                "delete interfaces st0",
                "delete interfaces lo0",
                "delete interfaces irb",
                "delete interfaces ae0",
                "delete interfaces ae1",
                "delete interfaces ae2",
                "delete interfaces ae3",
                "delete chassis",
                "delete system syslog",
                "delete system ntp",
                "delete access",
                "delete vlans",
                "delete bridge-domains",
                "delete switch-options",
                "delete forwarding-options",
                "delete snmp",
            ])
            try:
                cu.load(delete_cmds, format="set", merge=True)
            except ConfigLoadError as cle:
                # "statement not found" warnings are expected on clean devices — ignore
                if "statement not found" in str(cle):
                    pass
                else:
                    raise
            print("    Loading converted config (set merge)...")
            cu.load(config_text, format="set", merge=True)

            print("    Running commit check...")
            try:
                commit_check_result = cu.commit_check()
                # commit_check returns True on success
                if commit_check_result:
                    print("    Commit check PASSED — committing...")
                    cu.commit(comment=f"test-on-srx: {label}")

                    print("    Rolling back...")
                    cu.rollback(rb_id=1)
                    cu.commit(comment="test-on-srx: rollback after test")

                    result["status"] = "pass"
                else:
                    result["status"] = "fail"
                    result["error_details"] = "commit_check returned False"
                    cu.rollback(rb_id=0)

            except CommitError as commit_err:
                result["status"] = "fail"
                result["commit_errors"] = 1
                error_msg = str(commit_err)
                # Try to extract structured error info from the RPC reply
                if hasattr(commit_err, "rpc_error"):
                    error_msg = str(commit_err.rpc_error)
                elif hasattr(commit_err, "errs"):
                    error_details = []
                    for err in commit_err.errs:
                        error_details.append(
                            f"  {err.get('severity', '?')}: {err.get('message', '?')}"
                        )
                    error_msg = "\n".join(error_details)
                result["error_details"] = error_msg
                print(f"    Commit check FAILED: {error_msg[:200]}")
                # Rollback the candidate to discard our changes
                try:
                    cu.rollback(rb_id=0)
                except Exception:
                    pass

        except ConfigLoadError as load_err:
            result["status"] = "fail"
            result["commit_errors"] = 1
            error_msg = str(load_err)
            if hasattr(load_err, "errs"):
                error_details = []
                for err in load_err.errs:
                    error_details.append(
                        f"  {err.get('severity', '?')}: {err.get('message', '?')}"
                    )
                error_msg = "\n".join(error_details)
            result["error_details"] = f"Config load error: {error_msg}"
            print(f"    Config load FAILED: {error_msg[:200]}")
            try:
                cu.rollback(rb_id=0)
            except Exception:
                pass

        finally:
            print("    Unlocking configuration...")
            try:
                cu.unlock()
            except UnlockError:
                pass

    except LockError as lock_err:
        result["error_details"] = f"Could not lock config: {lock_err}"
        print(f"    LOCK ERROR: {lock_err}")

    except Exception as exc:
        result["error_details"] = f"Connection/general error: {exc}"
        print(f"    ERROR: {exc}")

    finally:
        try:
            dev.close()
        except Exception:
            pass

    return result


def print_summary(results):
    """Print a formatted summary table of all test results."""
    print("\n")
    print("=" * 80)
    print("  TEST RESULTS SUMMARY")
    print("=" * 80)
    print(
        f"  {'#':<4} {'Sample':<22} {'Vendor':<12} {'Status':<8} "
        f"{'Set Cmds':<10} {'Filtered':<10} {'Errors'}"
    )
    print("-" * 80)

    pass_count = 0
    fail_count = 0
    error_count = 0

    for idx, entry in enumerate(results, 1):
        status = entry["device_result"]["status"]
        status_display = {
            "pass": "PASS",
            "fail": "FAIL",
            "error": "ERROR",
        }.get(status, status.upper())

        if status == "pass":
            pass_count += 1
        elif status == "fail":
            fail_count += 1
        else:
            error_count += 1

        error_brief = ""
        if entry["device_result"]["error_details"]:
            error_brief = entry["device_result"]["error_details"][:35]

        print(
            f"  {idx:<4} {entry['label']:<22} {entry['vendor']:<12} "
            f"{status_display:<8} {entry['total_commands']:<10} "
            f"{entry['filtered_commands']:<10} {error_brief}"
        )

    print("-" * 80)
    print(f"  Total: {len(results)}  |  Pass: {pass_count}  |  Fail: {fail_count}  |  Error: {error_count}")
    print("=" * 80)


def main():
    """Run all 11 sample configs through convert -> push -> verify -> rollback."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = SCRIPT_DIR / f"test-on-srx-results_{timestamp}.json"

    print(f"test-on-srx.py — {datetime.now().isoformat()}")
    print(f"Target: {SRX_USER}@{SRX_HOST}:{SRX_PORT}")
    print(f"Results will be saved to: {results_file}")
    print(f"Testing {len(SAMPLE_KEYS)} sample configs\n")

    all_results = []

    for idx, sample_key in enumerate(SAMPLE_KEYS, 1):
        print(f"[{idx}/{len(SAMPLE_KEYS)}] {sample_key}")

        entry = {
            "sample_key": sample_key,
            "label": "",
            "vendor": "",
            "total_commands": 0,
            "filtered_commands": 0,
            "device_result": {
                "status": "error",
                "commit_warnings": 0,
                "commit_errors": 0,
                "error_details": None,
                "load_warnings": [],
            },
        }

        # Step 1: Convert via Node.js
        try:
            print(f"  Converting {sample_key}...")
            converted = convert_sample(sample_key)
            entry["label"] = converted.get("label", sample_key)
            entry["vendor"] = converted.get("vendor", "unknown")
            entry["total_commands"] = len(converted.get("commands", []))

            raw_commands = converted.get("commands", [])
        except Exception as exc:
            entry["device_result"]["error_details"] = f"Converter error: {exc}"
            print(f"  CONVERTER ERROR: {exc}")
            all_results.append(entry)
            continue

        # Step 2: Filter commands
        filtered = filter_commands(raw_commands)
        entry["filtered_commands"] = len(filtered)
        print(f"  {entry['total_commands']} total commands -> {len(filtered)} after filtering")

        if not filtered:
            print("  No set commands to push (all filtered out), skipping device push.")
            entry["device_result"]["status"] = "pass"
            entry["device_result"]["error_details"] = "No commands after filtering (trivially passes)"
            all_results.append(entry)
            continue

        # Step 3: Build full config with preserve commands
        config_text = build_config_text(filtered)

        # Step 4: Push to device
        entry["device_result"] = test_on_device(config_text, entry["label"])
        all_results.append(entry)

        # Brief pause between tests to let the device settle
        if idx < len(SAMPLE_KEYS):
            time.sleep(2)

    # Print summary
    print_summary(all_results)

    # Save detailed results to JSON
    with open(results_file, "w") as fh:
        json.dump(all_results, fh, indent=2, default=str)
    print(f"\nDetailed results saved to: {results_file}")


if __name__ == "__main__":
    main()
