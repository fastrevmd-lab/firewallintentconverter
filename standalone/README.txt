firewallintentconverter · a mechub project — Standalone Edition
===============================================================

A self-contained, offline web application that converts multi-vendor
firewall configurations to Juniper SRX format. No server, no install,
no internet connection required.

QUICK START
-----------
1. Unzip this archive
2. Open index.html in your browser

  Firefox:  Works directly from file://
  Chrome:   Launch with --allow-file-access-from-files flag, or serve
            the folder locally:
              python3 -m http.server 8000
            then open http://localhost:8000

SUPPORTED VENDORS
-----------------
  - Palo Alto Networks (PAN-OS XML)
  - Fortinet FortiGate (FortiOS config blocks)
  - Cisco ASA / FTD (show running-config)
  - Check Point R80+ (JSON + Gaia CLI)
  - SonicWall SonicOS 7 (JSON / TSR)
  - Huawei USG / VRP (CLI format)
  - Juniper SRX (set commands / hierarchical)

FEATURES
--------
  - Parse any supported vendor config and view policies, objects,
    zones, NAT, routing, and more in a structured editor
  - Convert to SRX set commands or XML format
  - Validation, shadow-rule detection, and optimization analysis
  - Hardware model selection with port/spec database
  - Interface mapping between source and target platforms
  - Multi-config merge mode (logical systems)
  - Configuration sanitization (redact IPs, secrets, keys)
  - Save/load projects (.fpic.json files)
  - Compliance report generation

NOT INCLUDED (STANDALONE)
-------------------------
  - LLM/AI translation (requires cloud API access)
  - Push-to-device via PyEZ (requires Python sidecar)

These features are available in the full version.
