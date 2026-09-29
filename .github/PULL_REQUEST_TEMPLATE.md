## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `npx vitest run` passes, and any relevant self-contained suites under `tests/` (see CONTRIBUTING.md)
- [ ] `npm run build` succeeds
- [ ] If `tools/pyez-bridge/` changed: `python -m unittest discover tools/pyez-bridge/tests -v` passes
- [ ] This PR touches vendor parsing/conversion logic for: <!-- none, or list: PAN-OS / Junos SRX / FortiGate / Cisco ASA-FTD / Check Point / SonicWall / Huawei USG / AWS / Azure / GCP -->
- [ ] Any new or changed fixtures/example configs are synthetic — no real customer or device configs, hostnames, serial numbers, IPs, or credentials
- [ ] No secrets, credentials, real hostnames, or real device configs in code, tests, fixtures, or this description
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches the LLM translate / greenfield interview / health-check path: the human "Accept" gate and the deterministic parser/serializer/validators still decide the final output — nothing here lets an LLM response reach output or a device unreviewed
- [ ] If this touches the PyEZ bridge or any device-push path: a device-changing action still requires an explicit human action, not automatic application of a model output

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
