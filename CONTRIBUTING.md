# Contributing to firewallintentconverter

Thanks for considering a contribution. firewallintentconverter is a browser-based tool that converts firewall and cloud security-group configurations (PAN-OS, Junos SRX, FortiGate, Cisco ASA/FTD, Check Point, SonicWall, Huawei USG, AWS Security Groups, Azure NSG, GCP Firewall Rules) into an intermediate format for review and conversion to Juniper SRX — a mechub project, part of the family of open-source, self-hosted network-security automation tooling. See [README.md](README.md) for what it does and [DESIGN.md](DESIGN.md) / [BUILD-PLAN-withoutLLM.md](BUILD-PLAN-withoutLLM.md) for how it's put together.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code.
- This project follows mechub's one hard rule, already stated in this repo's own README footer: **deterministic code decides, the model explains, a human approves.** The LLM features here (Translate with LLM, the greenfield interview, the compliance Health Check) may draft a suggested policy translation, flag findings, or propose config — they never get to be the thing that silently becomes the final output or gets pushed to a device. Every LLM-touched rule is marked "LLM Reviewed" and must be explicitly **Accepted** by a human before it counts as final; the deterministic parser, serializer, and validators are what actually produce and validate SRX output. Nothing you contribute should weaken that gate — for example, by auto-accepting LLM output, or by letting a "Pull from Device" / "Push to Mist"-style path apply a change without an explicit human action in between.

## Tech stack

This is a Vite + React (JavaScript, ESM) web app, plus a small Python bridge tool (`tools/pyez-bridge`) used for the optional "Pull from Device" / PyEZ push features. CI runs on Node 22 and Python 3.12 — match those locally if you can.

## Install, build, run

```sh
npm ci
npm run dev             # local dev server (vite --host)
npm run build           # production build
npm run preview         # preview a production build locally
```

Standalone build (single-file, works from file://, LLM features and PyEZ push stripped):

```sh
npm run build:standalone
```

These are the exact scripts defined in `package.json` — there is no separate lint or test script defined there (see below).

## Tests

There is no `npm test` script yet. Run the suites the same way `.github/workflows/ci.yml` does:

```sh
npx vitest run
```

A handful of suites under `tests/` are self-contained (not vitest-based) and are run directly with Node, e.g.:

```sh
for f in tests/*.test.js; do grep -q "from 'vitest'" "$f" || node "$f"; done
```

If your change touches `tools/pyez-bridge/`, also run its suite:

```sh
python -m pip install -r tools/pyez-bridge/requirements.txt
python -m unittest discover tools/pyez-bridge/tests -v
```

Add or update tests for any behavior change, especially in `src/parsers/`, `src/converters/`, or `src/conversion/` — the vendor parsing and SRX-generation logic.

## Lint

There is currently no lint script or ESLint configuration in this repository. Don't invent lint failures that can't be reproduced locally. If you add linting, wire it into `.github/workflows/ci.yml` as an explicit, required step and update this file to document the command.

## Fixtures and test data

Never commit real device configs, hostnames, serial numbers, IP addresses, or credentials — synthetic or sanitized fixtures only. This tool ships an 18-category sanitizer and RFC 5737 / RFC 3849 documentation address ranges for exactly this reason; use them (or hand-written synthetic data) for any new fixture. If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).

## Commit and PR conventions

- Match the existing commit style visible in `git log`: `type: summary (#NNN)` or `type(scope): summary` (`fix(deps):`, `ci:`, `chore(release):`, etc.).
- Keep PRs focused on one change.
- Fill out the PR template, including the exact commands you ran to verify the change.
- By opening a pull request, you're agreeing your contribution is licensed under this repository's [MIT license](LICENSE), consistent with the notice already in [README.md](README.md#license).

## Review process

All contributions land as a pull request against `main` for human review — nothing is pushed to `main` directly. Every pull request goes through a security review and a code review, then an independent test run, before anything merges. Only a maintainer merges; contributors, including anyone with write access, should not merge their own PR. CI (build, tests, SAST/secret scanning, dependency audit) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.
