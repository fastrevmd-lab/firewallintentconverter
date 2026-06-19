# Tiled Source Chooser — Import Page

**Date:** 2026-06-19
**Component:** `public/components/ConfigInput.jsx`
**Status:** Approved design, ready for implementation plan

## Problem

On the Import page, the conversion source is selected via a `<select className="vendor-select">`
dropdown that defaults to `Greenfield (New Config)`. Because Greenfield renders a prominent
"Choose a starting template" grid, a first-time user landing on this page perceives Greenfield
as the only option and does not realize the tool converts from 11 other sources (PAN-OS,
FortiGate, Cisco ASA, etc.). The 12 sources are effectively hidden inside one dropdown.

## Goal

Surface all conversion sources as a discoverable, brand-iconed **tile grid** in the
`Source Configuration` panel, replacing the dropdown as the selection mechanism. No change
to parsing/conversion behavior — purely the source-selection UX in front of the existing
import + template flows.

## Scope

- In scope: the source selector inside `ConfigInput.jsx` (the `vendor-select` dropdown and the
  area above the import controls / template picker), plus supporting CSS.
- Out of scope: parsers, converters, validators, `useConversion`/`useConfig` wiring beyond the
  existing `selectedVendor` state, merge-mode slot tabs, the template picker internals, the
  import controls (upload / sample / parse / textarea / Pull from Device) — all reused as-is.

## Decisions (from brainstorming)

1. **Placement — in-panel grid (not full-screen launchpad).** Tiles render in the left
   `Source Configuration` panel body, where the dropdown + content sit today. The 3-pane
   workspace (Navigator / editor / Inspector) remains visible throughout.
2. **Icon treatment — brand-colored marks.** Each tile has a tinted icon chip in the vendor's
   brand color. Brand color is **confined to the icon chip** (tinted background + colored
   glyph); the rest of the tile uses the normal palette (teal selected border, standard text).
   This is a deliberate, user-approved exception to the strict semantic palette, kept narrow so
   it does not bleed into the rest of the UI.
3. **Icons — custom inline SVG glyphs, NOT real vendor logos.** Simple abstract marks colored
   per brand, in the same inline-SVG style as the existing `TEMPLATE_ICONS`. Avoids
   trademark/redistribution concerns and keeps a single visual style.
4. **Selection flow.** Clicking a tile collapses the grid to a compact "selected source"
   header (icon chip + name + secondary line + a `Change` link) and reveals the existing
   controls below. `Change` reopens the grid. Greenfield → existing template picker; any
   vendor → existing import controls.

## Layout

### Grouping (rendered top to bottom)

- **From scratch:** `greenfield` (Greenfield / New Config), `srx_healthcheck` (Junos SRX Best Practice)
- **Firewall vendors:** `srx` (Junos SRX), `panos` (PAN-OS), `fortigate` (FortiGate),
  `cisco_asa` (Cisco ASA/FTD), `checkpoint` (Check Point R80+), `sonicwall` (SonicWall SonicOS),
  `huawei_usg` (Huawei USG)
- **Cloud:** `aws_sg` (AWS Security Groups), `azure_nsg` (Azure NSG), `gcp_fw` (GCP Firewall Rules)

The `value` strings above are the exact `selectedVendor` values currently used by the
`<select>` — they must be preserved so `onParse(selectedVendor)`, sample filtering, and
textarea placeholders keep working unchanged.

### Tile

- Icon chip (≈24px, rounded) with brand-tinted background and brand-colored glyph + label.
- Selected tile: teal (`--accent`) border, elevated background, primary text color.
- Hover: standard `--bg-hover`.

### Brand colors (icon chip only)

| Source | Brand color | Notes |
|---|---|---|
| greenfield | `--llm-cloud` violet `#a78bfa` | LLM-driven; obeys color convention |
| srx_healthcheck | `--juniper-green` `#90C641` | SRX target family |
| srx | `--juniper-green` `#90C641` | |
| panos | `#FA582D` | Palo Alto orange |
| fortigate | `#EE3124` | Fortinet red |
| cisco_asa | `#1BA0D7` | Cisco blue |
| checkpoint | `#E6097E` | Check Point magenta |
| sonicwall | `#FF6C2C` | SonicWall orange |
| huawei_usg | `#E40012` | Huawei red |
| aws_sg | `#FF9900` | AWS orange |
| azure_nsg | `#0078D4` | Azure blue |
| gcp_fw | `#4285F4` | Google blue |

Chip background = brand color at ~18% alpha; glyph = full brand color. These are icon-chip
fills only and carry no semantic state meaning.

## Selected-source header

When a source is selected:

```
[icon chip]  <Source name>            [ Change ]
             <secondary descriptor>
```

- Greenfield: name in violet, secondary "LLM-guided · start from a template".
- Vendors: name in primary text, secondary describing the import (e.g. "FortiOS config import").
- `Change` link (teal, bordered) clears the selection back to the grid.

## State & wiring

- Reuse existing `selectedVendor` `useState`. Add a small piece of local state to track whether
  the grid is open vs. a source is committed (e.g. `sourceCommitted` boolean), so the grid can
  collapse on pick and reopen on `Change`.
- **Initial state on first load: grid open, nothing committed** — so the full set of tiles is
  visible immediately. This is the core fix for the discoverability problem. (Contrast with
  today, which auto-commits to `greenfield` and jumps straight to the template picker.)
- Tile `onClick` sets `selectedVendor` and commits the selection (replacing `onChange` of the
  `<select>`).
- `deterministicMode`: the **From scratch** group is not rendered (mirrors today's behavior of
  hiding the `greenfield` and `srx_healthcheck` options); default committed source stays `panos`.
- `greenfieldMode` / `isParsed`: while parsed or in an active greenfield interview, the selector
  is locked (today the `<select>` is `disabled`). Equivalent behavior: show the selected-source
  header without an active `Change` affordance (or disabled), matching current lock semantics.
- Merge mode (`mergeMode`) and the slot tab bar are unchanged.
- The LLM warning currently on the dropdown (border/color + title tooltip when greenfield, using
  `--llm-cloud` or `--llm-local` based on `llmLocalOnly`) carries over to the Greenfield tile and
  its selected-source header.

## Files touched

- `public/components/ConfigInput.jsx` — replace the `<select>` with the tile grid + selected
  header; add a source-metadata map (id → label, group, brand color, secondary text, glyph);
  add the SVG glyphs (alongside or extending `TEMPLATE_ICONS`).
- `public/styles/main.css` (or the relevant existing stylesheet) — tile grid, tile, icon chip,
  group label, and selected-source header styles. Follow existing class-naming patterns.

## Testing

- No engine/unit-test changes expected (logic untouched). Verify `npx vitest run tests/` stays green.
- Manual: each tile selects the right source; Parse works per vendor; sample buttons filter
  correctly; Greenfield shows the template picker; `Change` reopens the grid; `deterministicMode`
  hides the From-scratch group; parsed/greenfield-active state locks the selector; LLM warning
  styling shows on the Greenfield tile.
- `npm run build` succeeds.

## Non-goals / YAGNI

- No real vendor logo assets.
- No new conversion sources.
- No change to the 3-pane workspace shell or Navigator.
