# Mechub Branding Design

**Date:** 2026-07-13  
**Status:** Approved for implementation
**Brand authority:** <https://command.mechub.org/branding> (Mechub brand system v1.1)

## Objective

Bring the complete user-facing application into the Mechub brand system. Replace the generic application icon with the official topology “M,” adopt the official product lockup, typography, colors, and control language, and carry the same identity into browser metadata and generated reports.

The rebrand must preserve the converter’s information architecture, workflows, state behavior, conversion output, accessibility semantics, and offline standalone build.

## Scope

The approved scope is end to end:

- Interactive application shell and all existing views
- Dark and light themes
- Browser title, favicon, description, and accessible brand labels
- HTML and PDF report presentation
- Standard Vite build and standalone/offline build
- Focused automated tests and representative rendered-state verification

This work does not redesign the workflow, rename domain concepts, change conversion behavior, rewrite feature components, or alter the contents of exported firewall configurations.

## Current-State Findings

The current application diverges from the brand authority in several concrete ways:

- `TopBar.jsx` references a 1.4 MB generic arrow-and-checkmark image at `static/logo.png`; it is not the Mechub M and is wasteful at a 28 px display size.
- The visible title is “Firewall Policy to Intent Converter,” not the official lowercase product name.
- The browser title still reads “Firewall Policy Converter — PAN-OS → SRX.”
- The application uses Inter and JetBrains Mono fallbacks without shipping the primary Geist families.
- Dark surfaces use a lighter charcoal scale rather than the official ink scale.
- LLM colors distinguish providers with violet and magenta instead of reserving the Mechub plum family for all model activity.
- Buttons and badges use several unrelated radii, heights, and type treatments.
- HTML and PDF reports use unrelated palettes and legacy product wording.
- The repository already contains accurate dark- and light-background Mechub mark SVGs under `docs/assets/`, but they are not used by the application.

## Chosen Approach

Use a token-led comprehensive rebrand. Establish canonical brand assets, fonts, and semantic tokens, then update the existing application shell and styling layers to consume them. Apply the same identity explicitly to report templates.

This approach is preferred over a header-only reskin because the latter would leave visibly inconsistent controls, model indicators, and reports. A component-by-component rewrite is rejected because it would add layout and regression risk without improving brand fidelity beyond what shared tokens and targeted component changes can deliver.

## Identity Foundation

### Brand assets

Create a dedicated `static/brand/` asset namespace for the official mark. This repository configures Vite's `publicDir` as `static`, so these files are copied consistently into both build forms:

- Primary gradient topology M for backgrounds at or darker than `#171A22`
- Deep-teal mark for light backgrounds
- Strokes-only favicon variant for sizes below the brand system’s 20 px minimum for the full node mark

The full mark keeps the authoritative 120-unit geometry:

- Path: `M18,96 L18,32 L60,74 L102,32 L102,96`
- Stroke width 7 with round caps and joins
- Outer nodes radius 7
- Hub radius 11 with radius-5.5 inner core
- One hub-diameter of clear space around the full mark where layout permits

The SVG assets are the source of truth. Application references use Vite's base URL rather than root-absolute paths so they resolve in the standard build and from `file://` in the standalone build. Report generators use the same geometry through a small safe inline-SVG helper because downloaded reports cannot depend on application-relative asset paths. Raster substitutes, decorative shadows, glows, rotations, and recolored individual nodes are prohibited.

### Product lockup

The top bar uses a small reusable lockup rather than an unstructured image and heading pair:

- Official M mark at a legible 28 px display size
- Product name `firewallintentconverter`, always lowercase and without separators
- `intent` highlighted with the appropriate plum token
- Endorsement `· a mechub project`, lowercase

Below 1200 px viewport width, the endorsement hides before the product name or mark. The mark and accessible product label always remain. The top bar keeps its current functional actions, statistics, and responsive behavior.

Browser metadata uses the same naming:

- Title: `firewallintentconverter · a mechub project`
- Description: `Browser-based, deterministic firewall configuration translation to Juniper SRX — a migration draft requiring review.`
- Favicon: strokes-only M

### Typography

Self-host Geist and Geist Mono as WOFF2 assets so no runtime network request is needed and the standalone build remains offline-capable.

- Geist carries interface, body, and display copy.
- Geist Mono carries configurations, commands, identifiers, tabular numbers, buttons, chips, and badges.
- Existing Inter and JetBrains Mono stacks remain fallbacks.
- The top-bar product wordmark uses `-0.045em` tracking; ordinary interface and data text keeps normal tracking.
- Dense UI text remains within the guide’s 11–15 px scale; this is a brand application, not a general typography enlargement.

Font licensing material must accompany any committed font files.

## Visual System

### Dark-theme tokens

The dark theme uses the authoritative core palette:

| Role | Token value |
| --- | --- |
| Page background | `#0B0D12` |
| Panel | `#12151C` |
| Raised surface | `#171A22` |
| Hairline/border | `#262B38` |
| Primary text | `#F8F9FA` |
| Secondary text | `#C9CED5` |
| Muted text | `#9AA2AD` |
| Identity/action teal | `#4DD0C8` |
| Deep teal | `#0D9488` |
| Dim teal | `#005B5A` |
| Model plum | `#7C3AED` |
| Model text on ink | `#C4B5FD` |
| Juniper data | `#90C641` |
| Success | `#34D399` |
| Warning | `#FBBF24` |
| Error | `#F87171` |
| Information | `#60A5FA` |

Hover, selected, focus, and translucent states derive from these roles rather than introducing new identity colors.

### Light-theme tokens

Light mode remains supported. It keeps the existing neutral `#F5F6F8` page base and accessible neutral surface hierarchy, with these mandatory brand rules:

- Filled and large-text accents use `#0D9488`.
- Body-size teal text uses `#005B5A`.
- The light-background M uses deep teal.
- Model text uses the official `#7C3AED` plum, which measures 5.27:1 against the `#F5F6F8` light page background; model surfaces use a translucent form of the same plum.
- Juniper and semantic roles remain distinct.

Light mode is verified independently rather than assumed correct because the primary mark cannot be placed on a background lighter than `#171A22`.

### Color semantics

Color communicates a single stable meaning across the application and reports:

- Teal: Mechub identity, focus, selection, and the primary action in a view
- Plum: model/LLM speech, generated content, or actions that invoke a model
- Juniper green: SRX devices, licenses, and target-specific data
- Green, amber, red, and blue: success, warning, error, and information respectively

Provider identity remains visible in text labels and tooltips. It is not encoded by conflicting violet-versus-magenta brand colors.

### Controls and surfaces

The implementation consolidates shared buttons, chips, badges, and link-like controls around Geist Mono, pill geometry, and a 34 px standard interactive height. Existing component-specific classes consume shared custom properties instead of repeating raw colors and radii.

Compact icon controls may use a 28 px box when a 34 px control would break dense spatial context; 28 px remains above the WCAG 2.2 AA 24 px minimum target size. Their color, focus, and hover treatments use the shared tokens. Table cells and status-only labels are not enlarged merely to imitate buttons.

Panels and modals retain modest radii; the full-pill rule applies to actionable controls and compact status atoms, not to every container.

The application continues to use a single visually dominant teal action per view. Secondary actions use quiet raised surfaces and brand-consistent borders.

## Application Surfaces

Shared tokens and typography apply to:

- Top bar and brand lockup
- Workflow stepper and breadcrumbs
- Navigator and inspector trees
- Content panels, tables, editors, and empty states
- Forms, tabs, modals, menus, and tooltips
- Command palette and status bar
- Loading, error, warning, success, and information states
- LLM settings, model-generated notes, translation actions, and provider labels

Targeted component markup changes are allowed where semantic spans or reusable brand elements are needed. The rebrand must not change context contracts, reducer state, event behavior, keyboard handling, or conversion logic.

## Reports

Generated HTML and PDF reports use a print-safe application of the same identity:

- M mark in the report header
- Official lowercase product lockup and endorsement
- Geist/Geist Mono when available, with robust system fallbacks
- Teal identity and primary hierarchy
- Plum only for model-authored material
- Juniper green only for SRX target data
- Existing semantic colors for findings and status
- Updated footer wording: `Generated by firewallintentconverter · a mechub project`

Report data, ordering, sections, escaping, print behavior, and export APIs remain unchanged. Branding must not reduce the legibility of monochrome printing or hide meaning behind color alone.

## Asset and Failure Behavior

Brand assets and fonts are local, deterministic build inputs. The implementation must not depend on the branding website or a font CDN at runtime.

- Missing referenced SVG or font files must fail normal build/test validation rather than silently shipping a broken logo.
- CSS font stacks provide readable fallbacks if a browser cannot decode WOFF2.
- Accessible text remains present beside or behind decorative marks so an image failure never removes the product identity.
- The favicon and report SVG markup must not embed scripts or external references.

## Accessibility

- The brand mark receives a concise accessible name when it conveys identity and is hidden from assistive technology when adjacent text already supplies the name.
- Focus indicators use the teal identity token with sufficient contrast in both themes.
- Color-coded states retain text or icons; color is never the only signal.
- Primary body text, secondary text, controls, and model text must meet WCAG AA contrast in both themes.
- Theme switching and operating-system preference behavior remain unchanged.
- `prefers-reduced-motion` behavior is preserved; the application does not add logo animation.

## Testing and Verification

### Automated coverage

Add focused tests that prove:

- The top bar references the canonical M asset and renders the lowercase product lockup and endorsement.
- Browser metadata and favicon use the approved identity.
- Canonical dark-theme tokens and required light-theme accents are present.
- LLM, Juniper, and semantic roles map to their authorized color families.
- Report templates use the official product name, endorsement, and brand roles.
- The removed `/logo.png` reference and legacy visible product titles do not return.

Existing behavioral tests must continue to pass.

### Build verification

Run and require success from:

- Full Vitest suite
- Standard production build
- Standalone/offline build

Inspect the build outputs to confirm all local brand assets and fonts resolve under both deployment forms.

### Rendered verification

Capture and inspect representative application renders in:

- Dark theme at the existing desktop target
- Light theme at the existing desktop target
- A constrained-width desktop/tablet viewport that exercises lockup responsiveness
- At least one populated workflow view containing LLM, Juniper, warning, and success roles

The review checks for broken assets, clipped labels, unexpected wrapping, obscured controls, semantic-color collisions, contrast problems, and regressions in panel density.

### Completion search

Before completion, search authoritative source and build output for:

- `/logo.png`
- Legacy user-facing product titles such as `Firewall Policy to Intent Converter`
- Legacy report footer names
- Core off-brand dark-surface and LLM colors where they still function as brand tokens

Raw colors used for vendor identities, syntax highlighting, charts, or print-specific semantics are reviewed in context rather than mechanically replaced.

## Acceptance Criteria

The rebrand is complete only when all of the following are true:

1. The official M replaces the generic application icon everywhere the application identifies itself.
2. The visible and browser product identity is `firewallintentconverter · a mechub project`, with `intent` marked as model-related plum in visual lockups.
3. Geist and Geist Mono are available offline and applied according to the brand roles.
4. Both themes use the approved identity, surface, text, model, Juniper, and semantic color roles.
5. Shared interactive controls visibly follow the mono-pill design language without breaking dense workflows.
6. LLM/model surfaces use plum exclusively, and Juniper green is not used as a success color.
7. HTML and PDF report presentation uses the same product identity and semantic palette.
8. No application behavior, conversion content, theme persistence, or accessibility interaction regresses.
9. Automated tests, standard build, and standalone build pass.
10. Representative dark, light, constrained-width, and populated renders have been inspected and found free of branding or layout defects.
