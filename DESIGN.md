# Design System

Reference for the Firewall Intent Converter UI. Dark professional theme targeting 1920x1080 and 1440x900 viewports.

---

## Color Palette

### Core Backgrounds

| Variable | Value | Use |
|----------|-------|-----|
| `--bg-primary` | `#1a1d23` | App background |
| `--bg-secondary` | `#22262e` | Panels, sidebars, topbar |
| `--bg-tertiary` | `#2a2f38` | Status bar, sub-headers |
| `--bg-elevated` | `#31363f` | Cards, active items |
| `--bg-hover` | `#383e48` | Hover states |

### Accent

| Variable | Value | Use |
|----------|-------|-----|
| `--accent` | `#4dd0c8` | Primary teal accent |
| `--accent-dim` | `#005b5a` | Hover/pressed accent |
| `--accent-text` | `#005b5a` | Accent on dark text |
| `--accent-glow` | `rgba(77,208,200,0.15)` | Glow/focus rings |

### Text

| Variable | Value | Use |
|----------|-------|-----|
| `--text-primary` | `#e8eaed` | Body text |
| `--text-secondary` | `#9aa0a6` | Labels, descriptions |
| `--text-muted` | `#6b7280` | Captions, disabled |

### Semantic

| Variable | Value | Use |
|----------|-------|-----|
| `--success` | `#34d399` | Success states |
| `--warning` | `#fbbf24` | Warnings |
| `--error` | `#f87171` | Errors, destructive |
| `--info` | `#60a5fa` | Informational |

### LLM Mode

| Variable | Value | Use |
|----------|-------|-----|
| `--llm-cloud` | `#f59e0b` | Cloud LLM features (orange) |
| `--llm-local` | `#84cc16` | Local LLM features (lime) |

### App Analysis / Caution

| Variable | Value | Use |
|----------|-------|-----|
| `--caution` | `#a78bfa` | App-driven analysis, warnings (violet) |
| `--juniper-green` | `#90C641` | SRX model branding |

### Status Badges

| Variable | Value | Maps to |
|----------|-------|---------|
| `--status-clean` | `#34d399` | `--success` |
| `--status-warning` | `#fbbf24` | `--warning` |
| `--status-unsupported` | `#f87171` | `--error` |
| `--status-interview` | `#a78bfa` | `--caution` |

### Layout Tokens

| Variable | Value |
|----------|-------|
| `--header-height` | `52px` |
| `--border-color` | `#3a3f48` |
| `--radius` | `6px` |
| `--radius-lg` | `10px` |

---

## Color Conventions (STRICT)

These rules prevent visual confusion between LLM-driven and app-driven features.

| Color | CSS Variable | Allowed Use | Forbidden Use |
|-------|-------------|-------------|---------------|
| Orange | `--llm-cloud` | LLM/cloud features ONLY (cloud LLM buttons, AI actions) | App-driven analysis, warnings, topology |
| Violet | `--caution` | App-driven analysis, warnings, app-generated highlights | LLM features |
| Lime | `--llm-local` | Local LLM features | App-driven features |
| Green | `--juniper-green` | SRX model branding, target platform labels | Semantic status (use `--success` instead) |
| Teal | `--accent` | General UI accent, links, focus rings | Semantic warnings |

---

## Typography

**Families:**

| Variable | Stack | Use |
|----------|-------|-----|
| `--font-sans` | `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif` | Body text |
| `--font-mono` | `JetBrains Mono, Fira Code, Cascadia Code, Consolas, monospace` | Code, config output |

**Size scale (from CSS):**

| Context | Size |
|---------|------|
| Base body | `14px` |
| Modal heading | `16px` |
| Empty state heading | `14px` |
| Nav items | `13px` |
| Buttons | `13px` |
| `.btn-sm` | `12px` |
| Nav group headers, sidebar titles | `12px` |
| Status bar, inspector header, tooltips | `11px` |
| Status labels, nav badges | `10px` |

**Line height:** `1.5` (base), `1.6` (empty state body)

---

## Spacing & Layout

**Base grid:** 4px increments. Common values: `4px`, `8px`, `12px`, `16px`, `20px`, `40px`.

**Border radius:** `--radius: 6px` (buttons, inputs), `--radius-lg: 10px` (modals, cards).

### 4-Panel IDE Shell

```
+----------------------------------------------------------+
| .app-topbar                              height: 52px     |
+----------+----------------------------+------------------+
| .app-    | .app-center               | .app-inspector   |
| sidebar  |  .center-toolbar (40px)   |  .inspector-     |
| 260px    |  .center-content          |   header         |
| (48-400) |  (flex: 1)               |  .inspector-     |
|          |                           |   body           |
|          |                           |  320px (0-500)   |
+----------+----------------------------+------------------+
| .app-statusbar                           height: 28px     |
+----------------------------------------------------------+
```

- **Sidebar** collapses to `48px` (icons only)
- **Inspector** collapses to a `24px` clickable strip
- **Resize handles** are `4px` wide, highlight with `--accent` on hover
- Responsive: sidebar `220px` at `<1280px`, `300px` at `>2560px`

---

## Component Patterns

### Buttons

| Class | Style |
|-------|-------|
| `.btn` | Base: `padding: 8px 16px`, `font-size: 13px`, `border-radius: var(--radius)` |
| `.btn-primary` | `background: var(--accent)`, `color: var(--bg-primary)` |
| `.btn-secondary` | `background: var(--bg-elevated)`, `border: 1px solid var(--border-color)` |
| `.btn-sm` | `padding: 5px 12px`, `font-size: 12px`, `min-height: 30px` |
| `.btn-block` | `width: 100%`, `margin-top: 12px` |
| `.btn-icon` | Icon-only button |
| `.btn-accept` | Green success action (`--success` with 10% alpha bg) |

Disabled state: `opacity: 0.5; cursor: not-allowed`.

### Empty States

```html
<div class="empty-state">
  <svg width="48" height="48" opacity="0.3">...</svg>
  <h3>Title</h3>
  <p>Description (max-width: 280px)</p>
</div>
```

Centered flex column, `padding: 40px 20px`, `gap: 12px`, `color: var(--text-muted)`.

### Modals

```html
<div class="modal-overlay">       <!-- fixed, backdrop-filter: blur(2px) -->
  <div class="modal-content">     <!-- bg-secondary, radius-lg, max-height: 85vh -->
    <div class="modal-header">    <!-- padding: 16px 20px -->
      <h2>Title</h2>
      <button class="modal-close">&times;</button>
    </div>
    <div class="modal-body">...</div>
    <div class="modal-footer">...</div>
  </div>
</div>
```

### Nav Tree

Collapsible groups with badges in `.app-sidebar`:

- `.nav-group` > `.nav-group-header` (12px uppercase) + `.nav-group-items`
- `.nav-item` has `border-left: 2px solid transparent`, becomes `--accent` when `.active`
- `.nav-badge` pill: `font-size: 10px`, `border-radius: 10px`, auto-margin-left
- `.nav-badge.warn` uses `--caution` color
- Review workflow: `.nav-review-pending` (teal), `.nav-review-done` (juniper-green)

### Status Labels

```html
<span class="status-label status-accepted">Accepted</span>
```

| Modifier | Color | Background |
|----------|-------|------------|
| `.status-disabled` | `--error` | `rgba(248,113,113,0.15)` |
| `.status-unreviewed` | `--text-muted` | `rgba(107,114,128,0.15)` |
| `.status-llm_reviewed` | `--accent` | `rgba(96,165,250,0.15)` |
| `.status-accepted` | `--success` | `rgba(52,211,153,0.15)` |

Base: `font-size: 10px`, `font-weight: 600`, `text-transform: uppercase`, `border-radius: 3px`.

### Tooltips (CSS-only)

```html
<span data-tooltip="Help text" data-tooltip-pos="top">Hover me</span>
```

Positions: `top` (default), `bottom`, `left`, `right`. Styled with `--bg-elevated` background, `--border-color` border, `box-shadow`.

---

## Accessibility

### Focus Visible

All interactive elements use `:focus-visible` with `outline: 2px solid var(--accent); outline-offset: 2px`. Applied to:
`.btn`, `.btn-primary`, `.btn-secondary`, `.btn-sm`, `.sub-tab-btn`, `.modal-close`, `.btn-icon`, `.btn-accept`.

### Reduced Motion

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

### Touch Targets

- `.sidebar-toggle`: `min-width: 32px; min-height: 32px`
- `.btn-sm`: `min-height: 30px`
- Nav items and group headers have `padding: 6px 12px` minimum hit areas
