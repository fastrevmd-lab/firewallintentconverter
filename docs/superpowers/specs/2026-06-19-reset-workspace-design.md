# Reset Workspace — Design Spec

**Date:** 2026-06-19
**Status:** Approved (pending implementation plan)

## Goal

Add a visible **Reset** button to the TopBar that clears all in-memory firewall
working data while preserving every localStorage-backed preference, letting the
user start a fresh conversion without reloading the page. Before resetting, the
user is warned to save first (with a one-click Save shortcut) so they don't lose
unsaved work.

## User Story

> As a user who just finished one conversion, I want to wipe the current config,
> output, warnings, and undo history and start over — without losing my theme,
> LLM settings/keys, application-mapping overrides, or layout — and without
> reloading the page.

## Scope

### In scope
- A standalone Reset icon button in the TopBar right cluster.
- A confirmation modal warning about unsaved data, with Cancel / Save now /
  Continue-without-saving.
- A coordinated `resetWorkspace()` operation that clears the working-data
  contexts and transient UI state.
- New `RESET` reducer cases for the Conversion and Merge contexts.

### Out of scope
- Clearing or migrating any localStorage value.
- Changing the Save or Load flows (Reset only hands off to the existing save
  flow).
- Undo of a reset (a reset is intentionally non-undoable, consistent with
  load-project).

## Definitions

**Working data (always cleared on reset):**
- `ConfigContext` — parsed/normalized config, edits, warnings, selections,
  section acceptance (full reset to `initialState`).
- `ConversionContext` — SRX output, convert warnings, summary, validation
  findings (full reset to `initialState`).
- `MergeContext` — merge mode, config slots, cross-LS links (full reset to
  `initialState`).
- `UndoContext` — undo/redo stack (`CLEAR`).
- Transient UI fields — active tab, selected rule, errors, loading flags,
  open working modals, translation/grouping flags.

**Settings / preferences (always preserved — choice B):**
Everything stored in `localStorage` is untouched:
- Theme.
- `llm-risk-acceptance` (LLM mode).
- LLM settings / API keys.
- Application-mapping overrides.
- Sidebar widths + collapse state, right-panel width + collapse state.
- `tour-completed`.

Because preserved settings are localStorage-backed (or read from localStorage on
init), the UI reset is **field-targeted**, not a full `initialState` swap — this
keeps `llmRiskAcceptance` and layout widths intact.

## Design

### 1. TopBar button

File: `public/components/layout/TopBar.jsx`

- New standalone icon button using the existing `settings-btn` class, placed at
  the **left edge of the right action cluster**, separated from Save by a thin
  vertical divider: `[↻ Reset] | [Save] [Load] [⋮]`.
- Glyph: refresh / circular-arrow SVG (stroke `currentColor`, matching the Save
  and Load icons).
- Styling: neutral by default with an **orange `--caution`** hover/accent. This
  is an app-driven destructive action (not LLM-driven), so per the project color
  convention it must **never** use violet.
- `title="Reset workspace"`.
- `onClick` → `uiDispatch({ type: 'SHOW_MODAL', name: 'resetConfirm' })`.

### 2. Confirmation modal

Files: `public/contexts/UIContext.jsx` (modal wiring), `public/app.jsx` (render).

- Add `showResetConfirm` to UIContext `initialState` and register
  `resetConfirm → showResetConfirm` in `MODAL_KEYS` so the existing
  `SHOW_MODAL` / `HIDE_MODAL` actions work unchanged.
- Render the modal **inline in `app.jsx`**, mirroring the existing
  `showLoadConfirm` block (same `modal-overlay` / `modal-content` /
  `modal-header` / `modal-body` / `modal-footer` structure). Not a lazy
  component — it matches the load-confirm precedent.
- Copy: a warning that resetting will permanently clear the current config,
  output, warnings, and undo history, that settings/preferences are kept, and
  that the user should save first if they want to keep this work. Use
  `var(--warning)` for the at-risk emphasis line.
- Footer buttons (left→right):
  - **Cancel** (`btn btn-secondary`) → `HIDE_MODAL resetConfirm`.
  - **Save now** (`btn btn-secondary` or accent) → `HIDE_MODAL resetConfirm`
    then `SHOW_MODAL saveModal` (hands off to the existing save flow; the user
    can re-trigger Reset afterward).
  - **Continue without saving** (`btn btn-primary`, caution-styled) →
    `project.resetWorkspace()` then `HIDE_MODAL resetConfirm`.

### 3. Reset logic — `resetWorkspace()` in `useProject`

File: `public/hooks/useProject.js`

Add a `resetWorkspace` callback that mirrors `applyLoadedProject`'s multi-context
coordination. The hook must also consume `UndoContext` (currently it wires
Config, UI, Conversion, Merge — add the Undo dispatch).

Dispatch sequence:
- `configDispatch({ type: 'RESET' })` — existing case → `initialState`.
- `conversionDispatch({ type: 'RESET' })` — **new case** → `initialState`.
- `mergeDispatch({ type: 'RESET' })` — **new case** → `initialState`.
- `undoDispatch({ type: 'CLEAR' })` — existing case.
- UI transient resets (reuse the "Reset transient UI state" block pattern from
  `applyLoadedProject`):
  - `editTab → 'import'` (return to the import screen).
  - `platformView → 'panos'` (default).
  - `bottomTab → 'output'` (default).
  - `selectedRule → null`.
  - `CLEAR_ERROR`.
  - `SET_LOADING isLoading:false`.
  - Hide working modals (modelSelector, interfaceMapper, llmWarning, etc.).
  - Clear translation/grouping flags if set.
  - Do **not** touch `llmRiskAcceptance`, layout widths/collapse, or
    `llmWarningDismissed` settings-derived values.

Expose `resetWorkspace` from the hook's return object so `app.jsx` can call it
via the `project` object already in scope.

### 4. New reducer cases

- `public/contexts/ConversionContext.jsx`:
  `case 'RESET': return { ...initialState };`
- `public/contexts/MergeContext.jsx`:
  `case 'RESET': return { ...initialState };`

Both placed alongside the existing `LOAD_PROJECT` / `CLEAR_OUTPUT` cases.

## Data Flow

```
Reset button click
  -> SHOW_MODAL resetConfirm
     -> Cancel:                 HIDE_MODAL resetConfirm                (no-op)
     -> Save now:               HIDE_MODAL resetConfirm; SHOW_MODAL saveModal
     -> Continue without saving:
            resetWorkspace():
              configDispatch    RESET
              conversionDispatch RESET
              mergeDispatch      RESET
              undoDispatch       CLEAR
              uiDispatch         (field-targeted transient resets)
            HIDE_MODAL resetConfirm
  -> App is back on the import screen, fully usable, settings intact.
```

## Error Handling / Edge Cases

- **Nothing to reset:** Reset is always available (cheap, idempotent). If there's
  no working data, reset simply re-applies initial states — harmless. No need to
  disable the button.
- **Save now path:** Reset is *not* performed automatically after save. The user
  saves, then chooses to reset again if they still want to. This avoids assuming
  intent and keeps each action explicit.
- **localStorage untouched:** No `localStorage.removeItem` calls anywhere in the
  reset path — this is the guarantee that settings survive.

## Testing

- After reset: `intermediateConfig`, `configText`, `srxOutput`,
  `convertWarnings`, undo stack are all empty/initial; `editTab === 'import'`.
- After reset: theme, `llm-risk-acceptance`, app-mapping overrides, and sidebar
  widths are unchanged (read back from localStorage / UI state).
- Save-now button opens the save modal and does not clear data.
- Cancel leaves all state untouched.
- App remains interactive (can parse a new config) without a page reload.

## Files Touched

- `public/components/layout/TopBar.jsx` — Reset button + divider.
- `public/app.jsx` — inline reset-confirm modal.
- `public/contexts/UIContext.jsx` — `showResetConfirm` + `MODAL_KEYS` entry.
- `public/contexts/ConversionContext.jsx` — `RESET` case.
- `public/contexts/MergeContext.jsx` — `RESET` case.
- `public/hooks/useProject.js` — `resetWorkspace()` + UndoContext wiring.
