import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useUIContext } from '../../contexts/UIContext.jsx';
import { useConfigContext } from '../../contexts/ConfigContext.jsx';

/* ── Static commands ─────────────────────────────────────────────── */
const STATIC_COMMANDS = [
  { id: 'nav-import',    label: 'Go to: Import',               category: 'Navigation', shortcut: 'Ctrl+1' },
  { id: 'nav-policies',  label: 'Go to: Policies',             category: 'Navigation', shortcut: 'Ctrl+2' },
  { id: 'nav-nat',       label: 'Go to: NAT Rules',            category: 'Navigation' },
  { id: 'nav-zones',     label: 'Go to: Zones',                category: 'Navigation' },
  { id: 'nav-objects',   label: 'Go to: Objects',              category: 'Navigation', shortcut: 'Ctrl+3' },
  { id: 'nav-routing',   label: 'Go to: Interfaces / Routing', category: 'Navigation' },
  { id: 'nav-vpn',       label: 'Go to: VPN',                  category: 'Navigation' },
  { id: 'nav-output',    label: 'Go to: SRX Output',           category: 'Navigation', shortcut: 'Ctrl+4' },
  { id: 'nav-warnings',  label: 'Go to: Warnings',             category: 'Navigation' },
  { id: 'nav-diff',      label: 'Go to: Diff View',            category: 'Navigation' },
  { id: 'parse',         label: 'Parse Configuration',         category: 'Actions',    shortcut: 'Ctrl+Enter' },
  { id: 'convert',       label: 'Convert to SRX',              category: 'Actions',    shortcut: 'Ctrl+Shift+C' },
  { id: 'translate-llm', label: 'Translate with LLM',          category: 'Actions',    shortcut: 'Ctrl+Shift+T' },
  { id: 'save-project',  label: 'Save Project',                category: 'Actions',    shortcut: 'Ctrl+S' },
  { id: 'load-project',  label: 'Open Project',                category: 'Actions',    shortcut: 'Ctrl+O' },
  { id: 'toggle-sidebar',   label: 'Toggle Sidebar',           category: 'View',       shortcut: 'Ctrl+B' },
  { id: 'toggle-inspector', label: 'Toggle Inspector',         category: 'View',       shortcut: 'Ctrl+Shift+B' },
  { id: 'undo',          label: 'Undo',                        category: 'Edit',       shortcut: 'Ctrl+Z' },
  { id: 'redo',          label: 'Redo',                        category: 'Edit',       shortcut: 'Ctrl+Shift+Z' },
  { id: 'settings',      label: 'Open Settings',               category: 'Actions' },
  { id: 'report',        label: 'Generate Report',             category: 'Actions' },
];

/* ── Tab mapping for navigation commands ─────────────────────────── */
const NAV_TAB_MAP = {
  'nav-import':   'import',
  'nav-policies': 'rules',
  'nav-nat':      'nat',
  'nav-zones':    'zones',
  'nav-objects':  'objects',
  'nav-routing':  'routing',
  'nav-vpn':      'vpn',
  'nav-output':   'output',
  'nav-warnings': 'warnings',
  'nav-diff':     'diff',
};

/* ── Category icon ───────────────────────────────────────────────── */
function CategoryIcon({ category }) {
  const paths = {
    Navigation: <polyline points="9 18 15 12 9 6" />,
    Actions:    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />,
    View:       <><rect x="3" y="3" width="18" height="18" rx="2" /><line x1="9" y1="3" x2="9" y2="21" /></>,
    Edit:       <><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" /><path d="M18.5 2.5a2.12 2.12 0 013 3L12 15l-4 1 1-4 9.5-9.5z" /></>,
  };
  return (
    <svg className="result-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {paths[category] || <circle cx="12" cy="12" r="3" />}
    </svg>
  );
}

/**
 * CommandPalette — Ctrl+P command palette overlay.
 */
export default function CommandPalette() {
  const { state: ui, dispatch: uiDispatch } = useUIContext();
  const { state: cfg } = useConfigContext();

  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);
  const resultsRef = useRef(null);

  // Build dynamic commands from config (zones, address objects)
  const dynamicCommands = useMemo(() => {
    const cmds = [];
    const ic = cfg.intermediateConfig;
    if (!ic) return cmds;

    // Add zone navigation shortcuts
    if (ic.zones?.length) {
      ic.zones.forEach(z => {
        cmds.push({
          id: `zone-${z.name || z}`,
          label: `Zone: ${z.name || z}`,
          category: 'Objects',
        });
      });
    }
    return cmds;
  }, [cfg.intermediateConfig]);

  const allCommands = useMemo(
    () => [...STATIC_COMMANDS, ...dynamicCommands],
    [dynamicCommands]
  );

  // Fuzzy filter: simple case-insensitive substring match
  const filtered = useMemo(() => {
    if (!query.trim()) return allCommands;
    const q = query.toLowerCase();
    return allCommands.filter(c => c.label.toLowerCase().includes(q));
  }, [query, allCommands]);

  // Clamp selected index
  useEffect(() => {
    if (selectedIndex >= filtered.length) {
      setSelectedIndex(Math.max(0, filtered.length - 1));
    }
  }, [filtered.length, selectedIndex]);

  // Autofocus input
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Scroll selected item into view
  useEffect(() => {
    if (resultsRef.current) {
      const el = resultsRef.current.children[selectedIndex];
      if (el) el.scrollIntoView({ block: 'nearest' });
    }
  }, [selectedIndex]);

  // Execute command
  const execute = useCallback((cmd) => {
    // Close palette
    uiDispatch({ type: 'SET_FIELD', field: 'commandPaletteOpen', value: false });

    // Navigation commands
    if (NAV_TAB_MAP[cmd.id]) {
      uiDispatch({ type: 'SET_FIELD', field: 'editTab', value: NAV_TAB_MAP[cmd.id] });
      return;
    }

    // Action commands
    switch (cmd.id) {
      case 'toggle-sidebar':
        uiDispatch({ type: 'TOGGLE_SIDEBAR' });
        break;
      case 'toggle-inspector':
        uiDispatch({ type: 'TOGGLE_INSPECTOR' });
        break;
      case 'settings':
        uiDispatch({ type: 'SHOW_MODAL', name: 'settings' });
        break;
      case 'report':
        uiDispatch({ type: 'SHOW_MODAL', name: 'reportModal' });
        break;
      case 'save-project':
        uiDispatch({ type: 'SHOW_MODAL', name: 'saveModal' });
        break;
      // Other actions (parse, convert, translate-llm, undo, redo, load-project)
      // are keyboard-driven from the main app — the palette serves as discovery.
      default:
        break;
    }
  }, [uiDispatch]);

  // Keyboard navigation
  const handleKeyDown = useCallback((e) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex(i => Math.min(i + 1, filtered.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex(i => Math.max(i - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (filtered[selectedIndex]) execute(filtered[selectedIndex]);
        break;
      case 'Escape':
        e.preventDefault();
        uiDispatch({ type: 'SET_FIELD', field: 'commandPaletteOpen', value: false });
        break;
      default:
        break;
    }
  }, [filtered, selectedIndex, execute, uiDispatch]);

  // Close on overlay click
  const handleOverlayClick = useCallback((e) => {
    if (e.target === e.currentTarget) {
      uiDispatch({ type: 'SET_FIELD', field: 'commandPaletteOpen', value: false });
    }
  }, [uiDispatch]);

  return (
    <div className="command-palette-overlay" onClick={handleOverlayClick}>
      <div className="command-palette">
        <input
          ref={inputRef}
          className="command-palette-input"
          type="text"
          placeholder="Type a command..."
          value={query}
          onChange={(e) => { setQuery(e.target.value); setSelectedIndex(0); }}
          onKeyDown={handleKeyDown}
        />
        <div className="command-palette-results" ref={resultsRef}>
          {filtered.length === 0 ? (
            <div className="command-palette-empty">No matching commands</div>
          ) : (
            filtered.map((cmd, i) => (
              <div
                key={cmd.id}
                className={`command-result${i === selectedIndex ? ' selected' : ''}`}
                onClick={() => execute(cmd)}
                onMouseEnter={() => setSelectedIndex(i)}
              >
                <CategoryIcon category={cmd.category} />
                <span className="result-label">{cmd.label}</span>
                {cmd.shortcut && <span className="result-shortcut">{cmd.shortcut}</span>}
                <span className="result-category">{cmd.category}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
