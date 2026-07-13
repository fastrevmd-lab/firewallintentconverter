/**
 * Standalone entry point.
 *
 * Forces deterministic (no-AI) mode so LLM features are disabled at the
 * React level, then mounts the standard App with all context providers.
 * This avoids modifying any existing component code.
 */
import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource-variable/geist/wght.css';
import '@fontsource-variable/geist-mono/wght.css';
import App from '../public/app.jsx';
import { ConfigProvider } from '../public/contexts/ConfigContext.jsx';
import { UIProvider } from '../public/contexts/UIContext.jsx';
import { ConversionProvider } from '../public/contexts/ConversionContext.jsx';
import { MergeProvider } from '../public/contexts/MergeContext.jsx';
import { UndoProvider } from '../public/contexts/UndoContext.jsx';
import '../public/styles/main.css';
import '../public/styles/layout.css';
import '../public/styles/nav-tree.css';
import '../public/styles/command-palette.css';
import '../public/styles/status-bar.css';
import './standalone-overrides.css';
import '../public/styles/brand.css';

// Force deterministic mode — bypasses LLM disclaimer and disables all AI
// features via the existing isDeterministicMode() gates in the app.
localStorage.setItem('llm-risk-acceptance', 'deterministic');

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ConfigProvider>
      <UIProvider>
        <ConversionProvider>
          <MergeProvider>
            <UndoProvider>
              <App />
            </UndoProvider>
          </MergeProvider>
        </ConversionProvider>
      </UIProvider>
    </ConfigProvider>
  </React.StrictMode>
);
