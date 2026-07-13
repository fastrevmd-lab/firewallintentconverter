/**
 * Application entry point.
 * Mounts the React app inside all context providers.
 */
import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource-variable/geist/wght.css';
import '@fontsource-variable/geist-mono/wght.css';
import App from './app.jsx';
import { ConfigProvider } from './contexts/ConfigContext.jsx';
import { UIProvider } from './contexts/UIContext.jsx';
import { ConversionProvider } from './contexts/ConversionContext.jsx';
import { MergeProvider } from './contexts/MergeContext.jsx';
import { UndoProvider } from './contexts/UndoContext.jsx';
import './styles/main.css';
import './styles/layout.css';
import './styles/nav-tree.css';
import './styles/command-palette.css';
import './styles/status-bar.css';
import './styles/brand.css';

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
