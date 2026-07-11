/**
 * usePush — Push-to-SRX workflow hook
 *
 * Manages connection to the PyEZ Bridge service, device selection,
 * config loading, diff, commit check, commit (with optional confirm),
 * and rollback operations.
 *
 * Reads srxOutput + outputFormat from ConversionContext.
 * Reads sanitizationTable from ConfigContext for IP restoration.
 */
import { useState, useCallback, useRef, useEffect } from 'react';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import {
  bridgeFetch,
  bridgeResponseError,
  loadBridgeSettings,
  saveBridgeSettings,
} from '../utils/bridge-client.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Restore sanitized placeholders with original values for export. */
function restoreForExport(text, sanitizationTable) {
  if (!sanitizationTable || sanitizationTable.length === 0) return text;
  let result = text;
  for (const entry of sanitizationTable) {
    if (entry.restore) {
      result = result.replaceAll(entry.placeholder, entry.original);
    }
  }
  return result;
}

async function readBridgeJson(response) {
  if ([401, 403, 429].includes(response.status)) {
    throw await bridgeResponseError(response);
  }
  return response.json();
}

/** Format timestamp for log entries. */
function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
export default function usePush() {
  const { state: convState } = useConversionContext();
  const { state: configState } = useConfigContext();

  const { srxOutput, outputFormat } = convState;
  const { sanitizationTable } = configState;

  // Connection state
  const [bridgeUrl, setBridgeUrl] = useState(() => loadBridgeSettings().url);
  const [bridgeConnected, setBridgeConnected] = useState(false);
  const [devices, setDevices] = useState([]);

  // Push workflow state
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [pushStep, setPushStep] = useState('select'); // select | diff | check | commit | done | error
  const [pushLog, setPushLog] = useState([]);
  const [configDiff, setConfigDiff] = useState('');
  const [commitCheckResult, setCommitCheckResult] = useState(null);
  const [commitResult, setCommitResult] = useState(null);
  const [confirmTimer, setConfirmTimer] = useState(null);
  const [isWorking, setIsWorking] = useState(false);

  // Confirm countdown interval ref
  const confirmIntervalRef = useRef(null);

  // Cleanup interval on unmount
  useEffect(() => {
    return () => {
      if (confirmIntervalRef.current) clearInterval(confirmIntervalRef.current);
    };
  }, []);

  // -----------------------------------------------------------------------
  // Logging
  // -----------------------------------------------------------------------
  const appendLog = useCallback((level, message) => {
    setPushLog(prev => [...prev, { time: timestamp(), level, message }]);
  }, []);

  // -----------------------------------------------------------------------
  // Base URL helper
  // -----------------------------------------------------------------------
  const baseUrl = useCallback(() => {
    return (bridgeUrl || '').replace(/\/+$/, '');
  }, [bridgeUrl]);

  // -----------------------------------------------------------------------
  // Get config text (with sanitization restore)
  // -----------------------------------------------------------------------
  const getConfigText = useCallback(() => {
    if (!srxOutput) return '';
    let text;
    if (outputFormat === 'xml') {
      text = srxOutput.xml || '';
    } else {
      text = (srxOutput.commands || []).join('\n');
    }
    return restoreForExport(text, sanitizationTable);
  }, [srxOutput, outputFormat, sanitizationTable]);

  // -----------------------------------------------------------------------
  // Connection
  // -----------------------------------------------------------------------
  const testConnection = useCallback(async (url) => {
    const base = (url || bridgeUrl || '').replace(/\/+$/, '');
    if (!base) return false;
    try {
      const healthResponse = await bridgeFetch(
        base + '/health',
        {},
        { authenticated: false },
      );
      if (!healthResponse.ok) {
        throw await bridgeResponseError(healthResponse);
      }

      const deviceResponse = await bridgeFetch(base + '/devices');
      if (!deviceResponse.ok) throw await bridgeResponseError(deviceResponse);
      const data = await deviceResponse.json();
      setDevices(Array.isArray(data) ? data : data.devices || []);
      setBridgeConnected(true);
      appendLog('success', 'Connected to authenticated PyEZ Bridge.');

      // Background probe for live status (may take seconds per device)
      bridgeFetch(
        base + '/devices?probe=true',
        {},
        { timeout: 60000 },
      ).then(async (response) => {
        if (response.ok) {
          const probed = await response.json();
          setDevices(Array.isArray(probed) ? probed : probed.devices || []);
        }
      }).catch(() => {});
      return true;
    } catch (err) {
      setBridgeConnected(false);
      appendLog('error', `Connection failed: ${err.message}`);
      return false;
    }
  }, [bridgeUrl, appendLog]);

  const saveSettings = useCallback((url) => {
    const saved = saveBridgeSettings({
      url,
      token: loadBridgeSettings().token,
    });
    setBridgeUrl(saved.url);
  }, []);

  // -----------------------------------------------------------------------
  // Device management
  // -----------------------------------------------------------------------
  const refreshDevices = useCallback(async () => {
    try {
      const resp = await bridgeFetch(baseUrl() + '/devices');
      const data = await readBridgeJson(resp);
      if (resp.ok) {
        setDevices(Array.isArray(data) ? data : data.devices || []);
      }
    } catch (err) {
      appendLog('error', `Failed to refresh devices: ${err.message}`);
    }
  }, [baseUrl, appendLog]);

  const addDevice = useCallback(async (deviceInfo) => {
    try {
      const resp = await bridgeFetch(baseUrl() + '/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(deviceInfo),
      });
      const data = await readBridgeJson(resp);
      if (data.ok) {
        appendLog('success', `Device '${deviceInfo.name}' added.`);
        await refreshDevices();
        return true;
      }
      appendLog('error', data.error || 'Failed to add device.');
      return false;
    } catch (err) {
      appendLog('error', `Failed to add device: ${err.message}`);
      return false;
    }
  }, [baseUrl, appendLog, refreshDevices]);

  const removeDevice = useCallback(async (deviceName) => {
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(deviceName)}`, {
        method: 'DELETE',
      });
      const data = await readBridgeJson(resp);
      if (data.ok) {
        appendLog('info', `Device '${deviceName}' removed.`);
        await refreshDevices();
        if (selectedDevice === deviceName) setSelectedDevice(null);
        return true;
      }
      appendLog('error', data.error || 'Failed to remove device.');
      return false;
    } catch (err) {
      appendLog('error', `Failed to remove device: ${err.message}`);
      return false;
    }
  }, [baseUrl, appendLog, refreshDevices, selectedDevice]);

  // -----------------------------------------------------------------------
  // Push workflow
  // -----------------------------------------------------------------------

  /** Try to clear a stale config lock via the bridge unlock endpoint. */
  const unlockConfig = useCallback(async (deviceName) => {
    const name = deviceName || selectedDevice;
    if (!name) return false;
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/unlock`, {
        method: 'POST',
      });
      const data = await readBridgeJson(resp);
      return data.ok;
    } catch { return false; }
  }, [selectedDevice, baseUrl]);

  const loadConfig = useCallback(async (deviceName, _retried) => {
    const name = deviceName || selectedDevice;
    if (!name) return false;
    setIsWorking(true);
    appendLog('info', `Loading configuration to ${name}...`);
    try {
      let configText = getConfigText();
      if (!configText) {
        appendLog('error', 'No SRX output to push.');
        setIsWorking(false);
        return false;
      }

      const fmt = outputFormat === 'xml' ? 'xml' : 'set';
      // For set format, strip comment lines and blanks — NETCONF rejects non-command lines
      if (fmt === 'set') {
        const lines = configText.split('\n').filter(l => {
          const trimmed = l.trim();
          return trimmed && !trimmed.startsWith('#');
        });
        configText = lines.join('\n');
        appendLog('info', `Sending ${lines.length} set commands (comments stripped).`);
      }
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/load`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: configText, format: fmt }),
      });
      const data = await readBridgeJson(resp);
      if (data.ok) {
        appendLog('success', data.message || 'Configuration loaded into candidate.');
        // Show skipped lines as warnings
        if (data.warnings && data.warnings.length > 0) {
          appendLog('warn', `${data.skipped} command(s) skipped due to errors:`);
          for (const w of data.warnings.slice(0, 20)) {
            appendLog('warn', `  Line ${w.line}: ${w.command}`);
            if (w.message) appendLog('warn', `    → ${w.message}`);
          }
          if (data.warnings.length > 20) {
            appendLog('warn', `  ... and ${data.warnings.length - 20} more`);
          }
        }
        setIsWorking(false);
        return true;
      }

      // Lock error (HTTP 409) — auto-unlock and retry once
      if (resp.status === 409 && !_retried) {
        appendLog('warn', 'Config lock held by another session — clearing lock and retrying...');
        await unlockConfig(name);
        return loadConfig(name, true);
      }

      appendLog('error', `Load failed: ${data.error}`);
      if (data.details) {
        if (Array.isArray(data.details)) {
          for (const err of data.details) {
            const cmd = err.command ? `: ${err.command}` : '';
            appendLog('error', `  ${err.message || err}${cmd}`);
          }
        } else {
          appendLog('error', String(data.details).slice(0, 500));
        }
      }
      setIsWorking(false);
      return false;
    } catch (err) {
      appendLog('error', `Load failed: ${err.message}`);
      setIsWorking(false);
      return false;
    }
  }, [selectedDevice, getConfigText, outputFormat, baseUrl, appendLog, unlockConfig]);

  const fetchDiff = useCallback(async (deviceName) => {
    const name = deviceName || selectedDevice;
    if (!name) return '';
    setIsWorking(true);
    appendLog('info', 'Fetching configuration diff...');
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/diff`);
      const data = await readBridgeJson(resp);
      if (data.ok) {
        setConfigDiff(data.diff || '');
        if (!data.diff) {
          appendLog('info', 'No changes — candidate matches active config.');
        } else {
          const adds = (data.diff.match(/^\+/gm) || []).length;
          const dels = (data.diff.match(/^-/gm) || []).length;
          appendLog('success', `Diff retrieved: ${adds} additions, ${dels} removals.`);
        }
        setIsWorking(false);
        return data.diff || '';
      }
      appendLog('error', data.error || 'Failed to get diff.');
      setIsWorking(false);
      return '';
    } catch (err) {
      appendLog('error', `Diff failed: ${err.message}`);
      setIsWorking(false);
      return '';
    }
  }, [selectedDevice, baseUrl, appendLog]);

  const commitCheck = useCallback(async (deviceName) => {
    const name = deviceName || selectedDevice;
    if (!name) return null;
    setIsWorking(true);
    appendLog('info', 'Running commit check (dry run)...');
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/commit-check`, {
        method: 'POST',
      });
      const data = await readBridgeJson(resp);
      setCommitCheckResult(data);
      if (data.ok) {
        appendLog('success', 'Commit check passed.');
      } else {
        appendLog('error', 'Commit check failed.');
        if (data.errors) {
          for (const err of data.errors) {
            appendLog('error', `  ${err.message}`);
          }
        }
      }
      setIsWorking(false);
      return data;
    } catch (err) {
      const result = { ok: false, errors: [{ message: err.message, severity: 'error' }] };
      setCommitCheckResult(result);
      appendLog('error', `Commit check failed: ${err.message}`);
      setIsWorking(false);
      return result;
    }
  }, [selectedDevice, baseUrl, appendLog]);

  const commitConfig = useCallback(async (deviceName, options = {}) => {
    const name = deviceName || selectedDevice;
    if (!name) return null;
    setIsWorking(true);
    const confirmMin = options.confirm_minutes || 0;
    appendLog('info', confirmMin
      ? `Committing with ${confirmMin}-minute confirm timer...`
      : 'Committing configuration...');
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/commit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          comment: options.comment || 'Pushed via Firewall Intent Converter',
          confirm_minutes: confirmMin || undefined,
        }),
      });
      const data = await readBridgeJson(resp);
      setCommitResult(data);

      if (data.ok) {
        appendLog('success', data.message);
        if (data.confirm_active && confirmMin > 0) {
          // Start countdown timer
          const expiresAt = Date.now() + confirmMin * 60 * 1000;
          setConfirmTimer({ active: true, minutes: confirmMin, expiresAt });
          // Update timer every second
          if (confirmIntervalRef.current) clearInterval(confirmIntervalRef.current);
          confirmIntervalRef.current = setInterval(() => {
            const remaining = Math.max(0, expiresAt - Date.now());
            if (remaining <= 0) {
              clearInterval(confirmIntervalRef.current);
              confirmIntervalRef.current = null;
              setConfirmTimer(prev => prev ? { ...prev, active: false } : null);
              appendLog('warn', 'Confirm timer expired — device will auto-rollback.');
            }
          }, 1000);
        }
      } else {
        appendLog('error', data.error || 'Commit failed.');
      }
      setIsWorking(false);
      return data;
    } catch (err) {
      const result = { ok: false, error: err.message };
      setCommitResult(result);
      appendLog('error', `Commit failed: ${err.message}`);
      setIsWorking(false);
      return result;
    }
  }, [selectedDevice, baseUrl, appendLog]);

  const confirmCommit = useCallback(async (deviceName) => {
    const name = deviceName || selectedDevice;
    if (!name) return false;
    setIsWorking(true);
    appendLog('info', 'Confirming commit...');
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/confirm`, {
        method: 'POST',
      });
      const data = await readBridgeJson(resp);
      if (data.ok) {
        appendLog('success', 'Commit confirmed. Auto-rollback cancelled.');
        if (confirmIntervalRef.current) {
          clearInterval(confirmIntervalRef.current);
          confirmIntervalRef.current = null;
        }
        setConfirmTimer(null);
        setIsWorking(false);
        return true;
      }
      appendLog('error', data.error || 'Confirm failed.');
      setIsWorking(false);
      return false;
    } catch (err) {
      appendLog('error', `Confirm failed: ${err.message}`);
      setIsWorking(false);
      return false;
    }
  }, [selectedDevice, baseUrl, appendLog]);

  const rollback = useCallback(async (deviceName) => {
    const name = deviceName || selectedDevice;
    if (!name) return false;
    setIsWorking(true);
    appendLog('info', 'Rolling back configuration...');
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 0 }),
      });
      const data = await readBridgeJson(resp);
      if (data.ok) {
        appendLog('success', 'Configuration rolled back successfully.');
        if (confirmIntervalRef.current) {
          clearInterval(confirmIntervalRef.current);
          confirmIntervalRef.current = null;
        }
        setConfirmTimer(null);
        setIsWorking(false);
        return true;
      }
      appendLog('error', data.error || 'Rollback failed.');
      setIsWorking(false);
      return false;
    } catch (err) {
      appendLog('error', `Rollback failed: ${err.message}`);
      setIsWorking(false);
      return false;
    }
  }, [selectedDevice, baseUrl, appendLog]);

  // -----------------------------------------------------------------------
  // Reset
  // -----------------------------------------------------------------------
  const resetPush = useCallback(() => {
    setSelectedDevice(null);
    setPushStep('select');
    setPushLog([]);
    setConfigDiff('');
    setCommitCheckResult(null);
    setCommitResult(null);
    if (confirmIntervalRef.current) {
      clearInterval(confirmIntervalRef.current);
      confirmIntervalRef.current = null;
    }
    setConfirmTimer(null);
    setIsWorking(false);
  }, []);

  // -----------------------------------------------------------------------
  // Return public API
  // -----------------------------------------------------------------------
  return {
    // Connection
    bridgeUrl,
    bridgeConnected,
    devices,
    testConnection,
    saveSettings,
    refreshDevices,
    addDevice,
    removeDevice,

    // Workflow state
    selectedDevice,
    setSelectedDevice,
    pushStep,
    setPushStep,
    pushLog,
    configDiff,
    commitCheckResult,
    commitResult,
    confirmTimer,
    isWorking,

    // Workflow actions
    unlockConfig,
    loadConfig,
    fetchDiff,
    commitCheck,
    commitConfig,
    confirmCommit,
    rollback,
    resetPush,
    appendLog,

    // Config info
    getConfigText,
    outputFormat,
    hasSrxOutput: !!(srxOutput && (srxOutput.commands?.length || srxOutput.xml)),
  };
}
