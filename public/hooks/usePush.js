/**
 * usePush — Push-to-SRX workflow hook
 *
 * Manages connection to the PyEZ Bridge service, device selection,
 * config loading, diff, commit check, commit (with optional confirm),
 * and rollback operations.
 *
 * Reads canonical srxOutput from ConversionContext.
 * Reads sanitizationTable from ConfigContext for IP restoration.
 */
import { useState, useCallback, useRef, useEffect } from 'react';
import { useConversionContext } from '../contexts/ConversionContext.jsx';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import {
  bridgeErrorMessage,
  bridgeFetch,
  bridgeResponseJson,
  isBridgeResponseStatus,
  loadBridgeSettings,
  safeBridgeLoadWarnings,
  saveBridgeSettings,
} from '../utils/bridge-client.js';
import {
  buildDeviceLoadPayload,
  getConversionOutputPresentation,
} from '../utils/conversion-output-consumer.js';
import { hasConversionOutput } from '../../src/conversion/conversion-output.js';

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

  const { srxOutput } = convState;
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
    const text = getConversionOutputPresentation(srxOutput).text;
    return restoreForExport(text, sanitizationTable);
  }, [srxOutput, sanitizationTable]);

  const hasSrxOutput = hasConversionOutput(srxOutput);
  const outputPresentation = hasSrxOutput
    ? getConversionOutputPresentation(srxOutput)
    : null;

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
      await bridgeResponseJson(healthResponse);

      const deviceResponse = await bridgeFetch(base + '/devices');
      const data = await bridgeResponseJson(deviceResponse);
      setDevices(Array.isArray(data) ? data : data.devices || []);
      setBridgeConnected(true);
      appendLog('success', 'Connected to authenticated PyEZ Bridge.');

      // Background probe for live status (may take seconds per device)
      bridgeFetch(
        base + '/devices?probe=true',
        {},
        { timeout: 60000 },
      ).then(bridgeResponseJson).then((probed) => {
        setDevices(Array.isArray(probed) ? probed : probed.devices || []);
      }).catch(() => {});
      return true;
    } catch (error) {
      setBridgeConnected(false);
      appendLog('error', bridgeErrorMessage(
        error,
        'Connection failed. Check the bridge service and try again.',
      ));
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
      const data = await bridgeResponseJson(resp);
      setDevices(Array.isArray(data) ? data : data.devices || []);
    } catch (error) {
      appendLog('error', bridgeErrorMessage(error, 'Failed to refresh devices.'));
    }
  }, [baseUrl, appendLog]);

  const addDevice = useCallback(async (deviceInfo) => {
    try {
      const resp = await bridgeFetch(baseUrl() + '/devices', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(deviceInfo),
      });
      const data = await bridgeResponseJson(resp);
      if (data.ok) {
        appendLog('success', 'Device added.');
        await refreshDevices();
        return true;
      }
      appendLog('error', 'Failed to add device.');
      return false;
    } catch (error) {
      appendLog('error', bridgeErrorMessage(error, 'Failed to add device.'));
      return false;
    }
  }, [baseUrl, appendLog, refreshDevices]);

  const removeDevice = useCallback(async (deviceName) => {
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(deviceName)}`, {
        method: 'DELETE',
      });
      const data = await bridgeResponseJson(resp);
      if (data.ok) {
        appendLog('info', 'Device removed.');
        await refreshDevices();
        if (selectedDevice === deviceName) setSelectedDevice(null);
        return true;
      }
      appendLog('error', 'Failed to remove device.');
      return false;
    } catch (error) {
      appendLog('error', bridgeErrorMessage(error, 'Failed to remove device.'));
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
      const data = await bridgeResponseJson(resp);
      return data.ok;
    } catch { return false; }
  }, [selectedDevice, baseUrl]);

  const loadConfig = useCallback(async (deviceName, _retried) => {
    const name = deviceName || selectedDevice;
    if (!name) return false;
    setIsWorking(true);
    appendLog('info', 'Loading configuration into the candidate configuration...');
    try {
      const payload = buildDeviceLoadPayload(
        srxOutput,
        text => restoreForExport(text, sanitizationTable),
      );
      if (!payload.config) {
        appendLog('error', 'No SRX output to push.');
        setIsWorking(false);
        return false;
      }

      if (payload.format === 'set') {
        appendLog('info', `Sending ${payload.config.split('\n').length} set commands (comments stripped).`);
      }
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/load`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await bridgeResponseJson(resp);
      if (data.ok) {
        appendLog('success', 'Configuration loaded into candidate.');
        const warnings = safeBridgeLoadWarnings(data.warnings);
        if (warnings.length > 0) {
          appendLog('warn', `${warnings.length} configuration line(s) were skipped:`);
          for (const warning of warnings.slice(0, 20)) {
            appendLog(
              'warn',
              `Line ${warning.line} (${warning.code}): ${warning.category}`,
            );
          }
          if (warnings.length > 20) {
            appendLog('warn', `${warnings.length - 20} additional line warning(s).`);
          }
        }
        setIsWorking(false);
        return true;
      }

      appendLog('error', 'Configuration load failed.');
      setIsWorking(false);
      return false;
    } catch (error) {
      if (isBridgeResponseStatus(error, 409) && !_retried) {
        appendLog('warn', 'Configuration lock detected. Clearing it and retrying once.');
        await unlockConfig(name);
        return loadConfig(name, true);
      }
      appendLog('error', bridgeErrorMessage(error, 'Configuration load failed.'));
      setIsWorking(false);
      return false;
    }
  }, [selectedDevice, srxOutput, sanitizationTable, baseUrl, appendLog, unlockConfig]);

  const fetchDiff = useCallback(async (deviceName) => {
    const name = deviceName || selectedDevice;
    if (!name) return '';
    setIsWorking(true);
    appendLog('info', 'Fetching configuration diff...');
    try {
      const resp = await bridgeFetch(baseUrl() + `/devices/${encodeURIComponent(name)}/diff`);
      const data = await bridgeResponseJson(resp);
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
      appendLog('error', 'Failed to get configuration diff.');
      setIsWorking(false);
      return '';
    } catch (error) {
      appendLog('error', bridgeErrorMessage(error, 'Failed to get configuration diff.'));
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
      const data = await bridgeResponseJson(resp);
      if (data.ok) {
        setCommitCheckResult({ ok: true });
        appendLog('success', 'Commit check passed.');
      } else {
        setCommitCheckResult({ ok: false });
        appendLog('error', 'Commit check failed.');
      }
      setIsWorking(false);
      return data;
    } catch (error) {
      const result = { ok: false };
      setCommitCheckResult(result);
      appendLog('error', bridgeErrorMessage(error, 'Commit check failed.'));
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
          comment: options.comment || 'Pushed via firewallintentconverter · a mechub project',
          confirm_minutes: confirmMin || undefined,
        }),
      });
      const data = await bridgeResponseJson(resp);

      if (data.ok) {
        const confirmActive = data.confirm_active === true && confirmMin > 0;
        setCommitResult({ ok: true, confirm_active: confirmActive });
        appendLog('success', 'Configuration committed successfully.');
        if (confirmActive) {
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
        setCommitResult({ ok: false });
        appendLog('error', 'Commit failed.');
      }
      setIsWorking(false);
      return data;
    } catch (error) {
      const result = { ok: false };
      setCommitResult(result);
      appendLog('error', bridgeErrorMessage(error, 'Commit failed.'));
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
      const data = await bridgeResponseJson(resp);
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
      appendLog('error', 'Commit confirmation failed.');
      setIsWorking(false);
      return false;
    } catch (error) {
      appendLog('error', bridgeErrorMessage(error, 'Commit confirmation failed.'));
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
      const data = await bridgeResponseJson(resp);
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
      appendLog('error', 'Rollback failed.');
      setIsWorking(false);
      return false;
    } catch (error) {
      appendLog('error', bridgeErrorMessage(error, 'Rollback failed.'));
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
    outputFormat: outputPresentation?.format ?? null,
    hasSrxOutput,
  };
}
