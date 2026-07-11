/**
 * PushModal — 4-step workflow for pushing SRX config to a live device.
 *
 * Steps: Select Device → Load & Diff → Commit Check → Commit
 * Uses the usePush hook for all state and bridge API calls.
 */
import React, { useState, useEffect, useCallback } from 'react';
import usePush from '../hooks/usePush.js';
import { useUIContext } from '../contexts/UIContext.jsx';

// ---------------------------------------------------------------------------
// Step definitions
// ---------------------------------------------------------------------------
const STEPS = [
  { key: 'select', label: 'Select Device', number: 1 },
  { key: 'diff',   label: 'Load & Diff',   number: 2 },
  { key: 'check',  label: 'Commit Check',  number: 3 },
  { key: 'commit', label: 'Commit',        number: 4 },
];

const STEP_ORDER = ['select', 'diff', 'check', 'commit', 'done'];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function PushModal({ onClose }) {
  const push = usePush();
  const { dispatch: uiDispatch } = useUIContext();
  const [logExpanded, setLogExpanded] = useState(false);
  const [commitMode, setCommitMode] = useState('immediate');
  const [confirmMinutes, setConfirmMinutes] = useState(10);
  const [commitComment, setCommitComment] = useState('Pushed via Firewall Intent Converter');
  const [timerDisplay, setTimerDisplay] = useState('');

  const {
    bridgeUrl, bridgeConnected, devices,
    selectedDevice, setSelectedDevice,
    pushStep, setPushStep,
    pushLog, configDiff, commitCheckResult, commitResult,
    confirmTimer, isWorking,
    testConnection, loadConfig, fetchDiff, commitCheck,
    commitConfig, confirmCommit, rollback, resetPush, appendLog,
    hasSrxOutput, outputFormat,
  } = push;

  // Auto-connect on mount if bridge URL is set
  useEffect(() => {
    if (bridgeUrl && !bridgeConnected) {
      testConnection(bridgeUrl);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Confirm timer countdown display
  useEffect(() => {
    if (!confirmTimer?.active) {
      setTimerDisplay('');
      return;
    }
    const update = () => {
      const remaining = Math.max(0, confirmTimer.expiresAt - Date.now());
      const mins = Math.floor(remaining / 60000);
      const secs = Math.floor((remaining % 60000) / 1000);
      setTimerDisplay(`${mins}:${secs.toString().padStart(2, '0')}`);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [confirmTimer?.active, confirmTimer?.expiresAt]);

  // -----------------------------------------------------------------------
  // Step navigation
  // -----------------------------------------------------------------------
  const currentStepIndex = STEP_ORDER.indexOf(pushStep);

  const goToStep = useCallback((step) => {
    setPushStep(step);
  }, [setPushStep]);

  // -----------------------------------------------------------------------
  // Step 2: Load & Diff (auto-trigger)
  // -----------------------------------------------------------------------
  const handleLoadAndDiff = useCallback(async () => {
    goToStep('diff');
    appendLog('info', `Preparing ${outputFormat === 'xml' ? 'XML' : 'set-command'} configuration push...`);
    const loaded = await loadConfig();
    if (loaded) {
      await fetchDiff();
    } else {
      goToStep('select');
    }
  }, [goToStep, appendLog, outputFormat, selectedDevice, loadConfig, fetchDiff]);

  // -----------------------------------------------------------------------
  // Step 3: Commit Check (auto-trigger)
  // -----------------------------------------------------------------------
  const handleCommitCheck = useCallback(async () => {
    goToStep('check');
    await commitCheck();
  }, [goToStep, commitCheck]);

  // -----------------------------------------------------------------------
  // Step 4: Commit
  // -----------------------------------------------------------------------
  const handleCommit = useCallback(async () => {
    await commitConfig(selectedDevice, {
      comment: commitComment,
      confirm_minutes: commitMode === 'confirm' ? confirmMinutes : 0,
    });
  }, [commitConfig, selectedDevice, commitComment, commitMode, confirmMinutes]);

  const handleConfirm = useCallback(async () => {
    const ok = await confirmCommit();
    if (ok) goToStep('done');
  }, [confirmCommit, goToStep]);

  const handleRollback = useCallback(async () => {
    await rollback();
    goToStep('select');
  }, [rollback, goToStep]);

  const handleClose = useCallback(() => {
    if (confirmTimer?.active) {
      if (!window.confirm('A commit-confirm timer is active. If you close this modal, the device will auto-rollback when the timer expires. Close anyway?')) {
        return;
      }
    }
    resetPush();
    onClose();
  }, [confirmTimer, resetPush, onClose]);

  // -----------------------------------------------------------------------
  // Render: Step Indicator
  // -----------------------------------------------------------------------
  const renderStepper = () => (
    <div className="push-stepper">
      {STEPS.map((step, i) => {
        const isCompleted = currentStepIndex > i || pushStep === 'done';
        const isActive = step.key === pushStep;
        const cls = isCompleted ? 'push-step completed' : isActive ? 'push-step active' : 'push-step';
        return (
          <React.Fragment key={step.key}>
            {i > 0 && <div className={`push-step-line${currentStepIndex > i ? ' completed' : ''}`} />}
            <div className={cls}>
              <span className="push-step-number">{isCompleted ? '\u2713' : step.number}</span>
              <span className="push-step-label">{step.label}</span>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );

  // -----------------------------------------------------------------------
  // Render: Step 1 — Select Device
  // -----------------------------------------------------------------------
  const renderSelectStep = () => {
    if (!bridgeConnected) {
      return (
        <div style={{ padding: 20, textAlign: 'center' }}>
          <p style={{ fontWeight: 600, marginBottom: 8 }}>PyEZ Bridge Not Connected</p>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
            Start the PyEZ Bridge service and configure it in Settings.
          </p>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
            <button className="btn btn-secondary btn-sm" onClick={() => {
              handleClose();
              uiDispatch({ type: 'SHOW_MODAL', name: 'settings', value: 'mcp' });
            }}>
              Open Settings
            </button>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 16, textAlign: 'left', background: 'var(--bg-tertiary)', padding: 12, borderRadius: 'var(--radius)' }}>
            <p style={{ fontWeight: 600, marginBottom: 4 }}>Quick Start:</p>
            <code style={{ fontSize: 10, display: 'block', lineHeight: 1.8 }}>
              cd tools/pyez-bridge<br />
              pip install -r requirements.txt<br />
              python app.py
            </code>
          </div>
        </div>
      );
    }

    return (
      <div style={{ padding: '16px 20px' }}>
        {/* Device list */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>Select Target Device</div>
          {devices.length === 0 ? (
            <div style={{ padding: 16, textAlign: 'center', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius)', fontSize: 12, color: 'var(--text-muted)' }}>
              No devices configured. Add devices in Settings &gt; SRX Device Connection.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {devices.map((dev, i) => (
                <div
                  key={i}
                  className={`push-device-card${selectedDevice === dev.name ? ' selected' : ''}`}
                  onClick={() => setSelectedDevice(dev.name)}
                >
                  <span style={{
                    width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                    background: dev.status === 'connected' ? 'var(--success)' : 'var(--error)',
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{dev.hostname || dev.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {dev.model && `${dev.model} `}
                      {dev.version && `v${dev.version} `}
                      {dev.host && <span style={{ fontFamily: 'var(--font-mono)' }}>{dev.host}</span>}
                    </div>
                  </div>
                  {dev.status !== 'connected' && (
                    <span style={{ fontSize: 10, color: 'var(--error)', fontWeight: 500 }}>Unreachable</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Config preview */}
        {hasSrxOutput && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
              Config Preview
              <span style={{
                fontSize: 10, padding: '1px 6px', borderRadius: 3,
                background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)',
                fontWeight: 500, textTransform: 'uppercase',
              }}>
                {outputFormat === 'xml' ? 'XML' : 'SET'}
              </span>
            </div>
            <pre className="push-config-preview">
              {push.getConfigText().split('\n').slice(0, 20).join('\n')}
              {push.getConfigText().split('\n').length > 20 && `\n... (${push.getConfigText().split('\n').length} total lines)`}
            </pre>
          </div>
        )}
      </div>
    );
  };

  // -----------------------------------------------------------------------
  // Render: Step 2 — Diff
  // -----------------------------------------------------------------------
  const renderDiffStep = () => (
    <div style={{ padding: '16px 20px' }}>
      {isWorking ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40, gap: 8, color: 'var(--text-muted)' }}>
          <span className="spinner" /> Loading configuration and fetching diff...
        </div>
      ) : configDiff ? (
        <>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
            Configuration Diff (candidate vs active)
          </div>
          <pre className="push-diff">
            {configDiff.split('\n').map((line, i) => {
              let cls = '';
              if (line.startsWith('+')) cls = 'diff-add';
              else if (line.startsWith('-')) cls = 'diff-del';
              else if (line.startsWith('@')) cls = 'diff-hdr';
              return <span key={i} className={cls}>{line}{'\n'}</span>;
            })}
          </pre>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
            {(configDiff.match(/^\+/gm) || []).length} additions, {(configDiff.match(/^-/gm) || []).length} removals
          </div>
        </>
      ) : (
        <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
          No changes — candidate matches active configuration.
        </div>
      )}
    </div>
  );

  // -----------------------------------------------------------------------
  // Render: Step 3 — Commit Check
  // -----------------------------------------------------------------------
  const renderCheckStep = () => (
    <div style={{ padding: '16px 20px' }}>
      {isWorking ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40, gap: 8, color: 'var(--text-muted)' }}>
          <span className="spinner" /> Running commit check...
        </div>
      ) : commitCheckResult ? (
        commitCheckResult.ok ? (
          <div style={{ padding: 24, textAlign: 'center' }}>
            <div style={{ fontSize: 32, color: 'var(--success)', marginBottom: 8 }}>{'\u2713'}</div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--success)' }}>Commit Check Passed</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
              Configuration is valid and ready to commit.
            </div>
          </div>
        ) : (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <span style={{ fontSize: 24, color: 'var(--error)' }}>{'\u2717'}</span>
              <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--error)' }}>Commit Check Failed</span>
            </div>
            <div style={{
              padding: '8px 12px', background: 'rgba(248, 113, 113, 0.08)',
              border: '1px solid rgba(248, 113, 113, 0.2)', borderRadius: 'var(--radius)',
              fontSize: 12, color: 'var(--text-primary)',
            }}>
              The candidate configuration did not pass the device commit check.
            </div>
          </div>
        )
      ) : null}
    </div>
  );

  // -----------------------------------------------------------------------
  // Render: Step 4 — Commit
  // -----------------------------------------------------------------------
  const renderCommitStep = () => (
    <div style={{ padding: '16px 20px' }}>
      {/* If commit-confirm timer is active */}
      {confirmTimer?.active && (
        <div className="push-commit-timer">
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>Commit Confirm Active</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              Device will auto-rollback if not confirmed before timer expires.
            </div>
          </div>
          <div className="timer-display">{timerDisplay}</div>
        </div>
      )}

      {/* If commit succeeded (non-confirm) */}
      {commitResult?.ok && !confirmTimer?.active && !confirmTimer && (
        <div style={{ padding: 24, textAlign: 'center' }}>
          <div style={{ fontSize: 32, color: 'var(--success)', marginBottom: 8 }}>{'\u2713'}</div>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--success)' }}>Commit Successful</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            The candidate configuration was committed successfully.
          </div>
        </div>
      )}

      {/* If timer expired */}
      {confirmTimer && !confirmTimer.active && (
        <div style={{ padding: 16, textAlign: 'center', background: 'rgba(251, 191, 36, 0.1)', borderRadius: 'var(--radius)', marginBottom: 12 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--warning)' }}>Timer Expired — Auto-Rollback</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
            The device has automatically rolled back the configuration.
          </div>
        </div>
      )}

      {/* Commit options (only if not yet committed) */}
      {!commitResult && (
        <>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12 }}>Commit Options</div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer' }}>
              <input type="radio" name="commitMode" checked={commitMode === 'immediate'} onChange={() => setCommitMode('immediate')} />
              <div>
                <div style={{ fontWeight: 500 }}>Commit</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Immediately apply — no rollback timer</div>
              </div>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer' }}>
              <input type="radio" name="commitMode" checked={commitMode === 'confirm'} onChange={() => setCommitMode('confirm')} />
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <div>
                  <div style={{ fontWeight: 500 }}>Commit Confirm</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Auto-rollback if not confirmed within timeout</div>
                </div>
                {commitMode === 'confirm' && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <input
                      type="number" min={1} max={60} value={confirmMinutes}
                      onChange={e => setConfirmMinutes(Math.max(1, Math.min(60, parseInt(e.target.value) || 10)))}
                      style={{ width: 50, padding: '2px 6px', background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', color: 'var(--text-primary)', fontSize: 12, textAlign: 'center' }}
                    />
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>min</span>
                  </div>
                )}
              </div>
            </label>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Commit Comment</label>
            <input
              type="text" value={commitComment}
              onChange={e => setCommitComment(e.target.value)}
              style={{ width: '100%', padding: '6px 10px', background: 'var(--bg-tertiary)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', color: 'var(--text-primary)', fontSize: 12 }}
            />
          </div>
        </>
      )}
    </div>
  );

  // -----------------------------------------------------------------------
  // Render: Push Log (collapsible)
  // -----------------------------------------------------------------------
  const renderLog = () => pushLog.length > 0 && (
    <div style={{ padding: '0 20px 12px' }}>
      <button
        onClick={() => setLogExpanded(!logExpanded)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 11, color: 'var(--text-muted)', padding: 0, display: 'flex', alignItems: 'center', gap: 4 }}
      >
        <span style={{ transform: logExpanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s', display: 'inline-block' }}>{'\u25B6'}</span>
        Log ({pushLog.length})
      </button>
      {logExpanded && (
        <div className="push-log">
          {pushLog.map((entry, i) => (
            <div key={i} className="push-log-entry">
              <span className="push-log-time">{entry.time}</span>
              <span className={`push-log-level ${entry.level}`}>{entry.level}</span>
              <span>{entry.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  // -----------------------------------------------------------------------
  // Render: Footer buttons
  // -----------------------------------------------------------------------
  const renderFooter = () => {
    const buttons = [];

    // Back button
    if (pushStep === 'diff' || pushStep === 'check') {
      buttons.push(
        <button key="back" className="btn btn-secondary" onClick={() => goToStep(pushStep === 'diff' ? 'select' : 'diff')} disabled={isWorking}>
          Back
        </button>
      );
    }

    // Rollback (available in diff/check/commit steps)
    if (['diff', 'check', 'commit'].includes(pushStep) && !commitResult?.ok) {
      buttons.push(
        <button key="rollback" className="btn btn-secondary" onClick={handleRollback} disabled={isWorking} style={{ color: 'var(--warning)' }}>
          Rollback
        </button>
      );
    }

    // Spacer
    buttons.push(<div key="spacer" style={{ flex: 1 }} />);

    // Step-specific action buttons
    if (pushStep === 'select') {
      buttons.push(
        <button key="next" className="btn btn-primary" onClick={handleLoadAndDiff} disabled={!selectedDevice || !hasSrxOutput || isWorking}>
          {isWorking ? 'Loading...' : 'Next: Load & Diff'}
        </button>
      );
    } else if (pushStep === 'diff') {
      buttons.push(
        <button key="next" className="btn btn-primary" onClick={handleCommitCheck} disabled={isWorking}>
          {isWorking ? 'Checking...' : 'Next: Commit Check'}
        </button>
      );
    } else if (pushStep === 'check') {
      buttons.push(
        <button key="next" className="btn btn-primary" onClick={() => goToStep('commit')} disabled={!commitCheckResult?.ok || isWorking}>
          Next: Commit
        </button>
      );
    } else if (pushStep === 'commit') {
      if (confirmTimer?.active) {
        buttons.push(
          <button key="confirm" className="btn btn-primary" onClick={handleConfirm} disabled={isWorking}>
            Confirm Commit
          </button>
        );
        buttons.push(
          <button key="timer-rollback" className="btn btn-secondary" onClick={handleRollback} disabled={isWorking} style={{ color: 'var(--error)' }}>
            Rollback Now
          </button>
        );
      } else if (commitResult?.ok) {
        buttons.push(
          <button key="done" className="btn btn-primary" onClick={handleClose}>
            Done
          </button>
        );
      } else if (!commitResult) {
        buttons.push(
          <button key="commit" className="btn btn-primary" onClick={handleCommit} disabled={isWorking}>
            {isWorking ? 'Committing...' : commitMode === 'confirm' ? `Commit (${confirmMinutes}m timer)` : 'Commit'}
          </button>
        );
      }
    } else if (pushStep === 'done') {
      buttons.push(
        <button key="done" className="btn btn-primary" onClick={handleClose}>
          Done
        </button>
      );
    }

    return (
      <div className="modal-footer" style={{ gap: 8, display: 'flex' }}>
        {buttons}
      </div>
    );
  };

  // -----------------------------------------------------------------------
  // Main render
  // -----------------------------------------------------------------------
  return (
    <div className="modal-overlay" onClick={handleClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{ width: 620, maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}>
        <div className="modal-header">
          <h2>Push to SRX</h2>
          <button className="modal-close" onClick={handleClose}>x</button>
        </div>

        {renderStepper()}

        <div style={{ flex: 1, overflow: 'auto' }}>
          {pushStep === 'select' && renderSelectStep()}
          {pushStep === 'diff' && renderDiffStep()}
          {pushStep === 'check' && renderCheckStep()}
          {pushStep === 'commit' && renderCommitStep()}
          {pushStep === 'done' && (
            <div style={{ padding: 24, textAlign: 'center' }}>
              <div style={{ fontSize: 32, color: 'var(--success)', marginBottom: 8 }}>{'\u2713'}</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--success)' }}>Push Complete</div>
            </div>
          )}
          {renderLog()}
        </div>

        {renderFooter()}
      </div>
    </div>
  );
}
