/**
 * GuidedTour Component
 *
 * Step-by-step walkthrough for first-time users.
 * Highlights key UI elements with a spotlight overlay and positioned tooltips.
 * Persists "don't show again" preference to localStorage.
 */
import React, { useState, useEffect, useCallback } from 'react';

const TOUR_STEPS = [
  {
    target: '[data-tour="config-input"]',
    title: 'Import Your Config',
    content: 'Paste or upload a firewall configuration here. You can also pick a sample config from the dropdown, or start a Greenfield build from scratch.',
    position: 'right',
  },
  {
    target: '[data-tour="parse-btn"]',
    title: 'Parse the Configuration',
    content: 'Click Parse to analyze your config. The tool auto-detects the vendor format and extracts zones, policies, NAT rules, objects, and more.',
    position: 'right',
  },
  {
    target: '[data-tour="center-panel"]',
    title: 'Review & Edit Rules',
    content: 'Your parsed security policies appear here. Use the tabs to switch between Rules, Objects, Zones, NAT, and other sections. Double-click any cell to edit inline.',
    position: 'bottom',
  },
  {
    target: '[data-tour="translate-btn"]',
    title: 'Translate with LLM',
    content: 'Optionally send your ruleset to an LLM (Claude, GPT-4, or a local model) for intelligent translation to optimized SRX policies with best-practice recommendations.',
    position: 'bottom',
  },
  {
    target: '[data-tour="right-panel"]',
    title: 'Rule Details & Accept',
    content: 'Click any rule to see its full details here. Review fields, edit values, and click Accept to mark rules as reviewed. Use the checkboxes in the table for bulk operations.',
    position: 'left',
  },
  {
    target: '[data-tour="output-panel"]',
    title: 'Export SRX Output',
    content: 'Your converted SRX configuration appears here as set commands or XML. Copy to clipboard or download the file. Check the Warnings tab for migration notes.',
    position: 'top',
  },
];

export default function GuidedTour({ onClose }) {
  const [step, setStep] = useState(0);
  const [dontShow, setDontShow] = useState(false);
  const [rect, setRect] = useState(null);

  const currentStep = TOUR_STEPS[step];

  const updateRect = useCallback(() => {
    if (!currentStep) return;
    const el = document.querySelector(currentStep.target);
    if (el) {
      const r = el.getBoundingClientRect();
      setRect({ top: r.top - 4, left: r.left - 4, width: r.width + 8, height: r.height + 8 });
    } else {
      setRect(null);
    }
  }, [currentStep]);

  useEffect(() => {
    updateRect();
    const handleResize = () => updateRect();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [updateRect, step]);

  const handleNext = () => {
    if (step < TOUR_STEPS.length - 1) {
      setStep(step + 1);
    } else {
      handleFinish();
    }
  };

  const handleFinish = () => {
    if (dontShow) {
      localStorage.setItem('tour-completed', 'true');
    }
    onClose();
  };

  const getTooltipStyle = () => {
    if (!rect) {
      return { top: '50%', left: '50%', transform: 'translate(-50%, -50%)' };
    }

    const pos = currentStep.position;
    const style = {};
    const gap = 16;

    if (pos === 'right') {
      style.top = rect.top;
      style.left = rect.left + rect.width + gap;
    } else if (pos === 'left') {
      style.top = rect.top;
      style.left = rect.left - 340 - gap;
    } else if (pos === 'bottom') {
      style.top = rect.top + rect.height + gap;
      style.left = rect.left;
    } else if (pos === 'top') {
      style.top = rect.top - gap;
      style.left = rect.left;
      style.transform = 'translateY(-100%)';
    }

    // Keep tooltip in viewport
    if (style.left < 8) style.left = 8;
    if (style.left + 340 > window.innerWidth - 8) {
      style.left = window.innerWidth - 348;
    }
    if (style.top < 8) style.top = 8;

    return style;
  };

  return (
    <div className="tour-overlay" onClick={handleFinish}>
      {/* Spotlight */}
      {rect && (
        <div
          className="tour-spotlight"
          style={{
            top: rect.top,
            left: rect.left,
            width: rect.width,
            height: rect.height,
          }}
        />
      )}

      {/* Tooltip */}
      <div
        className="tour-tooltip"
        style={getTooltipStyle()}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="tour-tooltip-header">
          <div className="tour-step-indicator">Step {step + 1} of {TOUR_STEPS.length}</div>
          <h3>{currentStep.title}</h3>
        </div>
        <div className="tour-tooltip-content">
          {currentStep.content}
        </div>
        <div className="tour-tooltip-footer">
          <label className="tour-dont-show">
            <input
              type="checkbox"
              checked={dontShow}
              onChange={(e) => setDontShow(e.target.checked)}
            />
            Don't show again
          </label>
          <div className="tour-tooltip-actions">
            <button className="btn btn-sm btn-secondary" onClick={handleFinish}>
              Skip Tour
            </button>
            <button className="btn btn-sm btn-primary" onClick={handleNext}>
              {step < TOUR_STEPS.length - 1 ? 'Next' : 'Finish'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
