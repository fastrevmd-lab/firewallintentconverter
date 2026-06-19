import { describe, it, expect } from 'vitest';
import { computeWorkflowSteps } from '../public/utils/workflow-steps.js';

const base = {
  editTab: 'rules', platformView: 'panos', analysisCount: 0,
  hasTranslated: false, hasOutput: false, llmReviewedCount: 0,
  mergeMode: false, sourceLabel: 'From PA-440', targetLabel: 'to SRX1600',
};
const byId = (steps, id) => steps.find(s => s.id === id);

describe('computeWorkflowSteps', () => {
  it('returns six steps in order with the given labels', () => {
    const steps = computeWorkflowSteps(base);
    expect(steps.map(s => s.id)).toEqual(['source', 'analysis', 'review', 'srx', 'convert', 'day2']);
    expect(byId(steps, 'source').label).toBe('From PA-440');
    expect(byId(steps, 'srx').label).toBe('to SRX1600');
  });

  it('marks source current when on the source rules view', () => {
    const steps = computeWorkflowSteps(base);
    expect(byId(steps, 'source').status).toBe('current');
  });

  it('marks analysis current on the analysis tab and source done', () => {
    const steps = computeWorkflowSteps({ ...base, editTab: 'analysis' });
    expect(byId(steps, 'analysis').status).toBe('current');
    expect(byId(steps, 'source').status).toBe('done');
  });

  it('marks review available once analysis has run', () => {
    const steps = computeWorkflowSteps({ ...base, editTab: 'analysis', analysisCount: 12 });
    expect(byId(steps, 'review').status).toBe('available');
  });

  it('marks review current on the review tab', () => {
    const steps = computeWorkflowSteps({ ...base, editTab: 'review' });
    expect(byId(steps, 'review').status).toBe('current');
    expect(byId(steps, 'review').optional).toBe(true);
    expect(byId(steps, 'review').llm).toBe(true);
  });

  it('marks review done when policies were llm-reviewed', () => {
    const steps = computeWorkflowSteps({ ...base, editTab: 'rules', platformView: 'srx', llmReviewedCount: 3 });
    expect(byId(steps, 'review').status).toBe('done');
  });

  it('marks srx current on the SRX rules view', () => {
    const steps = computeWorkflowSteps({ ...base, platformView: 'srx' });
    expect(byId(steps, 'srx').status).toBe('current');
  });

  it('marks convert + srx done once output exists', () => {
    const steps = computeWorkflowSteps({ ...base, hasOutput: true });
    expect(byId(steps, 'convert').status).toBe('done');
    expect(byId(steps, 'srx').status).toBe('done');
  });

  it('uses the merge label for the convert step', () => {
    const steps = computeWorkflowSteps({ ...base, mergeMode: true });
    expect(byId(steps, 'convert').label).toBe('Merge & Convert');
  });

  it('marks day2 current on the day2ops tab and optional', () => {
    const steps = computeWorkflowSteps({ ...base, editTab: 'day2ops' });
    expect(byId(steps, 'day2').status).toBe('current');
    expect(byId(steps, 'day2').optional).toBe(true);
  });
});
