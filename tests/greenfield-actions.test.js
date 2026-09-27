/**
 * Greenfield chat proposals must land as LLM output awaiting human review,
 * never pre-accepted. A policy that `applyGreenfieldAction` marks 'accepted'
 * would skip every per-rule accept gate (export confirm, section acceptance,
 * push) that only recognizes 'accepted' vs 'llm_reviewed'/'unreviewed'.
 */

import { describe, it, expect } from 'vitest';
import { applyGreenfieldAction } from '../public/utils/greenfield-actions.js';
import { computeTriageCounts } from '../public/utils/triage.js';

const emptyConfig = {
  metadata: { zone_count: 0, rule_count: 0, nat_rule_count: 0, object_count: 0, vpn_tunnel_count: 0, static_route_count: 0 },
  zones: [{ name: 'trust' }, { name: 'untrust' }],
  security_policies: [], nat_rules: [], address_objects: [], address_groups: [],
  service_objects: [], static_routes: [], screen_config: [], syslog_config: [],
  system_config: {},
};

describe('applyGreenfieldAction — add_policy', () => {
  it('marks the LLM-proposed policy llm_reviewed, not accepted', () => {
    const updated = applyGreenfieldAction(emptyConfig, 'add_policy', {
      name: 'allow-web', action: 'permit',
      src_zones: ['trust'], dst_zones: ['untrust'],
    });

    expect(updated.security_policies).toHaveLength(1);
    expect(updated.security_policies[0]._review_status).toBe('llm_reviewed');
    expect(updated.security_policies[0]._review_status).not.toBe('accepted');
  });

  it('never produces _review_status: "accepted" for any add_policy input', () => {
    const samples = [
      {},
      { name: 'x' },
      { name: 'x', action: 'deny' },
      { name: 'x', action: 'permit', log_start: true, log_end: false },
    ];
    for (const data of samples) {
      const updated = applyGreenfieldAction(emptyConfig, 'add_policy', data);
      const rule = updated.security_policies[updated.security_policies.length - 1];
      expect(rule._review_status).not.toBe('accepted');
    }
  });

  it('keeps the proposed policy out of the accepted count used by the export/push gate', () => {
    const updated = applyGreenfieldAction(emptyConfig, 'add_policy', {
      name: 'allow-web', action: 'permit',
      src_zones: ['trust'], dst_zones: ['untrust'],
    });

    // Mirrors the check useConversion.handleConvertClick and useSectionAcceptance
    // use to decide whether export/push may proceed without a warning/block.
    const counts = computeTriageCounts(updated.security_policies, updated);
    expect(counts.accepted).toBe(0);

    const allAccepted = updated.security_policies.length > 0
      && updated.security_policies.every(r => r._review_status === 'accepted');
    expect(allAccepted).toBe(false);
  });

  it('only becomes accepted through the explicit human accept action, not by re-running the LLM action', () => {
    const proposed = applyGreenfieldAction(emptyConfig, 'add_policy', { name: 'allow-web', action: 'permit' });
    const rule = proposed.security_policies[0];
    expect(rule._review_status).toBe('llm_reviewed');

    // Simulate the human "Accept Policy" click (layout/RightPanel.jsx handleAcceptRule).
    const accepted = { ...rule, _review_status: 'accepted' };
    expect(accepted._review_status).toBe('accepted');

    // Re-running the same LLM proposal must not itself flip the rule to accepted.
    const reProposed = applyGreenfieldAction(emptyConfig, 'add_policy', { name: 'allow-web', action: 'permit' });
    expect(reProposed.security_policies[0]._review_status).not.toBe('accepted');
  });
});

describe('applyGreenfieldAction — non-policy actions are untouched by review status', () => {
  it('add_zone does not introduce a review status', () => {
    const updated = applyGreenfieldAction(emptyConfig, 'add_zone', { name: 'dmz' });
    expect(updated.zones.at(-1)).not.toHaveProperty('_review_status');
  });
});
