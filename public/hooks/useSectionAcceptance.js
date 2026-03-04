/**
 * useSectionAcceptance — Derives acceptance state for all nav sections.
 *
 * Returns { items, hasContent, groups } where:
 * - items: per nav-item acceptance boolean
 * - hasContent: always true for all reviewable sections in SRX view
 *   (even empty sections show teal so users can navigate, add content, and accept)
 * - groups: parent rollup (green only when ALL children are accepted)
 *
 * Only active when platformView === 'srx'. Returns neutral state otherwise.
 */
import { useMemo } from 'react';
import { useConfigContext } from '../contexts/ConfigContext.jsx';
import { useUIContext } from '../contexts/UIContext.jsx';

const EMPTY = { items: {}, hasContent: {}, groups: {} };

// All reviewable section IDs (excludes analysis which is a tool, not a section)
const REVIEWABLE_SECTIONS = [
  'rules', 'nat', 'zones', 'screen', 'decryption', 'pbf',
  'objects', 'routing', 'vpn', 'dhcp', 'flow-monitoring',
  'ha', 'qos', 'syslog',
];

// Object sub-tab keys for per-tab acceptance
const OBJECT_SUB_TABS = [
  'obj:addresses', 'obj:groups', 'obj:services',
  'obj:applications', 'obj:profiles', 'obj:schedules',
];

export default function useSectionAcceptance() {
  const { state: cfg } = useConfigContext();
  const { state: ui } = useUIContext();

  const { intermediateConfig, sectionAcceptance, srxTranslatedPolicies } = cfg;
  const { platformView } = ui;

  return useMemo(() => {
    if (platformView !== 'srx' || !intermediateConfig) return EMPTY;

    const items = {};
    const hasContent = {};

    // All reviewable sections are always "has content" in SRX view
    // so they show teal and the user can navigate, add items, and accept
    for (const id of REVIEWABLE_SECTIONS) {
      hasContent[id] = true;
      items[id] = !!sectionAcceptance[id];
    }

    // --- Policies: special — derived from _review_status on each rule ---
    const policies = srxTranslatedPolicies || intermediateConfig.security_policies || [];
    items.rules = policies.length > 0 && policies.every(p => p._review_status === 'accepted');

    // --- Objects: derived from per-sub-tab compound keys ---
    items.objects = OBJECT_SUB_TABS.every(k => sectionAcceptance[k] === true);

    // --- Screen: per-zone compound keys override simple acceptance ---
    const screenConfig = intermediateConfig.screen_config || [];
    if (screenConfig.length > 0) {
      items.screen = screenConfig.every(s =>
        sectionAcceptance[`screen:${s.zone}`] === true
      );
    }
    // If no screens, the simple sectionAcceptance.screen check from above applies

    // Analysis is not an acceptance target
    items.analysis = false;
    hasContent.analysis = false;

    // --- Parent group rollup (ALL children must be accepted) ---
    const groups = {};

    const securityChildren = ['rules', 'nat', 'zones', 'screen', 'decryption', 'pbf'];
    groups.security = securityChildren.every(id => items[id]);

    groups.objects = !!items.objects;

    const networkChildren = ['routing', 'vpn', 'dhcp', 'flow-monitoring'];
    groups.network = networkChildren.every(id => items[id]);

    const systemChildren = ['ha', 'qos', 'syslog'];
    groups.system = systemChildren.every(id => items[id]);

    // Parent groups always have content in SRX view (for teal coloring)
    groups._securityHasContent = true;
    groups._objectsHasContent = true;
    groups._networkHasContent = true;
    groups._systemHasContent = true;

    return { items, hasContent, groups };
  }, [platformView, intermediateConfig, sectionAcceptance, srxTranslatedPolicies]);
}
