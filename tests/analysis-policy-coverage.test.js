/**
 * Tests for Group C: policy correctness & coverage checks (Issue #49)
 */
import { describe, it, expect } from 'vitest';
import { AnalysisEngine } from '../src/analysis/config-analyzer.js';

describe('Group C: Policy Correctness & Coverage Checks', () => {
  // ─── 1. orphan_ref ─────────────────────────────────────────────────────────
  describe('_orphanReferences', () => {
    it('flags policies with undefined address references', () => {
      const config = {
        security_policies: [
          {
            name: 'test-policy',
            _rule_index: 1,
            src_addresses: ['GHOST'],
            dst_addresses: ['any'],
            services: ['any'],
            action: 'allow',
          },
        ],
        address_objects: [],
        address_groups: [],
        service_objects: [],
        service_groups: [],
      };

      const result = AnalysisEngine._orphanReferences(config);
      expect(result.id).toBe('orphan_ref');
      expect(result.count).toBe(1);
      expect(result.items.length).toBe(1);
      expect(result.items[0].label).toContain('GHOST');
    });

    it('flags policies with undefined service references', () => {
      const config = {
        security_policies: [
          {
            name: 'test-policy',
            _rule_index: 1,
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['GHOST_SVC'],
            action: 'allow',
          },
        ],
        address_objects: [],
        address_groups: [],
        service_objects: [],
        service_groups: [],
      };

      const result = AnalysisEngine._orphanReferences(config);
      expect(result.id).toBe('orphan_ref');
      expect(result.count).toBe(1);
      expect(result.items.length).toBe(1);
      expect(result.items[0].label).toContain('GHOST_SVC');
    });

    it('returns zero when all references are defined', () => {
      const config = {
        security_policies: [
          {
            name: 'test-policy',
            _rule_index: 1,
            src_addresses: ['ADDR1'],
            dst_addresses: ['any'],
            services: ['SVC1'],
            action: 'allow',
          },
        ],
        address_objects: [{ name: 'ADDR1', value: '10.0.0.1' }],
        address_groups: [],
        service_objects: [{ name: 'SVC1', protocol: 'tcp', port_range: '443' }],
        service_groups: [],
      };

      const result = AnalysisEngine._orphanReferences(config);
      expect(result.id).toBe('orphan_ref');
      expect(result.count).toBe(0);
      expect(result.items.length).toBe(0);
    });

    it('ignores implicit policies', () => {
      const config = {
        security_policies: [
          {
            name: 'implicit-deny',
            _rule_index: 0,
            _implicit: true,
            src_addresses: ['GHOST'],
            dst_addresses: ['any'],
            services: ['any'],
            action: 'deny',
          },
          {
            name: 'real-policy',
            _rule_index: 1,
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            action: 'allow',
          },
        ],
        address_objects: [],
        address_groups: [],
        service_objects: [],
        service_groups: [],
      };

      const result = AnalysisEngine._orphanReferences(config);
      expect(result.count).toBe(0);
    });
  });

  // ─── 2. no_deny_all ────────────────────────────────────────────────────────
  describe('_noDenyAll', () => {
    it('returns count 0 when a logged deny any-any exists', () => {
      const config = {
        security_policies: [
          {
            name: 'allow-traffic',
            _rule_index: 1,
            action: 'allow',
            src_addresses: ['10.0.0.0/8'],
            dst_addresses: ['any'],
            services: ['any'],
          },
          {
            name: 'deny-all',
            _rule_index: 2,
            action: 'deny',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            log_start: true,
          },
        ],
      };

      const result = AnalysisEngine._noDenyAll(config);
      expect(result.id).toBe('no_deny_all');
      expect(result.count).toBe(0);
    });

    it('returns count 1 when no logged deny any-any exists', () => {
      const config = {
        security_policies: [
          {
            name: 'allow-traffic',
            _rule_index: 1,
            action: 'allow',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
          },
        ],
      };

      const result = AnalysisEngine._noDenyAll(config);
      expect(result.id).toBe('no_deny_all');
      expect(result.count).toBe(1);
      expect(result.items.length).toBe(1);
    });

    it('ignores implicit policies when checking for deny-all', () => {
      const config = {
        security_policies: [
          {
            name: 'implicit-deny',
            _rule_index: 0,
            _implicit: true,
            action: 'deny',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            log_start: true,
          },
          {
            name: 'allow-traffic',
            _rule_index: 1,
            action: 'allow',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
          },
        ],
      };

      const result = AnalysisEngine._noDenyAll(config);
      expect(result.count).toBe(1);
    });

    it('ignores deny-all without logging', () => {
      const config = {
        security_policies: [
          {
            name: 'deny-all-nolog',
            _rule_index: 1,
            action: 'deny',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
          },
        ],
      };

      const result = AnalysisEngine._noDenyAll(config);
      expect(result.count).toBe(1);
    });

    it('accepts log_end as logging', () => {
      const config = {
        security_policies: [
          {
            name: 'deny-all',
            _rule_index: 1,
            action: 'deny',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            log_end: true,
          },
        ],
      };

      const result = AnalysisEngine._noDenyAll(config);
      expect(result.count).toBe(0);
    });

    it('accepts reject/drop/reset-* as deny-family actions', () => {
      const config = {
        security_policies: [
          {
            name: 'reject-all',
            _rule_index: 1,
            action: 'reject',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            log_start: true,
          },
        ],
      };

      const result = AnalysisEngine._noDenyAll(config);
      expect(result.count).toBe(0);
    });
  });

  // ─── 3. redundant_rule ─────────────────────────────────────────────────────
  describe('_redundantRules', () => {
    it('flags identical enabled rules', () => {
      const config = {
        security_policies: [
          {
            name: 'rule-1',
            _rule_index: 1,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.1'],
            dst_addresses: ['any'],
            services: ['tcp/443'],
            applications: [],
          },
          {
            name: 'rule-2',
            _rule_index: 2,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.1'],
            dst_addresses: ['any'],
            services: ['tcp/443'],
            applications: [],
          },
        ],
      };

      const result = AnalysisEngine._redundantRules(config);
      expect(result.id).toBe('redundant_rule');
      expect(result.count).toBe(1);
      expect(result.items[0].label).toContain('#2');
      expect(result.items[0].label).toContain('#1');
    });

    it('returns zero when rules differ', () => {
      const config = {
        security_policies: [
          {
            name: 'rule-1',
            _rule_index: 1,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.1'],
            dst_addresses: ['any'],
            services: ['tcp/443'],
            applications: [],
          },
          {
            name: 'rule-2',
            _rule_index: 2,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.2'],
            dst_addresses: ['any'],
            services: ['tcp/443'],
            applications: [],
          },
        ],
      };

      const result = AnalysisEngine._redundantRules(config);
      expect(result.count).toBe(0);
    });

    it('ignores disabled policies', () => {
      const config = {
        security_policies: [
          {
            name: 'rule-1',
            _rule_index: 1,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.1'],
            dst_addresses: ['any'],
            services: ['tcp/443'],
            applications: [],
          },
          {
            name: 'rule-2',
            _rule_index: 2,
            disabled: true,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['untrust'],
            src_addresses: ['10.0.0.1'],
            dst_addresses: ['any'],
            services: ['tcp/443'],
            applications: [],
          },
        ],
      };

      const result = AnalysisEngine._redundantRules(config);
      expect(result.count).toBe(0);
    });

    it('ignores implicit policies', () => {
      const config = {
        security_policies: [
          {
            name: 'rule-1',
            _rule_index: 1,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            applications: [],
          },
          {
            name: 'intra-zone',
            _rule_index: 2,
            _implicit: true,
            action: 'allow',
            src_zones: ['trust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            applications: [],
          },
        ],
      };

      const result = AnalysisEngine._redundantRules(config);
      expect(result.count).toBe(0);
    });
  });

  // ─── 4. empty_policyset ────────────────────────────────────────────────────
  describe('_emptyPolicySet', () => {
    it('flags config with only implicit policies', () => {
      const config = {
        security_policies: [
          {
            name: 'implicit-deny',
            _rule_index: 0,
            _implicit: true,
            action: 'deny',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
          },
        ],
      };

      const result = AnalysisEngine._emptyPolicySet(config);
      expect(result.id).toBe('empty_policyset');
      expect(result.count).toBe(1);
      expect(result.items.length).toBe(1);
    });

    it('flags config with no policies', () => {
      const config = {
        security_policies: [],
      };

      const result = AnalysisEngine._emptyPolicySet(config);
      expect(result.count).toBe(1);
    });

    it('returns zero when real policies exist', () => {
      const config = {
        security_policies: [
          {
            name: 'real-policy',
            _rule_index: 1,
            action: 'allow',
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
          },
        ],
      };

      const result = AnalysisEngine._emptyPolicySet(config);
      expect(result.count).toBe(0);
    });
  });

  // ─── 5. zones_no_policy ────────────────────────────────────────────────────
  describe('_zonesWithoutPolicy', () => {
    it('flags zones not referenced in policies or NAT', () => {
      const config = {
        zones: [{ name: 'dmz' }, { name: 'trust' }],
        security_policies: [
          {
            name: 'policy-1',
            _rule_index: 1,
            src_zones: ['trust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            action: 'allow',
          },
        ],
        nat_rules: [],
      };

      const result = AnalysisEngine._zonesWithoutPolicy(config);
      expect(result.id).toBe('zones_no_policy');
      expect(result.count).toBe(1);
      expect(result.items[0].label).toBe('dmz');
    });

    it('counts zones referenced in NAT rules as used', () => {
      const config = {
        zones: [{ name: 'dmz' }, { name: 'untrust' }],
        security_policies: [],
        nat_rules: [
          {
            name: 'nat-1',
            source_zones: ['dmz'],
            destination_zones: ['untrust'],
          },
        ],
      };

      const result = AnalysisEngine._zonesWithoutPolicy(config);
      expect(result.count).toBe(0);
    });

    it('does not count "any" as a zone reference', () => {
      const config = {
        zones: [{ name: 'dmz' }],
        security_policies: [
          {
            name: 'policy-1',
            _rule_index: 1,
            src_zones: ['any'],
            dst_zones: ['any'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            action: 'allow',
          },
        ],
        nat_rules: [],
      };

      const result = AnalysisEngine._zonesWithoutPolicy(config);
      expect(result.count).toBe(1);
    });

    it('ignores implicit policies', () => {
      const config = {
        zones: [{ name: 'trust' }],
        security_policies: [
          {
            name: 'implicit',
            _rule_index: 0,
            _implicit: true,
            src_zones: ['trust'],
            dst_zones: ['trust'],
            src_addresses: ['any'],
            dst_addresses: ['any'],
            services: ['any'],
            action: 'allow',
          },
        ],
        nat_rules: [],
      };

      const result = AnalysisEngine._zonesWithoutPolicy(config);
      expect(result.count).toBe(1);
    });

    it('returns zero when no zones are defined', () => {
      const config = {
        zones: [],
        security_policies: [],
        nat_rules: [],
      };

      const result = AnalysisEngine._zonesWithoutPolicy(config);
      expect(result.count).toBe(0);
    });
  });

  // ─── 6. log_completeness ───────────────────────────────────────────────────
  describe('_logCompleteness', () => {
    it('flags when no remote syslog target is configured', () => {
      const config = {
        syslog_config: [],
      };

      const result = AnalysisEngine._logCompleteness(config);
      expect(result.id).toBe('log_completeness');
      expect(result.count).toBe(1);
      expect(result.items.length).toBe(1);
    });

    it('flags when syslog_config is missing', () => {
      const config = {};

      const result = AnalysisEngine._logCompleteness(config);
      expect(result.count).toBe(1);
    });

    it('returns zero when a remote syslog server is configured', () => {
      const config = {
        syslog_config: [
          { server: '192.168.1.100' },
        ],
      };

      const result = AnalysisEngine._logCompleteness(config);
      expect(result.count).toBe(0);
    });

    it('accepts "host" as remote target', () => {
      const config = {
        syslog_config: [
          { host: 'syslog.example.com' },
        ],
      };

      const result = AnalysisEngine._logCompleteness(config);
      expect(result.count).toBe(0);
    });

    it('ignores syslog entries without remote target', () => {
      const config = {
        syslog_config: [
          { facility: 'local0' },
        ],
      };

      const result = AnalysisEngine._logCompleteness(config);
      expect(result.count).toBe(1);
    });
  });
});
