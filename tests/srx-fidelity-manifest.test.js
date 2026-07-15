import { describe, expect, it } from 'vitest';

import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

describe('SRX fidelity manifest — undefined references', () => {
  it('deactivates policy with undefined address reference and includes caveat', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Allow-Ghost',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should contain deactivate command (using global policy structure by default)
    expect(output).toContain('deactivate security policies global policy Allow-Ghost');

    // Should contain caveat comment naming the undefined reference
    expect(output).toMatch(/# CAVEAT:.*undefined reference.*GHOST-OBJ/);

    // Should have a warning
    expect(result.warnings.length).toBeGreaterThan(0);
    const hasUndefinedRefWarning = result.warnings.some(w =>
      w.message && w.message.toLowerCase().includes('undefined'),
    );
    expect(hasUndefinedRefWarning).toBe(true);

    // Summary should count it
    expect(result.summary.total_source_policies).toBe(1);
    expect(result.summary.policies_deactivated_undefined_ref).toBe(1);

    // Should contain fidelity manifest block
    expect(output).toMatch(/# Conversion Fidelity Manifest/);
    expect(output).toMatch(/# Source security policies: 1/);
    expect(output).toMatch(/#   inactive \(undefined reference\): 1/);
  });

  it('does not deactivate policy with all defined references', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [
        { name: 'Server-1', type: 'host', value: '192.0.2.10/32' },
      ],
      address_groups: [],
      service_objects: [
        { name: 'HTTP', protocol: 'tcp', port: '80' },
      ],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Allow-HTTP',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['Server-1'],
          dst_addresses: ['any'],
          services: ['HTTP'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should NOT contain deactivate for this policy
    expect(output).not.toContain('deactivate security policies global policy Allow-HTTP');

    // Should NOT contain caveat about undefined references for this policy
    const policySection = output.substring(output.indexOf('Allow-HTTP'));
    expect(policySection).not.toMatch(/# CAVEAT:.*undefined reference/);

    // Summary should show 0 deactivated for undefined refs
    expect(result.summary.total_source_policies).toBe(1);
    expect(result.summary.policies_deactivated_undefined_ref).toBe(0);

    // Should still contain fidelity manifest block
    expect(output).toMatch(/# Conversion Fidelity Manifest/);
    expect(output).toMatch(/# Source security policies: 1/);
    expect(output).toMatch(/#   inactive \(undefined reference\): 0/);
  });

  it('deactivates policy with undefined service reference', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Allow-Ghost-Service',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['GHOST-SERVICE'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should contain deactivate command (for unmapped app, not undefined ref - GHOST-SERVICE creates unmapped app)
    expect(output).toMatch(/deactivate security policies global policy.*Ghost.*Service/i);

    // Should contain caveat comment naming the undefined service
    expect(output).toMatch(/# CAVEAT:.*undefined reference.*GHOST-SERVICE/);

    // Summary should count it
    expect(result.summary.total_source_policies).toBe(1);
    expect(result.summary.policies_deactivated_undefined_ref).toBe(1);
  });

  it('counts multiple policies with undefined references', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['GHOST-1'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Rule-2',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Rule-3',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['GHOST-3'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should count 2 policies deactivated for undefined refs (Rule-1 and Rule-3)
    expect(result.summary.total_source_policies).toBe(3);
    expect(result.summary.policies_deactivated_undefined_ref).toBe(2);

    // Manifest should reflect this
    expect(output).toMatch(/# Source security policies: 3/);
    expect(output).toMatch(/#   inactive \(undefined reference\): 2/);
  });

  it('does not emit manifest when there are no non-implicit policies', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should NOT contain fidelity manifest block when there are no policies
    expect(output).not.toMatch(/# Conversion Fidelity Manifest/);
  });

  it('does not count implicit policies in total_source_policies', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Implicit-Rule',
          _implicit: true,
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Real-Rule',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should count only the non-implicit policy
    expect(result.summary.total_source_policies).toBe(1);
    expect(result.summary.policies_deactivated_undefined_ref).toBe(0);

    // Manifest should show 1 total
    expect(output).toMatch(/# Source security policies: 1/);
  });

  // Fix 1: Complete fidelity manifest with disposition breakdown
  it('emits full disposition breakdown in manifest', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Active-Rule',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Disabled-Rule',
          disabled: true,
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Undefined-Ref-Rule',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Unmapped-App-Rule',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: ['UnknownApp'],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should emit full disposition breakdown
    expect(output).toMatch(/# Source security policies: 4/);
    expect(output).toMatch(/#   active \(converted\): 1/);
    expect(output).toMatch(/#   inactive \(disabled in source\): 1/);
    expect(output).toMatch(/#   inactive \(unmapped application\): 1/);
    expect(output).toMatch(/#   inactive \(undefined reference\): 1/);

    // Should emit detail lines for undefined references
    expect(output).toMatch(/# Undefined references \(rule -> missing object\):/);
    expect(output).toMatch(/#   - Undefined-Ref-Rule: address "GHOST-OBJ"/);
  });

  it('counts policy in only one inactive category when multiple conditions apply', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Active-Rule',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
        {
          name: 'Both-Disabled-And-Undefined',
          disabled: true,
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['GHOST-OBJ'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Total = 2, active = 1, inactive union = 1 (not 2)
    expect(output).toMatch(/# Source security policies: 2/);
    expect(output).toMatch(/#   active \(converted\): 1/);
    // The policy is in both disabled and undefined sets, but counted once
    const inactiveMatch = output.match(/#   inactive \(disabled in source\): (\d+)/);
    const undefinedMatch = output.match(/#   inactive \(undefined reference\): (\d+)/);
    const disabledCount = inactiveMatch ? parseInt(inactiveMatch[1]) : 0;
    const undefinedCount = undefinedMatch ? parseInt(undefinedMatch[1]) : 0;
    // Active should be total minus size of union (which is 1 policy with both conditions)
    expect(disabledCount).toBe(1);
    expect(undefinedCount).toBe(1);
    // Active = 2 - union{0,1} = 2 - 1 = 1
    const activeMatch = output.match(/#   active \(converted\): (\d+)/);
    expect(activeMatch ? parseInt(activeMatch[1]) : 0).toBe(1);
  });

  it('does not emit undefined references detail section when map is empty', () => {
    const config = {
      metadata: { source_vendor: 'panos' },
      zones: [
        { name: 'trust', interfaces: [] },
        { name: 'untrust', interfaces: [] },
      ],
      address_objects: [],
      address_groups: [],
      service_objects: [],
      service_groups: [],
      applications: [],
      application_groups: [],
      schedules: [],
      security_policies: [
        {
          name: 'Rule-1',
          src_zones: ['trust'],
          dst_zones: ['untrust'],
          src_addresses: ['any'],
          dst_addresses: ['any'],
          services: ['any'],
          applications: [],
          action: 'allow',
        },
      ],
    };

    const result = convertToSrxSetCommands(config);
    const output = result.commands.join('\n');

    // Should NOT emit detail section when no undefined refs
    expect(output).not.toMatch(/# Undefined references \(rule -> missing object\):/);
  });
});
