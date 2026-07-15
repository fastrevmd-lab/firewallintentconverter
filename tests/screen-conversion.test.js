import { describe, it, expect } from 'vitest';
import { parsePanosConfig } from '../src/parsers/panos-parser.js';
import { convertToSrxSetCommands } from '../src/converters/srx-converter.js';

/**
 * Tests for PAN-OS screen/IDS conversion (issue #38)
 *
 * Validates:
 * 1. Parser correctly reads zone-protection-profile from network.zone-protection-profile
 * 2. Parser captures both alarm-rate and activate-rate separately
 * 3. Converter emits distinct alarm-threshold and attack-threshold (no fabrication)
 * 4. Converter attaches screen to zone
 * 5. Converter warns when screen is not attached to any zone
 */
describe('Screen conversion (issue #38)', () => {
  /**
   * Test 1: Parser extracts zone attachment and both flood rates
   */
  it('parser: extracts zone from network.zone-protection-profile and preserves both flood rates', () => {
    const panXml = `<?xml version="1.0"?>
<config version="10.0.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <profiles>
          <zone-protection-profile>
            <entry name="strict-profile">
              <flood>
                <tcp-syn>
                  <enable>yes</enable>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>20000</activate-rate>
                  </red>
                </tcp-syn>
              </flood>
            </entry>
          </zone-protection-profile>
        </profiles>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust">
              <network>
                <zone-protection-profile>strict-profile</zone-protection-profile>
              </network>
            </entry>
          </zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`;

    const result = parsePanosConfig(panXml);
    const parsed = result.intermediateConfig;
    expect(parsed.screen_config).toBeDefined();
    expect(parsed.screen_config.length).toBe(1);

    const screen = parsed.screen_config[0];
    expect(screen.name).toBe('strict-profile');
    expect(screen.zone).toBe('trust'); // zone attachment from network path
    expect(screen.tcp.syn_flood_threshold).toBe(20000); // activate-rate → attack-threshold
    expect(screen.tcp.syn_flood_alarm_threshold).toBe(10000); // alarm-rate → alarm-threshold (NEW)
  });

  /**
   * Test 2: Converter emits distinct alarm/attack thresholds without fabrication
   */
  it('converter: emits distinct alarm-threshold and attack-threshold without fabrication', () => {
    const testConfig = {
      screen_config: [{
        name: 'test-screen',
        zone: 'trust',
        icmp: { flood_threshold: null, ping_death: false, fragment: false },
        tcp: {
          syn_flood_threshold: 20000,
          syn_flood_alarm_threshold: 10000,
          syn_flood_timeout: null,
          land_attack: false,
          winnuke: false,
          tcp_no_flag: false,
        },
        udp: { flood_threshold: null },
        ip: {
          spoofing: false,
          source_route: false,
          tear_drop: false,
          record_route: false,
          timestamp: false,
        },
        limit_session: {},
      }],
    };

    const result = convertToSrxSetCommands(testConfig);
    const commands = result.commands.join('\n');

    // Must contain both thresholds with correct values
    expect(commands).toContain('tcp syn-flood attack-threshold 20000');
    expect(commands).toContain('tcp syn-flood alarm-threshold 10000');

    // Must NOT contain fabricated value (20000 * 5 = 100000)
    expect(commands).not.toContain('100000');

    // Must attach screen to zone
    expect(commands).toMatch(/set security zones security-zone \S+ screen test-screen/);

    // Output should be well-formed (basic check)
    expect(commands).toContain('set security screen ids-option');
  });

  /**
   * Test 3: Converter warns when screen is not attached to any zone
   */
  it('converter: warns when screen is defined but not attached to zone', () => {
    const testConfig = {
      screen_config: [{
        name: 'orphan-screen',
        zone: '', // no zone attachment
        icmp: { flood_threshold: null, ping_death: false, fragment: false },
        tcp: {
          syn_flood_threshold: 15000,
          syn_flood_alarm_threshold: 8000,
          syn_flood_timeout: null,
          land_attack: false,
          winnuke: false,
          tcp_no_flag: false,
        },
        udp: { flood_threshold: null },
        ip: {
          spoofing: false,
          source_route: false,
          tear_drop: false,
          record_route: false,
          timestamp: false,
        },
        limit_session: {},
      }],
    };

    const result = convertToSrxSetCommands(testConfig);
    const commands = result.commands.join('\n');

    // Should contain warning comment
    expect(commands).toMatch(/# NOTE: screen profile "orphan-screen" is not attached to any zone/);

    // Should NOT contain zone attachment command
    expect(commands).not.toMatch(/set security zones security-zone .+ screen orphan-screen/);

    // Should contain a warning
    expect(result.warnings.length).toBeGreaterThan(0);
    const screenWarning = result.warnings.find(w => w.message.includes('orphan-screen'));
    expect(screenWarning).toBeDefined();
    expect(screenWarning.message).toMatch(/not attached to a security zone/i);
  });

  /**
   * Test 4: End-to-end parse→convert preserves exact values
   */
  it('end-to-end: parse→convert produces correct alarm/attack thresholds and zone attachment', () => {
    const panXml = `<?xml version="1.0"?>
<config version="10.0.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <profiles>
          <zone-protection-profile>
            <entry name="production-ids">
              <flood>
                <tcp-syn>
                  <enable>yes</enable>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>20000</activate-rate>
                  </red>
                </tcp-syn>
              </flood>
            </entry>
          </zone-protection-profile>
        </profiles>
      </network>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="dmz">
              <network>
                <zone-protection-profile>production-ids</zone-protection-profile>
              </network>
            </entry>
          </zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>`;

    const parseResult = parsePanosConfig(panXml);
    const parsed = parseResult.intermediateConfig;
    const result = convertToSrxSetCommands(parsed);
    const commands = result.commands.join('\n');

    // Verify parser extracted both values
    expect(parsed.screen_config[0].tcp.syn_flood_threshold).toBe(20000);
    expect(parsed.screen_config[0].tcp.syn_flood_alarm_threshold).toBe(10000);
    expect(parsed.screen_config[0].zone).toBe('dmz');

    // Verify converter emitted both correctly
    expect(commands).toContain('tcp syn-flood attack-threshold 20000');
    expect(commands).toContain('tcp syn-flood alarm-threshold 10000');
    expect(commands).toMatch(/set security zones security-zone \S+ screen production-ids/);

    // Output should be well-formed (basic check)
    expect(commands).toContain('set security screen ids-option');
  });
});
