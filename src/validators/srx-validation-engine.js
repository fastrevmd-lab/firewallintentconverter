/**
 * SRX Validation Engine Orchestrator
 * ====================================
 * Calls all three check modules (hardware, operational, compliance) and
 * handles license gating. Returns combined findings and any license-stripped output.
 */

import { createWarning } from '../parsers/parser-utils.js';
import { runHardwareChecks } from './hardware-checks.js';
import { runOperationalChecks } from './operational-checks.js';
import { runComplianceChecks } from './compliance-checks.js';

/** @type {Array<{pattern: RegExp, tier: string, label: string}>} */
const LICENSE_FEATURE_PATTERNS = [
  { pattern: /^set services idp\b/, tier: 'A1', label: 'IDP (Intrusion Detection & Prevention)' },
  { pattern: /^set services application-identification\b/, tier: 'A1', label: 'Application Identification (AppSecure)' },
  { pattern: /^set security policies .+ match application (?!any\b)\S+/, tier: 'A1', label: 'Application-based policy matching' },
  { pattern: /^set services security-intelligence\b/, tier: 'A1', label: 'Security Intelligence (SecIntel)' },
  { pattern: /^set security (utm|services content-security)\b/, tier: 'A2', label: 'UTM / Content Security' },
  { pattern: /^set services advanced-anti-malware\b/, tier: 'P1', label: 'Advanced Anti-Malware (ATP Cloud)' },
  { pattern: /application-services .+atp\b/, tier: 'P1', label: 'ATP Cloud policy attachment' },
];

/**
 * Determines if the held license tier covers the required tier.
 *
 * @param {string} haveTier - License tier held by the device
 * @param {string} needTier - License tier required by the feature
 * @returns {boolean}
 */
function tierCovers(haveTier, needTier) {
  const TIER_ORDER = { Base: 0, A1: 1, A2: 2, P1: 3, P2: 4 };

  if (haveTier === 'P2') return true;

  if (haveTier === 'P1') {
    // P1 covers Base, A1, P1 — NOT A2
    return needTier === 'Base' || needTier === 'A1' || needTier === 'P1';
  }

  if (haveTier === 'A2') {
    // A2 covers Base, A1, A2 — NOT P1
    return needTier === 'Base' || needTier === 'A1' || needTier === 'A2';
  }

  if (haveTier === 'A1') {
    return needTier === 'Base' || needTier === 'A1';
  }

  // Base covers Base only
  return needTier === 'Base';
}

/**
 * Runs license-gating checks against commands.
 *
 * @param {string[]} commands
 * @param {string|null} srxLicense
 * @param {boolean} enforce
 * @returns {{ findings: Object[], strippedCommands: string[], filteredCommands: string[] }}
 */
function runLicenseChecks(commands, srxLicense, enforce) {
  if (!srxLicense) {
    return {
      findings: [
        createWarning(
          'info',
          'license/no-tier',
          'No SRX license tier specified — license-gating checks skipped.',
          'Set a license tier (Base, A1, A2, P1, P2) to enable license validation.',
        ),
      ],
      strippedCommands: [],
      filteredCommands: commands,
    };
  }

  /** @type {Map<string, { label: string, tier: string, indices: Set<number> }>} */
  const gapsByFeature = new Map();

  for (let idx = 0; idx < commands.length; idx++) {
    const cmd = commands[idx];
    for (const { pattern, tier, label } of LICENSE_FEATURE_PATTERNS) {
      if (pattern.test(cmd) && !tierCovers(srxLicense, tier)) {
        const key = `${tier}:${label}`;
        if (!gapsByFeature.has(key)) {
          gapsByFeature.set(key, { label, tier, indices: new Set() });
        }
        gapsByFeature.get(key).indices.add(idx);
        break; // first matching pattern wins per command
      }
    }
  }

  const findings = [];
  const strippedIndices = new Set();

  for (const [, { label, tier, indices }] of gapsByFeature) {
    for (const idx of indices) strippedIndices.add(idx);

    if (enforce) {
      findings.push(
        createWarning(
          'unsupported',
          `license/${tier}`,
          `"${label}" requires the ${tier} license tier but device has ${srxLicense} — ${indices.size} command(s) were removed.`,
          `Upgrade the SRX license to ${tier} or higher to include this feature.`,
        ),
      );
    } else {
      findings.push(
        createWarning(
          'warning',
          `license/${tier}`,
          `"${label}" requires the ${tier} license tier (current: ${srxLicense}).`,
          `Upgrade the SRX license to ${tier} or higher to enable this feature.`,
        ),
      );
    }
  }

  const strippedCommands = commands.filter((_, idx) => strippedIndices.has(idx));
  const filteredCommands = commands.filter((_, idx) => !strippedIndices.has(idx));

  return { findings, strippedCommands, filteredCommands };
}

/**
 * Orchestrates all validation checks against converted SRX output.
 *
 * @param {object} opts
 * @param {object} opts.intermediateConfig - Parsed intermediate config object
 * @param {string} opts.srxOutput - Newline-separated SRX set commands
 * @param {string|null} opts.targetModel - Target SRX model string or null
 * @param {string|null} opts.srxLicense - License tier string or null ('Base','A1','A2','P1','P2')
 * @param {boolean} [opts.enforceLicense=false] - Strip unlicensed commands when true
 * @param {object} opts.modelDb - SRX_MODELS lookup object
 * @param {object} opts.capacityLimits - SRX_CAPACITY_LIMITS lookup object
 * @param {object|null} opts.sourceModel - Source model entry or null
 * @returns {{ findings: Object[], strippedCommands: string[], filteredOutput: string|null }}
 */
export function runValidation({
  intermediateConfig,
  srxOutput,
  targetModel,
  srxLicense,
  enforceLicense = false,
  modelDb,
  capacityLimits,
  sourceModel,
}) {
  const commands = (srxOutput ?? '').split('\n').filter(line => line.trim().length > 0);

  const hardwareFindings = runHardwareChecks(
    commands,
    targetModel,
    modelDb,
    capacityLimits,
    intermediateConfig,
    sourceModel,
  );

  const operationalFindings = runOperationalChecks(intermediateConfig, commands);

  const complianceFindings = runComplianceChecks(commands);

  const { findings: licenseFindings, strippedCommands, filteredCommands } =
    runLicenseChecks(commands, srxLicense, enforceLicense);

  const allFindings = [
    ...hardwareFindings,
    ...operationalFindings,
    ...complianceFindings,
    ...licenseFindings,
  ].map(finding => ({ ...finding, _source: 'validation' }));

  const filteredOutput =
    enforceLicense && strippedCommands.length > 0
      ? filteredCommands.join('\n')
      : null;

  return {
    findings: allFindings,
    strippedCommands,
    filteredOutput,
  };
}
