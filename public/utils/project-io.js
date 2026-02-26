/**
 * Project Save/Load — Serialization, validation, and migration for .fpic.json files
 */

const CURRENT_VERSION = 1;

const VENDOR_NAMES = {
  panos: 'PAN-OS', srx: 'SRX', fortigate: 'FortiGate',
  cisco_asa: 'Cisco-ASA', checkpoint: 'CheckPoint',
  sonicwall: 'SonicWall', huawei_usg: 'Huawei-USG',
  greenfield: 'Greenfield', srx_healthcheck: 'SRX-BestPractice',
};

const STATE_KEYS = [
  'configText', 'intermediateConfig', 'sourceVendor', 'sourceModel', 'targetModel',
  'srxLicense', 'portProfile', 'siteName', 'siteGroup', 'interfaceMappings',
  'isSanitized', 'sanitizationTable', 'parseWarnings', 'parseStats',
  'warningStatuses', 'srxTranslatedPolicies', 'srxOutput', 'convertWarnings',
  'conversionSummary', 'outputFormat', 'targetContext', 'greenfieldMode',
  'greenfieldTemplate', 'editTab', 'platformView', 'bottomTab',
];

const STATE_DEFAULTS = {
  configText: '',
  intermediateConfig: null,
  sourceVendor: 'panos',
  sourceModel: '',
  targetModel: '',
  srxLicense: '',
  portProfile: null,
  siteName: '',
  siteGroup: '',
  interfaceMappings: {},
  isSanitized: false,
  sanitizationTable: null,
  parseWarnings: [],
  parseStats: null,
  warningStatuses: {},
  srxTranslatedPolicies: null,
  srxOutput: null,
  convertWarnings: [],
  conversionSummary: null,
  outputFormat: 'set',
  targetContext: { type: 'none', name: '' },
  greenfieldMode: false,
  greenfieldTemplate: null,
  editTab: 'rules',
  platformView: 'panos',
  bottomTab: 'output',
};

/**
 * Build a save-ready project JSON payload from current app state.
 */
export function buildProjectPayload(stateBag, projectName) {
  const state = {};
  for (const key of STATE_KEYS) {
    state[key] = stateBag[key] ?? STATE_DEFAULTS[key];
  }
  return {
    fpic_version: CURRENT_VERSION,
    name: projectName,
    savedAt: new Date().toISOString(),
    state,
  };
}

/**
 * Validate a parsed JSON object as a valid FPIC project file.
 * Returns { valid: true, project, warnings } or { valid: false, error }.
 */
export function validateProjectFile(json) {
  const warnings = [];

  if (!json || typeof json !== 'object') {
    return { valid: false, error: 'File is not a valid JSON object.' };
  }

  if (typeof json.fpic_version !== 'number') {
    return { valid: false, error: 'Not a valid project file (missing fpic_version).' };
  }

  if (json.fpic_version > CURRENT_VERSION) {
    return {
      valid: false,
      error: `Project file version ${json.fpic_version} is newer than this app supports (v${CURRENT_VERSION}). Please update the app.`,
    };
  }

  if (!json.state || typeof json.state !== 'object') {
    return { valid: false, error: 'Project file is missing state data.' };
  }

  if (!json.state.intermediateConfig && !json.state.configText) {
    warnings.push('Project has no parsed config or source text. You may need to re-parse.');
  }

  const project = migrateProject(json);

  return { valid: true, project, warnings };
}

/**
 * Migrate a project from an older version to the current version.
 * Each version bump adds a migration step.
 */
function migrateProject(project) {
  const p = { ...project, state: { ...project.state } };

  // Fill missing keys with defaults
  for (const key of STATE_KEYS) {
    if (!(key in p.state)) {
      p.state[key] = STATE_DEFAULTS[key];
    }
  }

  // Future migrations:
  // if (p.fpic_version < 2) { ... p.fpic_version = 2; }

  return p;
}

/**
 * Generate a default project name from current state.
 */
export function generateProjectName(sourceVendor, sourceModel, siteName) {
  const vendor = VENDOR_NAMES[sourceVendor] || sourceVendor || 'Project';
  const model = sourceModel ? `-${sourceModel}` : '';
  const site = siteName ? `-${siteName}` : '';
  const date = new Date().toISOString().slice(0, 10);
  return `${vendor}${model}${site}-${date}`;
}
