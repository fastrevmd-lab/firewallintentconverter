import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const hookHarness = vi.hoisted(() => ({
  cleanup: null,
  configState: {},
  configDispatch: null,
  conversionState: {},
  conversionDispatch: null,
  mergeState: {},
  mergeDispatch: null,
  uiState: {},
  uiDispatch: null,
  undoDispatch: null,
}));

vi.mock('react', () => ({
  useCallback: callback => callback,
  useEffect: effect => {
    hookHarness.cleanup = effect();
  },
  useRef: initialValue => ({ current: initialValue }),
}));

vi.mock('../public/contexts/ConfigContext.jsx', () => ({
  useConfigContext: () => ({
    state: hookHarness.configState,
    dispatch: hookHarness.configDispatch,
  }),
}));

vi.mock('../public/contexts/ConversionContext.jsx', () => ({
  useConversionContext: () => ({
    state: hookHarness.conversionState,
    dispatch: hookHarness.conversionDispatch,
  }),
}));

vi.mock('../public/contexts/MergeContext.jsx', () => ({
  useMergeContext: () => ({
    state: hookHarness.mergeState,
    dispatch: hookHarness.mergeDispatch,
  }),
}));

vi.mock('../public/contexts/UIContext.jsx', () => ({
  useUIContext: () => ({
    state: hookHarness.uiState,
    dispatch: hookHarness.uiDispatch,
  }),
}));

vi.mock('../public/contexts/UndoContext.jsx', () => ({
  useUndoContext: () => ({ dispatch: hookHarness.undoDispatch }),
}));

import useProject, {
  assembleProjectStateBag,
  downloadValidatedProject,
  projectSecurityMessage,
} from '../public/hooks/useProject.js';
import {
  MAX_PROJECT_FILE_BYTES,
  PROJECT_SECURITY_MODES,
  serializeProjectExport,
} from '../public/utils/project-security.js';
import { encryptReversiblePayload } from '../public/utils/project-crypto.js';

const baseConfigState = {
  configText: 'set system host-name edge',
  intermediateConfig: { metadata: {} },
  sourceVendor: 'panos',
  sourceModel: 'PA-440',
  targetModel: 'SRX345',
  srxLicense: '',
  portProfile: null,
  siteName: 'site',
  siteGroup: 'group',
  interfaceMappings: {},
  isSanitized: false,
  sanitizationTable: null,
  parseWarnings: [],
  parseStats: null,
  warningStatuses: {},
  srxTranslatedPolicies: null,
  ruleGroups: [],
  sectionAcceptance: {},
  greenfieldMode: false,
  greenfieldTemplate: null,
};

const baseConversionState = {
  srxOutput: null,
  convertWarnings: [],
  conversionSummary: null,
  outputFormat: 'set',
  targetContext: { type: 'none', name: '' },
};

const baseUiState = {
  editTab: 'rules',
  platformView: 'panos',
  bottomTab: 'output',
};

const baseMergeState = {
  mergeMode: false,
  configSlots: [],
  activeSlotIndex: 0,
  crossLsLinks: [],
};

function findUiAction(type, predicate = () => true) {
  return hookHarness.uiDispatch.mock.calls
    .map(([action]) => action)
    .find(action => action.type === type && predicate(action));
}

function loadEvent(contents, size = new TextEncoder().encode(contents).length) {
  return {
    target: {
      files: [{ contents, size }],
      value: 'selected-project.json',
    },
  };
}

function treeContainsString(value, marker, seen = new Set()) {
  if (typeof value === 'string') return value.includes(marker);
  if (value === null || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (Object.hasOwn(descriptor, 'value')
        && treeContainsString(descriptor.value, marker, seen)) return true;
  }
  return false;
}

function allDispatchedValues() {
  return [
    hookHarness.configDispatch,
    hookHarness.conversionDispatch,
    hookHarness.mergeDispatch,
    hookHarness.uiDispatch,
    hookHarness.undoDispatch,
  ].flatMap(dispatch => dispatch.mock.calls.map(([value]) => value));
}

beforeEach(() => {
  hookHarness.cleanup = null;
  hookHarness.configState = structuredClone(baseConfigState);
  hookHarness.configDispatch = vi.fn();
  hookHarness.conversionState = structuredClone(baseConversionState);
  hookHarness.conversionDispatch = vi.fn();
  hookHarness.mergeState = structuredClone(baseMergeState);
  hookHarness.mergeDispatch = vi.fn();
  hookHarness.uiState = structuredClone(baseUiState);
  hookHarness.uiDispatch = vi.fn();
  hookHarness.undoDispatch = vi.fn();

  vi.stubGlobal('FileReader', class FakeFileReader {
    readAsText(file) {
      this.onload({ target: { result: file.contents } });
    }
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('secure project workflow helpers', () => {
  it('includes nested merge restoration tables in the security boundary input', () => {
    const nestedTable = [{
      type: 'hostname',
      placeholder: 'SANITIZED_HOST_0',
      original: 'nested-original.example',
    }];
    const mergeState = {
      ...baseMergeState,
      mergeMode: true,
      configSlots: [{
        configText: 'set system host-name SANITIZED_HOST_0',
        intermediateConfig: { metadata: {} },
        isSanitized: true,
        sanitizationTable: nestedTable,
      }],
    };

    const assembled = assembleProjectStateBag(
      baseConfigState,
      baseConversionState,
      baseUiState,
      mergeState,
    );

    expect(assembled.configSlots).toBe(mergeState.configSlots);
    expect(assembled.configSlots[0].sanitizationTable).toBe(nestedTable);
    expect(assembled).toMatchObject({
      configText: baseConfigState.configText,
      srxOutput: baseConversionState.srxOutput,
      editTab: baseUiState.editTab,
      mergeMode: true,
    });
  });

  it('creates and clicks a download only from a validated serialized boundary result', async () => {
    const click = vi.fn();
    const revokeObjectURL = vi.fn();
    const environment = {
      Blob: vi.fn(function FakeBlob(parts, options) {
        this.parts = parts;
        this.options = options;
      }),
      URL: {
        createObjectURL: vi.fn(() => 'blob:validated-project'),
        revokeObjectURL,
      },
      document: {
        createElement: vi.fn(() => ({ click })),
      },
    };
    const result = await serializeProjectExport({
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'original.example',
      }],
    }, 'edge', { mode: PROJECT_SECURITY_MODES.SANITIZED });

    downloadValidatedProject(result, environment);

    expect(environment.Blob).toHaveBeenCalledWith(
      [result.serialized],
      { type: 'application/json' },
    );
    expect(environment.URL.createObjectURL).toHaveBeenCalledOnce();
    expect(environment.document.createElement).toHaveBeenCalledWith('a');
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:validated-project');
  });

  it('rejects a hand-built download result before Blob, URL, or click', () => {
    const click = vi.fn();
    const environment = {
      Blob: vi.fn(),
      URL: { createObjectURL: vi.fn(), revokeObjectURL: vi.fn() },
      document: { createElement: vi.fn(() => ({ click })) },
    };
    const forged = {
      serialized: JSON.stringify({
        fpic_version: 5,
        name: 'forged',
        savedAt: '2026-07-12T00:00:00.000Z',
        security: {
          schema: 1, mode: 'unsanitized', containsOriginals: true,
          reversible: false, restorationAvailable: false,
        },
        state: { configText: 'set password FORGED', isSanitized: false },
      }),
      filename: 'forged.unsanitized.fpic.json',
      security: { mode: PROJECT_SECURITY_MODES.UNSANITIZED },
    };

    expect(() => downloadValidatedProject(forged, environment)).toThrow(
      expect.objectContaining({ code: 'invalid_project' }),
    );
    expect(environment.Blob).not.toHaveBeenCalled();
    expect(environment.URL.createObjectURL).not.toHaveBeenCalled();
    expect(environment.document.createElement).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
  });

  it('downloads the immutable boundary snapshot after the public result is mutated', async () => {
    const anchor = { click: vi.fn() };
    const environment = {
      Blob: vi.fn(function CaptureBlob(parts, options) {
        this.parts = parts;
        this.options = options;
      }),
      URL: {
        createObjectURL: vi.fn(() => 'blob:immutable-project'),
        revokeObjectURL: vi.fn(),
      },
      document: { createElement: vi.fn(() => anchor) },
    };
    const result = await serializeProjectExport({
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname', placeholder: 'SANITIZED_HOST_0', original: 'immutable.example',
      }],
    }, 'immutable', { mode: PROJECT_SECURITY_MODES.SANITIZED });
    const original = {
      serialized: result.serialized,
      filename: result.filename,
      mode: result.security.mode,
    };

    result.serialized = '{"forged":true}';
    result.filename = 'forged.unsanitized.fpic.json';
    result.security = { mode: PROJECT_SECURITY_MODES.UNSANITIZED };
    downloadValidatedProject(result, environment);

    expect(environment.Blob).toHaveBeenCalledWith(
      [original.serialized],
      { type: 'application/json' },
    );
    expect(anchor.download).toBe(original.filename);
    expect(JSON.parse(environment.Blob.mock.instances[0].parts[0]).security.mode)
      .toBe(original.mode);
    expect(anchor.click).toHaveBeenCalledOnce();
  });

  it.each([
    [null],
    [{}],
    [{ serialized: {}, filename: 'edge.fpic.json', security: {} }],
    [{ serialized: '{}', filename: '', security: {} }],
    [{ serialized: '{}', filename: 'edge.fpic.json', security: null }],
    [{
      serialized: '{}',
      filename: 'edge.sanitized.fpic.json',
      security: { mode: PROJECT_SECURITY_MODES.SANITIZED },
    }],
  ])('does not allocate a Blob or click for an invalid boundary result: %j', result => {
    const environment = {
      Blob: vi.fn(),
      URL: { createObjectURL: vi.fn(), revokeObjectURL: vi.fn() },
      document: { createElement: vi.fn() },
    };

    expect(() => downloadValidatedProject(result, environment)).toThrow();
    expect(environment.Blob).not.toHaveBeenCalled();
    expect(environment.URL.createObjectURL).not.toHaveBeenCalled();
    expect(environment.document.createElement).not.toHaveBeenCalled();
  });

  it('maps known local codes without reflecting unknown error messages', () => {
    expect(projectSecurityMessage({ code: 'oversized_project' }))
      .toBe('Project data exceeds the supported size limit.');
    expect(projectSecurityMessage({ code: 'invalid_confirmation' }, 'import'))
      .toBe('Project import acknowledgement is required.');
    expect(projectSecurityMessage({ code: 'unsupported_crypto' }, 'import'))
      .toBe('Encrypted project import is unavailable in this browser.');
    expect(projectSecurityMessage({ code: 'invalid_confirmation' }, 'export'))
      .toBe('Project export confirmation is invalid.');

    const message = projectSecurityMessage({
      code: 'future_error',
      message: 'UNIQUE-UNKNOWN-ERROR-DETAIL',
    });
    expect(message).toBe('Project security operation failed.');
    expect(message).not.toContain('UNIQUE-UNKNOWN-ERROR-DETAIL');
  });
});

describe('transactional project hook orchestration', () => {
  it('refuses direct application of a project that did not complete the import transaction', () => {
    const project = useProject();

    project.applyLoadedProject({
      state: { ...baseConfigState, ...baseConversionState, ...baseMergeState, ...baseUiState },
    }, { mode: PROJECT_SECURITY_MODES.SANITIZED });

    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Project file is invalid.',
    });
  });

  it('classifies current and nested merge state without returning credentials', () => {
    hookHarness.configState.isSanitized = true;
    hookHarness.configState.configText = 'set system host-name SANITIZED_HOST_0';
    hookHarness.configState.sanitizationTable = [{
      type: 'hostname', placeholder: 'SANITIZED_HOST_0', original: 'top-original',
    }];
    hookHarness.mergeState.configSlots = [{
      configText: 'set system host-name SANITIZED_HOST_1',
      intermediateConfig: { metadata: {} },
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname', placeholder: 'SANITIZED_HOST_1', original: 'nested-original',
      }],
    }];
    const project = useProject();

    const descriptor = project.getExportDescriptor();

    expect(descriptor).toEqual({
      mode: PROJECT_SECURITY_MODES.SANITIZED,
      sanitizedEligible: true,
      reversibleAvailable: true,
      restorationAvailable: true,
    });
    expect(JSON.stringify(descriptor)).not.toContain('original');
    expect(JSON.stringify(descriptor)).not.toContain('passphrase');
  });

  it('does not create a Blob or click when secure export serialization fails', async () => {
    const click = vi.fn();
    const BlobImpl = vi.fn();
    const createObjectURL = vi.fn();
    const createElement = vi.fn(() => ({ click }));
    vi.stubGlobal('Blob', BlobImpl);
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL: vi.fn() });
    vi.stubGlobal('document', { createElement });
    const project = useProject();

    await project.handleExportProject({
      name: 'must-not-download',
      mode: PROJECT_SECURITY_MODES.SANITIZED,
    });

    expect(BlobImpl).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(createElement).not.toHaveBeenCalled();
    expect(click).not.toHaveBeenCalled();
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Sanitized export requires every populated source to be sanitized.',
    });
  });

  it('acceptance: sanitized round-trip dispatch actions omit stripped originals', async () => {
    const original = 'DISPATCH-ORIGINAL-SECRET';
    let serialized;
    vi.stubGlobal('Blob', vi.fn(function CaptureBlob(parts) {
      [serialized] = parts;
    }));
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:sanitized-project'),
      revokeObjectURL: vi.fn(),
    });
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({ click: vi.fn() })),
    });
    hookHarness.configState = {
      ...hookHarness.configState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original,
      }],
    };
    const project = useProject();

    await project.handleExportProject({
      name: 'dispatch-acceptance',
      mode: PROJECT_SECURITY_MODES.SANITIZED,
    });
    project.handleLoadProjectFile(loadEvent(serialized));
    const loadConfirm = findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm');
    project.applyLoadedProject(loadConfirm.value.project, loadConfirm.value.security);

    const dispatched = allDispatchedValues();
    expect(dispatched.length).toBeGreaterThan(0);
    expect(treeContainsString(dispatched, original), original).toBe(false);
  });

  it('acceptance: reversible export and import dispatch no passphrase or original', async () => {
    const original = 'REVERSIBLE-DISPATCH-ORIGINAL';
    const passphrase = 'reversible dispatch passphrase';
    let serialized;
    vi.stubGlobal('Blob', vi.fn(function CaptureBlob(parts) {
      [serialized] = parts;
    }));
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:reversible-project'),
      revokeObjectURL: vi.fn(),
    });
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({ click: vi.fn() })),
    });
    hookHarness.configState = {
      ...hookHarness.configState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original,
      }],
    };
    const project = useProject();

    await project.handleExportProject({
      name: 'reversible-dispatch-acceptance',
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    project.handleLoadProjectFile(loadEvent(serialized));
    await project.confirmPendingImport({ passphrase, acknowledgement: true });

    const loadConfirm = findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm');
    expect(loadConfirm.value).toMatchObject({
      project: { name: 'Encrypted project', state: {} },
      security: { mode: PROJECT_SECURITY_MODES.REVERSIBLE },
    });
    const dispatched = allDispatchedValues();
    expect(dispatched.length).toBeGreaterThan(0);
    for (const marker of [passphrase, original]) {
      expect(treeContainsString(dispatched, marker), marker).toBe(false);
    }
  });

  it('never stages or dispatches an authenticated reversible payload without restoration proof', async () => {
    const passphrase = 'authenticated forged payload passphrase';
    const envelope = await encryptReversiblePayload({
      payloadSchema: 1,
      name: 'forged-authenticated-project',
      savedAt: '2026-07-11T00:00:00.000Z',
      sourceMode: 'sanitized',
      state: {
        ...baseConfigState,
        configText: 'set system host-name sanitized-fw',
        isSanitized: true,
        sanitizationTable: null,
      },
    }, passphrase);
    const project = useProject();
    project.handleLoadProjectFile(loadEvent(JSON.stringify(envelope)));
    hookHarness.uiDispatch.mockClear();

    await project.confirmPendingImport({ passphrase, acknowledgement: true });

    expect(findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm'))
      .toBeUndefined();
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Encrypted project could not be opened.',
    });
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();
  });

  it('fails altered encrypted metadata during the initial file read without staging it', async () => {
    const passphrase = 'correct horse battery staple';
    const result = await serializeProjectExport({
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'INITIAL-READ-ORIGINAL',
      }],
    }, 'altered-initial-read', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    const envelope = JSON.parse(result.serialized);
    envelope.security.schema = 2;
    const project = useProject();

    project.handleLoadProjectFile(loadEvent(JSON.stringify(envelope)));

    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Encrypted project could not be opened.',
    });
    expect(findUiAction('SHOW_MODAL', action => action.name === 'projectSecurityImport'))
      .toBeUndefined();
    expect(findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm'))
      .toBeUndefined();
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();

    hookHarness.uiDispatch.mockClear();
    await project.confirmPendingImport({ passphrase, acknowledgement: true });
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Project file is invalid.',
    });
    expect(findUiAction('SHOW_MODAL')).toBeUndefined();
  });

  it('rejects an oversized file before FileReader reads it', () => {
    const readAsText = vi.fn();
    vi.stubGlobal('FileReader', class TrackingFileReader {
      readAsText(file) {
        readAsText(file);
      }
    });
    const project = useProject();

    project.handleLoadProjectFile(loadEvent('{}', MAX_PROJECT_FILE_BYTES + 1));

    expect(readAsText).not.toHaveBeenCalled();
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Project data exceeds the supported size limit.',
    });
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();
  });

  it('fails closed when FileReader throws without reflecting native details', () => {
    vi.stubGlobal('FileReader', class ThrowingFileReader {
      readAsText() {
        throw new Error('UNIQUE-NATIVE-FILE-ERROR');
      }
    });
    const project = useProject();

    expect(() => project.handleLoadProjectFile(loadEvent('{}'))).not.toThrow();

    const errorAction = findUiAction('SET_FIELD', action => action.field === 'error');
    expect(errorAction.value).toBe('Project file is invalid.');
    expect(errorAction.value).not.toContain('UNIQUE-NATIVE-FILE-ERROR');
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();
  });

  it('keeps secret-bearing bytes out of UI state and delays application dispatch until both confirmations', async () => {
    const sensitiveState = {
      ...baseConfigState,
      configText: 'set system login password UNIQUE-PENDING-SECRET',
    };
    const result = await serializeProjectExport(sensitiveState, 'sensitive', {
      mode: PROJECT_SECURITY_MODES.UNSANITIZED,
      confirmation: 'EXPORT UNSANITIZED',
    });
    const project = useProject();

    project.handleLoadProjectFile(loadEvent(result.serialized));

    const securityModal = findUiAction(
      'SHOW_MODAL',
      action => action.name === 'projectSecurityImport',
    );
    expect(securityModal.value).toMatchObject({
      kind: PROJECT_SECURITY_MODES.UNSANITIZED,
      requiresConfirmation: true,
    });
    expect(JSON.stringify(securityModal.value)).not.toContain('UNIQUE-PENDING-SECRET');
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();

    await project.confirmPendingImport({
      passphrase: 'UNIQUE-CALLBACK-PASSPHRASE',
      acknowledgement: false,
    });

    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm'))
      .toBeUndefined();
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Project import acknowledgement is required.',
    });
    expect(JSON.stringify(hookHarness.uiDispatch.mock.calls))
      .not.toContain('UNIQUE-CALLBACK-PASSPHRASE');

    hookHarness.uiDispatch.mockClear();
    await project.confirmPendingImport({
      passphrase: 'UNIQUE-CALLBACK-PASSPHRASE',
      acknowledgement: true,
    });

    const loadConfirm = findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm');
    expect(loadConfirm.value.project.state.configText)
      .toContain('UNIQUE-PENDING-SECRET');
    expect(loadConfirm.value.security.mode).toBe(PROJECT_SECURITY_MODES.UNSANITIZED);
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();
    expect(JSON.stringify(hookHarness.uiDispatch.mock.calls))
      .not.toContain('UNIQUE-CALLBACK-PASSPHRASE');

    project.applyLoadedProject(loadConfirm.value.project, loadConfirm.value.security);

    expect(hookHarness.configDispatch).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'LOAD_PROJECT' }),
    );
    expect(hookHarness.conversionDispatch).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'LOAD_PROJECT' }),
    );
    expect(hookHarness.mergeDispatch).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'LOAD_PROJECT' }),
    );
  });

  it('sends validated sanitized plaintext directly to ordinary load confirmation', async () => {
    const sanitizedState = {
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'original.example',
      }],
    };
    const result = await serializeProjectExport(sanitizedState, 'sanitized', {
      mode: PROJECT_SECURITY_MODES.SANITIZED,
    });
    const project = useProject();

    project.handleLoadProjectFile(loadEvent(result.serialized));

    expect(findUiAction('SHOW_MODAL', action => action.name === 'projectSecurityImport'))
      .toBeUndefined();
    const loadConfirm = findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm');
    expect(loadConfirm.value.security.mode).toBe(PROJECT_SECURITY_MODES.SANITIZED);
    expect(loadConfirm.value.project.state.sanitizationTable).toBeNull();
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
  });

  it('applies an inaccessible secret-bearing snapshot after the confirmation copy is mutated', async () => {
    const secretBearingState = {
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'top-original.example',
      }],
      mergeMode: true,
      configSlots: [{
        configText: 'set system host-name SANITIZED_HOST_1',
        intermediateConfig: { metadata: {} },
        isSanitized: true,
        sanitizationTable: [{
          type: 'hostname',
          placeholder: 'SANITIZED_HOST_1',
          original: 'nested-original.example',
        }],
      }],
    };
    const result = await serializeProjectExport(secretBearingState, 'secret-bearing-merge', {
      mode: PROJECT_SECURITY_MODES.UNSANITIZED,
      confirmation: 'EXPORT UNSANITIZED',
    });
    const project = useProject();
    project.handleLoadProjectFile(loadEvent(result.serialized));
    await project.confirmPendingImport({ acknowledgement: true });
    const loadConfirm = findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm');

    loadConfirm.value.project.state.configText = 'set system login password MUTATED-TOP-SECRET';
    loadConfirm.value.project.state.configSlots[0].configText =
      'set system login password MUTATED-NESTED-SECRET';
    loadConfirm.value.project.state.configSlots[0].sanitizationTable = [{
      type: 'password',
      placeholder: 'SANITIZED_KEY_0',
      original: 'MUTATED-RESTORATION-SECRET',
    }];
    project.applyLoadedProject(loadConfirm.value.project, loadConfirm.value.security);

    const configLoad = hookHarness.configDispatch.mock.calls
      .map(([action]) => action)
      .find(action => action.type === 'LOAD_PROJECT');
    const mergeLoad = hookHarness.mergeDispatch.mock.calls
      .map(([action]) => action)
      .find(action => action.type === 'LOAD_PROJECT');
    expect(configLoad.state.configText).toBe('set system host-name SANITIZED_HOST_0');
    expect(configLoad.state.sanitizationTable[0].original).toBe('top-original.example');
    expect(mergeLoad.state.configSlots[0].configText)
      .toBe('set system host-name SANITIZED_HOST_1');
    expect(mergeLoad.state.configSlots[0].sanitizationTable[0].original)
      .toBe('nested-original.example');
    expect(JSON.stringify([configLoad, mergeLoad])).not.toContain('MUTATED-');
  });

  it('clears a pending import when cancelled, reset, replaced, or unmounted', async () => {
    const result = await serializeProjectExport(baseConfigState, 'pending', {
      mode: PROJECT_SECURITY_MODES.UNSANITIZED,
      confirmation: 'EXPORT UNSANITIZED',
    });

    for (const clearPending of [
      project => project.cancelPendingImport(),
      project => project.resetWorkspace(),
      project => project.handleLoadProjectFile(loadEvent('{invalid-json')),
      () => hookHarness.cleanup(),
    ]) {
      hookHarness.uiDispatch.mockClear();
      const project = useProject();
      project.handleLoadProjectFile(loadEvent(result.serialized));
      clearPending(project);
      hookHarness.uiDispatch.mockClear();

      await project.confirmPendingImport({ acknowledgement: true, passphrase: '' });

      expect(findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm'))
        .toBeUndefined();
      expect(hookHarness.configDispatch.mock.calls
        .some(([action]) => action.type === 'LOAD_PROJECT')).toBe(false);
    }
  });

  it.each(['overlay', 'close', 'Cancel callback'])(
    'clears a decrypted validated snapshot when final review is dismissed by %s',
    async () => {
      const original = 'FINAL-REVIEW-DECRYPTED-ORIGINAL';
      const passphrase = 'final review cancellation passphrase';
      const result = await serializeProjectExport({
        ...baseConfigState,
        configText: 'set system host-name SANITIZED_HOST_0',
        isSanitized: true,
        sanitizationTable: [{
          type: 'hostname',
          placeholder: 'SANITIZED_HOST_0',
          original,
        }],
      }, 'final-review-cancel', {
        mode: PROJECT_SECURITY_MODES.REVERSIBLE,
        passphrase,
        confirmationPassphrase: passphrase,
        acknowledgement: true,
      });
      const project = useProject();
      project.handleLoadProjectFile(loadEvent(result.serialized));
      await project.confirmPendingImport({ passphrase, acknowledgement: true });
      const loadConfirm = findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm');
      expect(loadConfirm).toBeDefined();

      hookHarness.uiDispatch.mockClear();
      project.cancelValidatedImportReview();
      expect(findUiAction('HIDE_MODAL', action => action.name === 'loadConfirm'))
        .toBeDefined();

      hookHarness.uiDispatch.mockClear();
      project.applyLoadedProject(loadConfirm.value.project, loadConfirm.value.security);
      expect(hookHarness.configDispatch.mock.calls
        .some(([action]) => action.type === 'LOAD_PROJECT')).toBe(false);
      expect(hookHarness.conversionDispatch.mock.calls
        .some(([action]) => action.type === 'LOAD_PROJECT')).toBe(false);
      expect(hookHarness.mergeDispatch.mock.calls
        .some(([action]) => action.type === 'LOAD_PROJECT')).toBe(false);
      expect(treeContainsString(allDispatchedValues(), original)).toBe(false);
      expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
        value: 'Project file is invalid.',
      });
    },
  );

  it('ignores an in-flight encrypted open after a replacement file is selected', async () => {
    const passphrase = 'correct horse battery staple';
    const reversibleState = {
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'original.example',
      }],
    };
    const result = await serializeProjectExport(reversibleState, 'reversible', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    const project = useProject();
    project.handleLoadProjectFile(loadEvent(result.serialized));
    hookHarness.uiDispatch.mockClear();

    const opening = project.confirmPendingImport({ passphrase, acknowledgement: true });
    project.handleLoadProjectFile(loadEvent('{replacement-is-invalid'));
    await opening;

    expect(findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm'))
      .toBeUndefined();
    expect(hookHarness.configDispatch).not.toHaveBeenCalled();
    expect(hookHarness.conversionDispatch).not.toHaveBeenCalled();
    expect(hookHarness.mergeDispatch).not.toHaveBeenCalled();
  });

  it('allows only the latest overlapping confirmation attempt to update UI', async () => {
    const passphrase = 'correct horse battery staple';
    const reversibleState = {
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'original.example',
      }],
    };
    const result = await serializeProjectExport(reversibleState, 'overlap', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    const project = useProject();
    project.handleLoadProjectFile(loadEvent(result.serialized));
    hookHarness.uiDispatch.mockClear();

    const olderFailure = project.confirmPendingImport({
      passphrase: 'too short',
      acknowledgement: true,
    });
    const newerSuccess = project.confirmPendingImport({
      passphrase,
      acknowledgement: true,
    });
    await Promise.all([olderFailure, newerSuccess]);

    const actions = hookHarness.uiDispatch.mock.calls.map(([action]) => action);
    expect(actions.some(action => action.type === 'SET_FIELD' && action.field === 'error'))
      .toBe(false);
    expect(actions.filter(action => action.type === 'SET_LOADING' && !action.isLoading))
      .toHaveLength(1);
    expect(actions.filter(action => action.type === 'SHOW_MODAL' && action.name === 'loadConfirm'))
      .toHaveLength(1);
    expect(actions.at(-1)).toEqual({
      type: 'SHOW_MODAL',
      name: 'loadConfirm',
      value: expect.any(Object),
    });
  });

  it('ends loading when a latest acknowledgement failure supersedes an open attempt', async () => {
    const passphrase = 'correct horse battery staple';
    const reversibleState = {
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'original.example',
      }],
    };
    const result = await serializeProjectExport(reversibleState, 'overlap-ack', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    const project = useProject();
    project.handleLoadProjectFile(loadEvent(result.serialized));
    hookHarness.uiDispatch.mockClear();

    const olderSuccess = project.confirmPendingImport({ passphrase, acknowledgement: true });
    const newerRejection = project.confirmPendingImport({
      passphrase,
      acknowledgement: false,
    });
    await Promise.all([olderSuccess, newerRejection]);

    const actions = hookHarness.uiDispatch.mock.calls.map(([action]) => action);
    expect(actions.filter(action => action.type === 'SET_LOADING' && !action.isLoading))
      .toHaveLength(1);
    expect(actions.some(action => action.type === 'SHOW_MODAL' && action.name === 'loadConfirm'))
      .toBe(false);
    expect(actions.find(action => action.type === 'SET_FIELD' && action.field === 'error'))
      .toMatchObject({ value: 'Project import acknowledgement is required.' });
  });

  it('normalizes unavailable WebCrypto without exposing environment details', async () => {
    const passphrase = 'correct horse battery staple';
    const reversibleState = {
      ...baseConfigState,
      configText: 'set system host-name SANITIZED_HOST_0',
      isSanitized: true,
      sanitizationTable: [{
        type: 'hostname',
        placeholder: 'SANITIZED_HOST_0',
        original: 'original.example',
      }],
    };
    const result = await serializeProjectExport(reversibleState, 'reversible', {
      mode: PROJECT_SECURITY_MODES.REVERSIBLE,
      passphrase,
      confirmationPassphrase: passphrase,
      acknowledgement: true,
    });
    const project = useProject();
    project.handleLoadProjectFile(loadEvent(result.serialized));
    vi.stubGlobal('crypto', {});
    hookHarness.uiDispatch.mockClear();

    await project.confirmPendingImport({ passphrase, acknowledgement: true });

    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Encrypted project could not be opened.',
    });
    expect(findUiAction('HIDE_MODAL', action => action.name === 'projectSecurityImport'))
      .toBeUndefined();

    hookHarness.uiDispatch.mockClear();
    await project.confirmPendingImport({ passphrase, acknowledgement: true });
    expect(findUiAction('SET_FIELD', action => action.field === 'error')).toMatchObject({
      value: 'Encrypted project could not be opened.',
    });
    expect(findUiAction('SHOW_MODAL', action => action.name === 'loadConfirm'))
      .toBeUndefined();
  });
});
