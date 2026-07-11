# Canonical Conversion Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace permissive SRX output shape handling with one runtime-validated set/XML contract so validation, enforcement, rendering, export, persistence, batch conversion, and push cannot silently inspect or transmit empty content.

**Architecture:** A dependency-free conversion-output boundary module owns a discriminated `{ format: 'set', commands } | { format: 'xml', xml }` contract and delegates completed-artifact checks to the existing Junos validators. The engine and project importer normalize data once; state and consumers assert and read it through shared helpers. Set-command validation receives the canonical object and returns filtered command arrays so enforcement can replace only `commands` while preserving metadata.

**Tech Stack:** JavaScript ES modules, React 18 contexts/hooks, Vitest 4, existing Junos set/XML validators, Vite 8.

## Global Constraints

- Keep the converter-internal set and XML builders unchanged except for normalizing their public return value.
- Do not add TypeScript or new production dependencies.
- Never accept `srxCommands` as an alias; that property is the fail-open typo being eliminated.
- Never reflect rejected configuration content in an error.
- New application state must contain only canonical output or `null`.
- Legacy string output is accepted only with a `set` format hint during project migration.
- Existing validation remains set-command-only; XML validation attempts must fail closed with an actionable message.
- Preserve warnings, summaries, and unknown converter metadata when commands are filtered.
- Use TDD for every behavior change and commit each task independently.

---

### Task 1: Define the canonical conversion-output contract

**Files:**
- Create: `src/conversion/conversion-output.js`
- Create: `tests/conversion-output.test.js`

**Interfaces:**
- Consumes: `validateSetOutput(commands: string[]): true` and `validateXmlOutput(xml: string): true` from `src/security/junos-output-validation.js`.
- Produces: `ConversionOutputError`, `normalizeConversionOutput(rawOutput, formatHint?)`, `assertConversionOutput(output)`, `getConversionOutputText(output)`, `getSetCommands(output)`, `replaceSetCommands(output, commands)`, and `hasConversionOutput(output)`.

- [ ] **Step 1: Write the contract tests first**

Create `tests/conversion-output.test.js`:

```js
import { describe, expect, it } from 'vitest';

import {
  ConversionOutputError,
  assertConversionOutput,
  getConversionOutputText,
  getSetCommands,
  hasConversionOutput,
  normalizeConversionOutput,
  replaceSetCommands,
} from '../src/conversion/conversion-output.js';

const SET_COMMANDS = [
  'set system host-name edge-1',
  'set system services ssh',
];
const XML = '<configuration><system><host-name>edge-1</host-name></system></configuration>';

describe('canonical conversion output', () => {
  it('normalizes converter set output and preserves metadata', () => {
    const summary = { policies_converted: 2 };
    const output = normalizeConversionOutput({ commands: SET_COMMANDS, warnings: [], summary }, 'set');

    expect(output).toEqual({ format: 'set', commands: SET_COMMANDS, warnings: [], summary });
    expect(output.commands).not.toBe(SET_COMMANDS);
    expect(getConversionOutputText(output)).toBe(SET_COMMANDS.join('\n'));
    expect(getSetCommands(output)).toEqual(SET_COMMANDS);
  });

  it('normalizes converter XML output', () => {
    const output = normalizeConversionOutput({ xml: XML, warnings: [] }, 'xml');

    expect(output).toEqual({ format: 'xml', xml: XML, warnings: [] });
    expect(getConversionOutputText(output)).toBe(XML);
    expect(() => getSetCommands(output)).toThrow(/Set Commands/);
  });

  it('normalizes a legacy set string only with an explicit hint', () => {
    expect(normalizeConversionOutput(SET_COMMANDS.join('\n'), 'set')).toEqual({
      format: 'set',
      commands: SET_COMMANDS,
    });
    expect(() => normalizeConversionOutput(SET_COMMANDS.join('\n'))).toThrow(ConversionOutputError);
    expect(() => normalizeConversionOutput(XML, 'xml')).toThrow(ConversionOutputError);
  });

  it('preserves metadata when replacing filtered commands', () => {
    const original = normalizeConversionOutput({
      commands: SET_COMMANDS,
      warnings: [{ type: 'warning' }],
      summary: { policies_converted: 2 },
      auditId: 'conversion-7',
    }, 'set');

    const filtered = replaceSetCommands(original, [SET_COMMANDS[0]]);

    expect(filtered).toEqual({
      format: 'set',
      commands: [SET_COMMANDS[0]],
      warnings: [{ type: 'warning' }],
      summary: { policies_converted: 2 },
      auditId: 'conversion-7',
    });
    expect(original.commands).toEqual(SET_COMMANDS);
  });

  it.each([
    null,
    '',
    '   ',
    {},
    { format: 'set', commands: [] },
    { format: 'set', commands: [''] },
    { format: 'set', commands: [7] },
    { format: 'xml', xml: '' },
    { format: 'xml', xml: 7 },
    { format: 'set', commands: SET_COMMANDS, xml: XML },
    { format: 'xml', xml: XML, commands: SET_COMMANDS },
    { format: 'yaml', commands: SET_COMMANDS },
    { format: 'set', srxCommands: SET_COMMANDS.join('\n') },
  ])('rejects missing, empty, mixed, or malformed output: %j', value => {
    expect(() => assertConversionOutput(value)).toThrow(ConversionOutputError);
    expect(hasConversionOutput(value)).toBe(false);
  });

  it('rejects mismatched format hints and unsafe artifacts', () => {
    expect(() => normalizeConversionOutput({ format: 'set', commands: SET_COMMANDS }, 'xml'))
      .toThrow(/does not match/);
    expect(() => normalizeConversionOutput({
      commands: ['set system host-name safe', 'set system services telnet'],
    }, 'set')).toThrow(ConversionOutputError);
  });

  it('does not include rejected configuration in errors', () => {
    const secret = 'set system root-authentication encrypted-password SECRET-HASH';
    let error;
    try {
      normalizeConversionOutput({ commands: [secret] }, 'set');
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(ConversionOutputError);
    expect(error.message).not.toContain(secret);
    expect(error.message).not.toContain('SECRET-HASH');
  });
});
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
npx vitest run tests/conversion-output.test.js
```

Expected: FAIL because `src/conversion/conversion-output.js` does not exist.

- [ ] **Step 3: Implement the minimal shared contract**

Create `src/conversion/conversion-output.js`:

```js
import {
  validateSetOutput,
  validateXmlOutput,
} from '../security/junos-output-validation.js';

/**
 * @typedef {Object} SetConversionOutput
 * @property {'set'} format
 * @property {string[]} commands
 */

/**
 * @typedef {Object} XmlConversionOutput
 * @property {'xml'} format
 * @property {string} xml
 */

/** @typedef {SetConversionOutput | XmlConversionOutput} ConversionOutput */

export class ConversionOutputError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'ConversionOutputError';
    this.reason = reason;
  }
}

function fail(reason) {
  throw new ConversionOutputError(reason);
}

function validateArtifact(output) {
  try {
    if (output.format === 'set') validateSetOutput(output.commands);
    else validateXmlOutput(output.xml);
  } catch {
    fail(`Generated ${output.format === 'set' ? 'Set Commands' : 'XML'} output failed Junos artifact validation.`);
  }
}

export function normalizeConversionOutput(rawOutput, formatHint) {
  if (!['set', 'xml', undefined].includes(formatHint)) {
    fail('Conversion output format hint must be set or xml.');
  }

  if (typeof rawOutput === 'string') {
    if (formatHint !== 'set') {
      fail('Legacy string output requires an explicit Set Commands format hint.');
    }
    rawOutput = {
      commands: rawOutput.split('\n').filter(line => line.trim().length > 0),
    };
  }

  if (!rawOutput || typeof rawOutput !== 'object' || Array.isArray(rawOutput)) {
    fail('Conversion output must be an object.');
  }
  if (Object.hasOwn(rawOutput, 'srxCommands')) {
    fail('Conversion output uses an unsupported command field.');
  }

  const format = rawOutput.format ?? formatHint;
  if (rawOutput.format && formatHint && rawOutput.format !== formatHint) {
    fail('Conversion output format does not match its format hint.');
  }
  if (!['set', 'xml'].includes(format)) {
    fail('Conversion output format must be set or xml.');
  }

  if (format === 'set') {
    if (Object.hasOwn(rawOutput, 'xml')) fail('Set Commands output cannot contain XML content.');
    if (!Array.isArray(rawOutput.commands) || rawOutput.commands.length === 0) {
      fail('Set Commands output must contain at least one command.');
    }
    if (rawOutput.commands.some(command => typeof command !== 'string' || !command.trim())) {
      fail('Set Commands output must contain only non-empty strings.');
    }
    const output = { ...rawOutput, format: 'set', commands: [...rawOutput.commands] };
    validateArtifact(output);
    return output;
  }

  if (Object.hasOwn(rawOutput, 'commands')) fail('XML output cannot contain Set Commands content.');
  if (typeof rawOutput.xml !== 'string' || !rawOutput.xml.trim()) {
    fail('XML output must contain non-empty XML text.');
  }
  const output = { ...rawOutput, format: 'xml', xml: rawOutput.xml };
  validateArtifact(output);
  return output;
}

export function assertConversionOutput(output) {
  if (!output || typeof output !== 'object' || !Object.hasOwn(output, 'format')) {
    fail('Canonical conversion output is missing its format.');
  }
  return normalizeConversionOutput(output, output.format);
}

export function getConversionOutputText(output) {
  const canonical = assertConversionOutput(output);
  return canonical.format === 'set' ? canonical.commands.join('\n') : canonical.xml;
}

export function getSetCommands(output) {
  const canonical = assertConversionOutput(output);
  if (canonical.format !== 'set') {
    fail('Validation and license enforcement require Set Commands output.');
  }
  return [...canonical.commands];
}

export function replaceSetCommands(output, commands) {
  const canonical = assertConversionOutput(output);
  if (canonical.format !== 'set') {
    fail('Only Set Commands output can be filtered.');
  }
  return normalizeConversionOutput({ ...canonical, commands }, 'set');
}

export function hasConversionOutput(output) {
  try {
    assertConversionOutput(output);
    return true;
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Run the focused test and verify GREEN**

Run:

```bash
npx vitest run tests/conversion-output.test.js
```

Expected: 1 file passes with all canonical contract cases green.

- [ ] **Step 5: Commit the contract**

```bash
git add src/conversion/conversion-output.js tests/conversion-output.test.js
git commit -m "feat: define canonical conversion output"
```

---

### Task 2: Enforce the contract at engine and state boundaries

**Files:**
- Modify: `public/utils/engine.js:63-138`
- Modify: `public/contexts/ConversionContext.jsx:8-51`
- Modify: `tests/conversion-security.test.js`
- Modify: `tests/context-reducers.test.js`

**Interfaces:**
- Consumes: `normalizeConversionOutput(rawOutput, formatHint)` and `assertConversionOutput(output)` from Task 1.
- Produces: engine envelopes whose `output` is canonical and reducer state whose `outputFormat` is derived from `srxOutput.format`.

- [ ] **Step 1: Add failing engine and reducer boundary tests**

Append to `tests/conversion-security.test.js`:

```js
it('returns canonical discriminated output through both public engine paths', async () => {
  const intermediate = {
    metadata: {},
    zones: [],
    address_objects: [],
    address_groups: [],
    service_objects: [],
    service_groups: [],
    security_policies: [],
    nat_rules: [],
    interfaces: [],
  };

  const setResult = await convertConfig(intermediate, 'set');
  const xmlResult = await mergeConvert([
    { lsName: 'site-a', intermediateConfig: intermediate, interfaceMappings: {} },
  ], [], 'xml');

  expect(setResult.output.format).toBe('set');
  expect(setResult.output.commands.length).toBeGreaterThan(0);
  expect(xmlResult.output.format).toBe('xml');
  expect(xmlResult.output.xml).toContain('<configuration>');
});
```

Append to `tests/context-reducers.test.js`:

```js
describe('conversionReducer canonical output', () => {
  it('derives outputFormat from canonical output and ignores a stale action format', () => {
    const output = {
      format: 'set',
      commands: ['set system host-name edge-1'],
      warnings: [],
    };
    const next = conversionReducer(conversionInitial, {
      type: 'SET_CONVERSION_RESULT',
      output,
      format: 'xml',
      warnings: [],
    });

    expect(next.srxOutput).toEqual(output);
    expect(next.outputFormat).toBe('set');
  });

  it('rejects malformed output instead of storing it', () => {
    expect(() => conversionReducer(conversionInitial, {
      type: 'SET_CONVERSION_RESULT',
      output: { commands: [] },
    })).toThrow(/Canonical conversion output/);
  });
});
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
npx vitest run tests/conversion-security.test.js tests/context-reducers.test.js
```

Expected: FAIL because engine output has no `format`, reducer trusts `action.format`, and malformed output is stored.

- [ ] **Step 3: Normalize engine output before returning**

At the top of `public/utils/engine.js`, add:

```js
import { normalizeConversionOutput } from '../../src/conversion/conversion-output.js';
```

In both `convertConfig` and `mergeConvert`, immediately after existing completed-artifact validation, replace the local output with canonical output:

```js
output = normalizeConversionOutput(output, format);
```

Keep the existing return envelopes and return `format: output.format`:

```js
return { output, format: output.format, validation };
```

and:

```js
return { output, format: output.format };
```

- [ ] **Step 4: Assert canonical output in the reducer**

At the top of `public/contexts/ConversionContext.jsx`, add:

```js
import { assertConversionOutput } from '../../src/conversion/conversion-output.js';
```

Replace the `SET_CONVERSION_RESULT` case with:

```js
case 'SET_CONVERSION_RESULT': {
  const output = assertConversionOutput(action.output);
  return {
    ...state,
    srxOutput: output,
    convertWarnings: action.warnings ?? [],
    conversionSummary: action.summary ?? output.summary ?? null,
    outputFormat: output.format,
    validationFindings: action.validationFindings ?? state.validationFindings,
  };
}
```

- [ ] **Step 5: Run focused and baseline reducer/engine tests**

Run:

```bash
npx vitest run tests/conversion-output.test.js tests/conversion-security.test.js tests/context-reducers.test.js
```

Expected: all three files pass.

- [ ] **Step 6: Commit boundary enforcement**

```bash
git add public/utils/engine.js public/contexts/ConversionContext.jsx tests/conversion-security.test.js tests/context-reducers.test.js
git commit -m "fix: enforce canonical output boundaries"
```

---

### Task 3: Make validation and license enforcement consume canonical output

**Files:**
- Modify: `src/validators/srx-validation-engine.js:128-187`
- Modify: `public/hooks/useConversion.js:13-222`
- Modify: `tests/validation-engine.test.js`
- Create: `tests/conversion-enforcement.test.js`

**Interfaces:**
- Consumes: `getSetCommands(output)`, `replaceSetCommands(output, commands)`, and `ConversionOutputError` from Task 1.
- Produces: `runValidation({ conversionOutput, ... })` returning `{ findings, strippedCommands, filteredCommands }`, where `filteredCommands` is `string[] | null`.

- [ ] **Step 1: Update validation tests to express the canonical API**

At the top of `tests/validation-engine.test.js`, import:

```js
import { normalizeConversionOutput } from '../src/conversion/conversion-output.js';
```

Add this helper near the test utilities:

```js
const setOutput = text => normalizeConversionOutput(text, 'set');
```

For every call to `runValidation`, replace:

```js
srxOutput,
```

with:

```js
conversionOutput: setOutput(srxOutput || 'set system host-name validation-fixture'),
```

Replace assertions against `result.filteredOutput` with array assertions against `result.filteredCommands`. The enforce-mode case must assert:

```js
assert(Array.isArray(result.filteredCommands), 'filteredCommands is an array');
assert(!result.filteredCommands.some(command => command.includes('set services idp')), 'filteredCommands excludes IDP command');
```

The warn-only case must assert:

```js
assert(result.filteredCommands === null, 'filteredCommands is null in warn-only mode');
```

Create `tests/conversion-enforcement.test.js`:

```js
import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

import { normalizeConversionOutput, replaceSetCommands } from '../src/conversion/conversion-output.js';
import { runValidation } from '../src/validators/srx-validation-engine.js';

const modelDb = {};
const capacityLimits = {};
const intermediateConfig = {
  security_policies: [],
  zones: [],
  interfaces: [],
  address_objects: [],
};

describe('canonical license enforcement', () => {
  it('detects and removes the command that the former srxCommands typo skipped', () => {
    const output = normalizeConversionOutput({
      commands: [
        'set system host-name edge-1',
        'set services idp active-policy recommended',
      ],
      warnings: [{ type: 'warning', message: 'preserve me' }],
      summary: { policies_converted: 1 },
    }, 'set');

    const result = runValidation({
      intermediateConfig,
      conversionOutput: output,
      targetModel: null,
      srxLicense: 'Base',
      enforceLicense: true,
      modelDb,
      capacityLimits,
      sourceModel: null,
    });
    const filtered = replaceSetCommands(output, result.filteredCommands);

    expect(result.strippedCommands).toEqual(['set services idp active-policy recommended']);
    expect(filtered.commands).toEqual(['set system host-name edge-1']);
    expect(filtered.warnings).toEqual(output.warnings);
    expect(filtered.summary).toEqual(output.summary);
  });

  it('blocks XML and malformed output instead of validating an empty string', () => {
    const xml = normalizeConversionOutput({
      xml: '<configuration><system><host-name>edge-1</host-name></system></configuration>',
    }, 'xml');

    expect(() => runValidation({
      intermediateConfig,
      conversionOutput: xml,
      targetModel: null,
      srxLicense: 'Base',
      modelDb,
      capacityLimits,
      sourceModel: null,
    })).toThrow(/Set Commands/);

    expect(() => runValidation({
      intermediateConfig,
      conversionOutput: { commands: [] },
      targetModel: null,
      srxLicense: 'Base',
      modelDb,
      capacityLimits,
      sourceModel: null,
    })).toThrow(/Canonical conversion output/);
  });

  it('reports an empty filtered command list when enforcement removes everything', () => {
    const output = normalizeConversionOutput({
      commands: ['set services idp active-policy recommended'],
    }, 'set');
    const result = runValidation({
      intermediateConfig,
      conversionOutput: output,
      targetModel: null,
      srxLicense: 'Base',
      enforceLicense: true,
      modelDb,
      capacityLimits,
      sourceModel: null,
    });

    expect(result.filteredCommands).toEqual([]);
    expect(() => replaceSetCommands(output, result.filteredCommands)).toThrow(/at least one command/);
  });

  it('removes every srxCommands read and write from the conversion hook', () => {
    const source = fs.readFileSync(new URL('../public/hooks/useConversion.js', import.meta.url), 'utf8');

    expect(source).not.toContain('srxCommands');
    expect(source).toContain('conversionOutput: srxOutput');
    expect(source).toContain('replaceSetCommands(srxOutput, result.filteredCommands)');
    expect(source).toContain('result.filteredCommands.length === 0');
    expect(source).toContain("conversionDispatch({ type: 'CLEAR_OUTPUT' })");
  });
});
```

- [ ] **Step 2: Run validation and enforcement tests and verify RED**

Run:

```bash
node tests/validation-engine.test.js
npx vitest run tests/conversion-enforcement.test.js
```

Expected: FAIL because `runValidation` still accepts `srxOutput`, returns `filteredOutput`, and `useConversion` still reads and writes `srxCommands`.

- [ ] **Step 3: Change the validation engine to canonical input**

Add to `src/validators/srx-validation-engine.js`:

```js
import { getSetCommands } from '../conversion/conversion-output.js';
```

Change the JSDoc parameter and return definitions to:

```js
 * @param {import('../conversion/conversion-output.js').ConversionOutput} opts.conversionOutput
 * @returns {{ findings: Object[], strippedCommands: string[], filteredCommands: string[]|null }}
```

Change the function parameter and command extraction:

```js
export function runValidation({
  intermediateConfig,
  conversionOutput,
  targetModel,
  srxLicense,
  enforceLicense = false,
  modelDb,
  capacityLimits,
  sourceModel,
}) {
  const commands = getSetCommands(conversionOutput);
```

Replace `filteredOutput` construction and return with:

```js
const enforcedCommands =
  enforceLicense && strippedCommands.length > 0
    ? filteredCommands
    : null;

return {
  findings: allFindings,
  strippedCommands,
  filteredCommands: enforcedCommands,
};
```

- [ ] **Step 4: Update the conversion hook to replace canonical commands**

Add to `public/hooks/useConversion.js`:

```js
import {
  ConversionOutputError,
  replaceSetCommands,
} from '../../src/conversion/conversion-output.js';
```

Extend `formatJunosSerializationError` before its generic branch:

```js
if (error instanceof ConversionOutputError) {
  return `${prefix} blocked: ${error.reason}`;
}
```

Inside `handleValidate`, change the guard to throw safely for missing output:

```js
if (!srxOutput) {
  uiDispatch({ type: 'SET_FIELD', field: 'error', value: 'Validation blocked: No SRX output is available.' });
  return;
}
```

Call validation with:

```js
const result = runValidation({
  intermediateConfig,
  conversionOutput: srxOutput,
  targetModel,
  srxLicense,
  enforceLicense,
  modelDb: SRX_MODELS,
  capacityLimits: SRX_CAPACITY_LIMITS,
  sourceModel: null,
});
```

Replace the `filteredOutput` block with:

```js
if (result.filteredCommands !== null) {
  if (result.filteredCommands.length === 0) {
    conversionDispatch({ type: 'CLEAR_OUTPUT' });
    conversionDispatch({ type: 'SET_FIELD', field: 'convertWarnings', value: newWarnings });
    conversionDispatch({ type: 'SET_FIELD', field: 'validationFindings', value: result.findings });
    uiDispatch({
      type: 'SET_FIELD',
      field: 'error',
      value: 'License enforcement blocked all generated commands; output, export, and push have been disabled.',
    });
    return;
  }
  const updatedOutput = replaceSetCommands(srxOutput, result.filteredCommands);
  conversionDispatch({
    type: 'SET_CONVERSION_RESULT',
    output: updatedOutput,
    warnings: newWarnings,
    summary: updatedOutput.summary ?? conversionState.conversionSummary,
    validationFindings: result.findings,
  });
} else {
  conversionDispatch({ type: 'SET_FIELD', field: 'convertWarnings', value: newWarnings });
  conversionDispatch({ type: 'SET_FIELD', field: 'validationFindings', value: result.findings });
}
```

Replace the catch message with:

```js
uiDispatch({
  type: 'SET_FIELD',
  field: 'error',
  value: formatJunosSerializationError(err, 'Validation'),
});
```

- [ ] **Step 5: Verify focused validation behavior is GREEN**

Run:

```bash
node tests/validation-engine.test.js
npx vitest run tests/conversion-output.test.js tests/conversion-enforcement.test.js tests/conversion-security.test.js
```

Expected: all validation-engine assertions and all four Vitest files pass.

- [ ] **Step 6: Commit canonical validation and enforcement**

```bash
git add src/validators/srx-validation-engine.js public/hooks/useConversion.js tests/validation-engine.test.js tests/conversion-enforcement.test.js
git commit -m "fix: validate canonical conversion output"
```

---

### Task 4: Normalize project persistence and legacy output

**Files:**
- Modify: `public/utils/project-io.js:1-140`
- Create: `tests/project-io.test.js`

**Interfaces:**
- Consumes: `normalizeConversionOutput(rawOutput, formatHint)` from Task 1.
- Produces: FPIC project format version 3 with canonical `state.srxOutput`; imports version 2 strings and pre-discriminant objects.

- [ ] **Step 1: Write failing versioning and migration tests**

Create `tests/project-io.test.js`:

```js
import { describe, expect, it } from 'vitest';

import { buildProjectPayload, validateProjectFile } from '../public/utils/project-io.js';

const baseState = {
  configText: 'set system host-name source',
  intermediateConfig: { metadata: {} },
};

function legacyProject(srxOutput, outputFormat = 'set') {
  return {
    fpic_version: 2,
    name: 'legacy',
    savedAt: '2026-07-11T00:00:00.000Z',
    state: { ...baseState, srxOutput, outputFormat },
  };
}

describe('canonical project output', () => {
  it('writes version 3 projects with canonical output', () => {
    const payload = buildProjectPayload({
      ...baseState,
      srxOutput: { format: 'set', commands: ['set system host-name edge-1'] },
      outputFormat: 'set',
    }, 'canonical');

    expect(payload.fpic_version).toBe(3);
    expect(payload.state.srxOutput).toEqual({
      format: 'set',
      commands: ['set system host-name edge-1'],
    });
  });

  it('migrates version 2 string, set-object, and XML-object output', () => {
    const stringResult = validateProjectFile(legacyProject('set system host-name edge-1'));
    const objectResult = validateProjectFile(legacyProject({
      commands: ['set system host-name edge-2'],
      warnings: [],
    }));
    const xmlResult = validateProjectFile(legacyProject({
      xml: '<configuration><system><host-name>edge-3</host-name></system></configuration>',
    }, 'xml'));

    expect(stringResult.valid).toBe(true);
    expect(stringResult.project.state.srxOutput.format).toBe('set');
    expect(objectResult.project.state.srxOutput).toMatchObject({ format: 'set' });
    expect(xmlResult.project.state.srxOutput).toMatchObject({ format: 'xml' });
    expect(stringResult.project.fpic_version).toBe(3);
  });

  it.each([
    { commands: [] },
    { srxCommands: 'set system host-name bypass' },
    { commands: ['set system host-name edge-1'], xml: '<configuration/>' },
  ])('rejects malformed legacy output: %j', srxOutput => {
    const result = validateProjectFile(legacyProject(srxOutput));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/conversion output/i);
  });

  it('preserves null output', () => {
    const result = validateProjectFile(legacyProject(null));

    expect(result.valid).toBe(true);
    expect(result.project.state.srxOutput).toBeNull();
  });
});
```

- [ ] **Step 2: Run the migration tests and verify RED**

Run:

```bash
npx vitest run tests/project-io.test.js
```

Expected: FAIL because the current project version is 2 and no output migration or rejection exists.

- [ ] **Step 3: Implement project version 3 migration**

At the top of `public/utils/project-io.js`, add:

```js
import {
  ConversionOutputError,
  assertConversionOutput,
  normalizeConversionOutput,
} from '../../src/conversion/conversion-output.js';
```

Change:

```js
const CURRENT_VERSION = 2;
```

to:

```js
const CURRENT_VERSION = 3;
```

In `buildProjectPayload`, validate non-null output before assigning state:

```js
for (const key of STATE_KEYS) {
  state[key] = stateBag[key] ?? STATE_DEFAULTS[key];
}
if (state.srxOutput !== null) {
  state.srxOutput = assertConversionOutput(state.srxOutput);
  state.outputFormat = state.srxOutput.format;
}
```

In `validateProjectFile`, replace the direct migration call with:

```js
let project;
try {
  project = migrateProject(json);
} catch (error) {
  if (error instanceof ConversionOutputError) {
    return { valid: false, error: `Project conversion output is invalid: ${error.reason}` };
  }
  throw error;
}

return { valid: true, project, warnings };
```

At the end of `migrateProject`, before `return p`, add:

```js
if (p.state.srxOutput !== null) {
  p.state.srxOutput = normalizeConversionOutput(
    p.state.srxOutput,
    p.state.outputFormat,
  );
  p.state.outputFormat = p.state.srxOutput.format;
}

if (p.fpic_version < 3) {
  p.fpic_version = 3;
}
```

Remove the obsolete future-migration comment for version 3.

- [ ] **Step 4: Run migration and reducer tests and verify GREEN**

Run:

```bash
npx vitest run tests/project-io.test.js tests/context-reducers.test.js tests/conversion-output.test.js
```

Expected: all three files pass.

- [ ] **Step 5: Commit canonical project persistence**

```bash
git add public/utils/project-io.js tests/project-io.test.js
git commit -m "fix: normalize saved conversion output"
```

---

### Task 5: Route rendering, export, batch, diff, and push through the contract

**Files:**
- Modify: `public/components/SRXOutput.jsx:12-190`
- Modify: `public/hooks/usePush.js:13-111,542`
- Modify: `public/components/ConfigDiff.jsx:10-125`
- Modify: `public/utils/pdf-report-generator.js:527-541`
- Modify: `public/components/ConversionReport.jsx:582-1004`
- Modify: `public/components/BatchMigrationPanel.jsx:8-121`
- Modify: `public/components/layout/WorkflowStepper.jsx:1-177`
- Create: `tests/conversion-consumers.test.js`

**Interfaces:**
- Consumes: `getConversionOutputText(output)`, `getSetCommands(output)`, and `hasConversionOutput(output)` from Task 1; canonical engine envelopes from Task 2.
- Produces: all user-visible and device-facing output derived from one validated object; batch conversion correctly reads `convertResult.output`.

- [ ] **Step 1: Add a failing consumer contract regression test**

Create `tests/conversion-consumers.test.js`:

```js
import fs from 'node:fs';

import { describe, expect, it } from 'vitest';

const read = relativePath => fs.readFileSync(new URL(`../${relativePath}`, import.meta.url), 'utf8');

describe('canonical conversion output consumers', () => {
  it('routes render, push, diff, PDF, report, and workflow checks through shared helpers', () => {
    expect(read('public/components/SRXOutput.jsx')).toContain('getConversionOutputText(output)');
    expect(read('public/hooks/usePush.js')).toContain('getConversionOutputText(srxOutput)');
    expect(read('public/hooks/usePush.js')).toContain('hasConversionOutput(srxOutput)');
    expect(read('public/components/ConfigDiff.jsx')).toContain('getConversionOutputText(currentOutput)');
    expect(read('public/utils/pdf-report-generator.js')).toContain('getConversionOutputText(srxOutput)');
    expect(read('public/components/ConversionReport.jsx')).toContain('getSetCommands(srxOutput)');
    expect(read('public/components/layout/WorkflowStepper.jsx')).toContain('hasConversionOutput(srxOutput)');
  });

  it('makes batch conversion consume the engine envelope', () => {
    const source = read('public/components/BatchMigrationPanel.jsx');

    expect(source).toContain('getConversionOutputText(convertResult.output)');
    expect(source).toContain('convertResult.output.warnings');
    expect(source).not.toContain('(convertResult.commands || [])');
  });

  it('removes permissive output fallbacks from security-sensitive paths', () => {
    const combined = [
      read('public/components/SRXOutput.jsx'),
      read('public/hooks/usePush.js'),
      read('public/components/ConfigDiff.jsx'),
      read('public/utils/pdf-report-generator.js'),
    ].join('\n');

    expect(combined).not.toMatch(/srxOutput\?\.srxCommands|srxOutput\.srxCommands/);
    expect(combined).not.toContain("(srxOutput.commands || []).join('\\n')");
    expect(combined).not.toContain("output.xml || ''");
  });
});
```

- [ ] **Step 2: Run the consumer test and verify RED**

Run:

```bash
npx vitest run tests/conversion-consumers.test.js
```

Expected: FAIL because consumers still read `commands`/`xml` directly and batch reads the wrong envelope level.

- [ ] **Step 3: Update rendering, export, diff, and push extraction**

Add the relevant imports:

```js
import {
  getConversionOutputText,
  getSetCommands,
  hasConversionOutput,
} from '../../src/conversion/conversion-output.js';
```

Use the correct relative depth for each file (`../../../src/...` from `public/components/layout/WorkflowStepper.jsx`).

Make these exact replacements:

In `SRXOutput.jsx`, replace `getOutputText` with:

```js
const getOutputText = useCallback(() => getConversionOutputText(output), [output]);
```

Use `getSetCommands(output)` in both Terraform and Ansible click handlers. The component's existing `!output` early return remains, so the helper is called only for present state.

In `usePush.js`, replace `getConfigText` with:

```js
const getConfigText = useCallback(() => {
  const text = getConversionOutputText(srxOutput);
  return restoreForExport(text, sanitizationTable);
}, [srxOutput, sanitizationTable]);
```

Return:

```js
hasSrxOutput: hasConversionOutput(srxOutput),
```

In `ConfigDiff.jsx`, replace `currentText` with:

```js
const currentText = useMemo(
  () => currentOutput ? getConversionOutputText(currentOutput) : '',
  [currentOutput],
);
```

In `pdf-report-generator.js`, replace `buildFinalOutput` extraction with:

```js
const text = getConversionOutputText(srxOutput);
const isXml = srxOutput.format === 'xml';
```

In `WorkflowStepper.jsx`, define:

```js
const hasOutput = hasConversionOutput(srxOutput);
```

and use `hasOutput` for conditional display and button disabling instead of truthiness checks.

- [ ] **Step 4: Update reports and batch conversion**

In `ConversionReport.jsx`, add `getSetCommands` and replace each direct `srxOutput.commands` read with:

```js
const commands = srxOutput?.format === 'set' ? getSetCommands(srxOutput) : [];
```

Use `commands.length` for totals and rollback generation. XML reports retain zero set-command totals and continue showing XML through the PDF output path.

In `BatchMigrationPanel.jsx`, import `getConversionOutputText` and replace:

```js
const srxOutput = (convertResult.commands || []).join('\n');
const warningCount = (convertResult.warnings || []).length;
```

with:

```js
const srxOutput = getConversionOutputText(convertResult.output);
const warningCount = (convertResult.output.warnings || []).length;
```

- [ ] **Step 5: Run the consumer and build checks**

Run:

```bash
npx vitest run tests/conversion-consumers.test.js tests/conversion-output.test.js tests/conversion-enforcement.test.js
npm run build
```

Expected: all focused tests pass and Vite builds successfully.

- [ ] **Step 6: Commit consumer migration**

```bash
git add public/components/SRXOutput.jsx public/hooks/usePush.js public/components/ConfigDiff.jsx public/utils/pdf-report-generator.js public/components/ConversionReport.jsx public/components/BatchMigrationPanel.jsx public/components/layout/WorkflowStepper.jsx tests/conversion-consumers.test.js
git commit -m "fix: consume canonical output everywhere"
```

---

### Task 6: Wire CI, document the contract, and run the complete gate

**Files:**
- Modify: `.github/workflows/ci.yml:25-38`
- Modify: `README.md`

**Interfaces:**
- Consumes: all tests and production interfaces from Tasks 1-5.
- Produces: CI coverage for every new Vitest suite and concise developer documentation for the canonical output shape.

- [ ] **Step 1: Add the new Vitest files to CI**

Extend the `Run Vitest suites` command in `.github/workflows/ci.yml` with:

```yaml
          tests/conversion-output.test.js
          tests/conversion-enforcement.test.js
          tests/project-io.test.js
          tests/conversion-consumers.test.js
```

- [ ] **Step 2: Document the public result contract**

Add this paragraph to the README conversion/development section:

```markdown
Generated SRX configuration uses a runtime-validated discriminated output object: set output is `{ format: 'set', commands: string[] }`, while XML output is `{ format: 'xml', xml: string }`. Consumers must use `src/conversion/conversion-output.js`; missing, empty, mixed, or malformed output is a blocking error and must never be converted to an empty fallback.
```

- [ ] **Step 3: Run all Vitest suites**

Run:

```bash
npx vitest run \
  tests/context-reducers.test.js \
  tests/triage.test.js \
  tests/workflow-steps.test.js \
  tests/junos-serialization.test.js \
  tests/junos-validation.test.js \
  tests/srx-injection-defense.test.js \
  tests/conversion-security.test.js \
  tests/conversion-output.test.js \
  tests/conversion-enforcement.test.js \
  tests/project-io.test.js \
  tests/conversion-consumers.test.js
```

Expected: every Vitest file and assertion passes.

- [ ] **Step 4: Run all self-contained JavaScript suites**

Run:

```bash
for test_file in tests/*.test.js; do
  if rg -q "from 'vitest'" "$test_file"; then
    continue
  fi
  node "$test_file"
done
```

Expected: every self-contained JavaScript suite reports zero failures.

- [ ] **Step 5: Run bridge, build, audit, and source-contract checks**

Run:

```bash
venv/bin/python -m unittest discover -s tools/pyez-bridge/tests -v
npm run build
npm audit --audit-level=high
venv/bin/pip check
! rg -n "srxOutput\?\.srxCommands|srxOutput\.srxCommands|srxCommands: result" public src
! rg -n "srxOutput\?\.commands|srxOutput\.commands" public src
git diff --check main...HEAD
git status --short
```

Expected: 33 bridge tests pass, Vite builds, both dependency checks report no problems, both forbidden property scans are empty, the diff has no whitespace errors, and status shows only the intended README/CI changes before commit.

- [ ] **Step 6: Commit CI and documentation**

```bash
git add .github/workflows/ci.yml README.md
git commit -m "test: enforce canonical output contract"
```

- [ ] **Step 7: Review the final branch scope**

Run:

```bash
git status --short --branch
git log --oneline main..HEAD
git diff --stat main...HEAD
git diff --check main...HEAD
```

Expected: clean branch, one design commit plus the plan and implementation commits, only issue #8 files in the diff, and no whitespace errors.

---

### Task 7: Publish, pass CI, merge, and clean the worktree

**Files:**
- No source changes expected.

**Interfaces:**
- Consumes: verified branch from Task 6 and the repository's standard GitHub workflow.
- Produces: a merged PR closing issue #8, successful post-merge `main` CI, and no remaining local/remote issue branch or worktree.

- [ ] **Step 1: Perform the final pre-push verification**

Re-run the exact commands from Task 6 Steps 3-5 after the final commit.

Expected: all tests, build, audits, source scans, and diff checks pass from committed `HEAD`.

- [ ] **Step 2: Push the issue branch**

```bash
git push -u origin agent/issue-8-canonical-output
```

- [ ] **Step 3: Open a ready PR linked to issue #8**

Use title:

```text
fix: enforce canonical conversion output
```

The PR body must summarize the runtime contract, fail-closed validation/enforcement, consumer migration, project migration, batch fix, and verification evidence, and end with:

```text
Closes #8
```

- [ ] **Step 4: Inspect and pass PR CI**

Verify the PR is ready, mergeable, linked to issue #8, and contains only expected files. Watch both `Web` and `PyEZ bridge` checks until they pass. If a check fails, use `superpowers:systematic-debugging` and `github:gh-fix-ci` before making changes.

- [ ] **Step 5: Squash-merge and verify closure**

Squash-merge the PR, delete the remote branch, fast-forward the primary checkout to `origin/main`, and verify issue #8 is closed.

- [ ] **Step 6: Verify post-merge CI and clean isolation**

Watch the push-triggered `main` CI run until both jobs pass. Then remove `.worktrees/issue-8-canonical-output`, prune worktrees, delete the local feature branch, and verify the remote feature branch is absent.
