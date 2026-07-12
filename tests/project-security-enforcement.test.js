import { readFileSync, readdirSync } from 'node:fs';
import { extname, relative, resolve } from 'node:path';
import { parse } from 'acorn';
import { transformWithOxc } from 'vite';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const SERIALIZATION_APPROVED = new Set([
  'public/utils/project-security.js',
  'public/utils/project-crypto.js',
]);
const DOWNLOAD_APPROVED = new Set([
  'public/hooks/useProject.js',
]);

function publicJavaScriptFiles(directory = resolve(ROOT, 'public')) {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap(entry => {
      const absolute = resolve(directory, entry.name);
      return entry.isDirectory() ? publicJavaScriptFiles(absolute) : [absolute];
    })
    .filter(filename => ['.js', '.jsx'].includes(extname(filename)))
    .map(filename => relative(ROOT, filename).replaceAll('\\', '/'))
    .sort();
}

const PROJECT_EXPORT_FUNCTIONS = new Set([
  'assertSanitizedProjectSafe',
  'boundedProjectStringify',
  'buildProjectCore',
  'buildProjectPayload',
  'encryptReversiblePayload',
  'serializeProjectExport',
]);
const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function walkAst(node, visitor) {
  if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;
  visitor(node);
  for (const [key, value] of Object.entries(node)) {
    if (['loc', 'start', 'end'].includes(key)) continue;
    if (Array.isArray(value)) {
      for (const child of value) walkAst(child, visitor);
    } else {
      walkAst(value, visitor);
    }
  }
}

function decodeVlq(segment) {
  const values = [];
  let value = 0;
  let shift = 0;
  for (const character of segment) {
    const digit = BASE64.indexOf(character);
    if (digit < 0) throw new Error('Invalid source map.');
    value += (digit & 31) << shift;
    if (digit & 32) {
      shift += 5;
      continue;
    }
    values.push(value & 1 ? -(value >> 1) : value >> 1);
    value = 0;
    shift = 0;
  }
  return values;
}

function decodeSourceMap(map) {
  const decoded = [];
  let source = 0;
  let originalLine = 0;
  let originalColumn = 0;
  let name = 0;
  for (const line of map.mappings.split(';')) {
    let generatedColumn = 0;
    const entries = [];
    for (const encoded of line.split(',').filter(Boolean)) {
      const values = decodeVlq(encoded);
      generatedColumn += values[0];
      if (values.length >= 4) {
        source += values[1];
        originalLine += values[2];
        originalColumn += values[3];
        if (values.length === 5) name += values[4];
        entries.push({ generatedColumn, source, originalLine, originalColumn, name });
      }
    }
    decoded.push(entries);
  }
  return decoded;
}

function mappedLine(node, decodedMap) {
  if (!decodedMap) return node.loc.start.line;
  const entries = decodedMap[node.loc.start.line - 1] || [];
  let closest;
  for (const entry of entries) {
    if (entry.generatedColumn > node.loc.start.column) break;
    closest = entry;
  }
  return (closest || entries[0])?.originalLine + 1 || node.loc.start.line;
}

function staticPropertyName(member, strings) {
  const property = member.type === 'Property' ? member.key : member.property;
  if (!member.computed && property.type === 'Identifier') {
    return property.name;
  }
  return constantString(property, strings);
}

function constantString(node, strings) {
  if (!node) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier') return strings.get(node.name);
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0].value.cooked;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = constantString(node.left, strings);
    const right = constantString(node.right, strings);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}

function objectProperty(object, name, strings) {
  if (object?.type !== 'ObjectExpression') return undefined;
  return object.properties.find(property => (
    property.type === 'Property'
      && property.kind === 'init'
      && staticPropertyName(property, strings) === name
  ));
}

function containsProperty(node, name, strings) {
  let found = false;
  walkAst(node, child => {
    if (child.type === 'Property' && staticPropertyName(child, strings) === name) found = true;
  });
  return found;
}

function literalValue(node) {
  return node?.type === 'Literal' ? node.value : undefined;
}

function isSanitizedV5WithTable(node, strings) {
  if (node?.type !== 'ObjectExpression') return false;
  const version = objectProperty(node, 'fpic_version', strings);
  const security = objectProperty(node, 'security', strings);
  const state = objectProperty(node, 'state', strings);
  const mode = objectProperty(security?.value, 'mode', strings);
  return literalValue(version?.value) === 5
    && literalValue(mode?.value) === 'sanitized'
    && containsProperty(state?.value, 'sanitizationTable', strings);
}

function isProjectContext(relativePath, source, ast) {
  if (/project/i.test(relativePath) || source.includes('.fpic')) return true;
  let projectImport = false;
  walkAst(ast, node => {
    if (node.type === 'ImportDeclaration'
        && /project-(?:security|crypto|io)/.test(String(node.source.value))) {
      projectImport = true;
    }
  });
  return projectImport;
}

function addKind(bindings, name, ...kinds) {
  if (!name) return false;
  const current = bindings.get(name) || new Set();
  const before = current.size;
  for (const kind of kinds) current.add(kind);
  bindings.set(name, current);
  return current.size !== before;
}

function propertyKinds(sourceKinds, property) {
  const kinds = new Set();
  if (sourceKinds.has('global-namespace') && property === 'JSON') {
    kinds.add('json-namespace');
  }
  if (sourceKinds.has('global-namespace') && property === 'Blob') {
    kinds.add('blob-constructor');
  }
  if (sourceKinds.has('global-namespace') && property === 'URL') {
    kinds.add('url-namespace');
  }
  if (sourceKinds.has('json-namespace') && property === 'stringify') {
    kinds.add('json-stringify');
  }
  if (sourceKinds.has('url-namespace') && property === 'createObjectURL') {
    kinds.add('url-create-object-url');
  }
  if (sourceKinds.has('project')
      && ['serialized', 'security', 'state', 'payload', 'envelope'].includes(property)) {
    kinds.add('project');
  }
  return kinds;
}

function expressionKinds(node, bindings, strings, projectContext) {
  const kinds = new Set();
  if (!node) return kinds;
  if (['AwaitExpression', 'ChainExpression'].includes(node.type)) {
    return expressionKinds(node.argument ?? node.expression, bindings, strings, projectContext);
  }
  if (node.type === 'Identifier') {
    for (const kind of bindings.get(node.name) || []) kinds.add(kind);
    if (node.name === 'JSON') kinds.add('json-namespace');
    if (node.name === 'Blob') kinds.add('blob-constructor');
    if (node.name === 'URL') kinds.add('url-namespace');
    if (node.name === 'globalThis') kinds.add('global-namespace');
    if (projectContext
        && /^(?:project|stateBag|projectPayload|aad(?:Object|Bytes)?|envelope|candidate|serialized|exportResult|result)$/i.test(node.name)) {
      kinds.add('project');
    }
    return kinds;
  }
  if (node.type === 'MemberExpression') {
    const sourceKinds = expressionKinds(node.object, bindings, strings, projectContext);
    const property = staticPropertyName(node, strings);
    for (const kind of propertyKinds(sourceKinds, property)) kinds.add(kind);
    return kinds;
  }
  if (node.type === 'CallExpression') {
    const calleeKinds = expressionKinds(node.callee, bindings, strings, projectContext);
    if (calleeKinds.has('project-export-function')) kinds.add('project');
    if (calleeKinds.has('json-stringify')
        && expressionKinds(node.arguments[0], bindings, strings, projectContext).has('project')) {
      kinds.add('project');
    }
    return kinds;
  }
  if (node.type === 'NewExpression') {
    const calleeKinds = expressionKinds(node.callee, bindings, strings, projectContext);
    const projectData = node.arguments.some(argument => (
      expressionKinds(argument, bindings, strings, projectContext).has('project')
    ));
    if (calleeKinds.has('blob-constructor') && projectData) kinds.add('project-blob');
    return kinds;
  }
  if (node.type === 'ArrayExpression') {
    if (node.elements.some(element => (
      expressionKinds(element, bindings, strings, projectContext).has('project')
    ))) kinds.add('project');
    return kinds;
  }
  if (node.type === 'ObjectExpression') {
    if (objectProperty(node, 'fpic_version', strings)
        && (objectProperty(node, 'state', strings) || objectProperty(node, 'security', strings))) {
      kinds.add('project');
    }
    if (node.properties.some(property => (
      property.type === 'Property'
        && expressionKinds(property.value, bindings, strings, projectContext).has('project')
    ))) kinds.add('project');
  }
  return kinds;
}

function bindPattern(pattern, sourceKinds, bindings, strings) {
  let changed = false;
  if (pattern.type === 'Identifier') {
    changed = addKind(bindings, pattern.name, ...sourceKinds) || changed;
  } else if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties) {
      if (property.type !== 'Property') continue;
      const name = staticPropertyName(property, strings);
      changed = bindPattern(
        property.value,
        propertyKinds(sourceKinds, name),
        bindings,
        strings,
      ) || changed;
    }
  }
  return changed;
}

function collectBindings(ast, strings, projectContext) {
  const bindings = new Map();
  const declarators = [];
  const assignments = [];
  walkAst(ast, node => {
    if (node.type === 'ImportDeclaration') {
      for (const specifier of node.specifiers) {
        const imported = specifier.imported?.name;
        if (PROJECT_EXPORT_FUNCTIONS.has(imported)) {
          addKind(bindings, specifier.local.name, 'project-export-function');
        }
      }
    }
    if (node.type === 'VariableDeclarator') declarators.push(node);
    if (node.type === 'AssignmentExpression' && node.operator === '=') assignments.push(node);
  });

  let changed = true;
  while (changed) {
    changed = false;
    for (const declarator of declarators) {
      changed = bindPattern(
        declarator.id,
        expressionKinds(declarator.init, bindings, strings, projectContext),
        bindings,
        strings,
      ) || changed;
    }
    for (const assignment of assignments) {
      changed = bindPattern(
        assignment.left,
        expressionKinds(assignment.right, bindings, strings, projectContext),
        bindings,
        strings,
      ) || changed;
    }
  }
  return bindings;
}

function collectConstantStrings(ast) {
  const strings = new Map();
  const declarations = [];
  walkAst(ast, node => {
    if (node.type === 'VariableDeclaration' && node.kind === 'const') {
      declarations.push(...node.declarations);
    }
  });
  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of declarations) {
      if (declaration.id.type !== 'Identifier') continue;
      const value = constantString(declaration.init, strings);
      if (value !== undefined && strings.get(declaration.id.name) !== value) {
        strings.set(declaration.id.name, value);
        changed = true;
      }
    }
  }
  return strings;
}

async function analyzeSource(source, relativePath) {
  const transformed = extname(relativePath) === '.jsx'
    ? await transformWithOxc(source, relativePath, { lang: 'jsx', sourcemap: true })
    : { code: source, map: null };
  const ast = parse(transformed.code, {
    ecmaVersion: 'latest',
    sourceType: 'module',
    locations: true,
    allowAwaitOutsideFunction: true,
  });
  const strings = collectConstantStrings(ast);
  const projectContext = isProjectContext(relativePath, source, ast);
  const bindings = collectBindings(ast, strings, projectContext);
  const decodedMap = transformed.map ? decodeSourceMap(transformed.map) : null;
  const violations = new Set();
  const report = (node, operation) => {
    violations.add(`${relativePath}:${mappedLine(node, decodedMap)}: ${operation}`);
  };

  walkAst(ast, node => {
    if (isSanitizedV5WithTable(node, strings)) {
      report(node, 'sanitized v5 payload includes sanitizationTable');
    }
    if (node.type === 'Property'
        && staticPropertyName(node, strings) === 'mode'
        && literalValue(node.value) === 'reversible') {
      report(node, 'plaintext reversible project mode');
    }
    if (node.type === 'CallExpression') {
      const calleeKinds = expressionKinds(node.callee, bindings, strings, projectContext);
      if (!SERIALIZATION_APPROVED.has(relativePath)
          && calleeKinds.has('json-stringify')
          && expressionKinds(node.arguments[0], bindings, strings, projectContext)
            .has('project')) {
        report(node, 'project serialization');
      }
      if (!DOWNLOAD_APPROVED.has(relativePath)
          && calleeKinds.has('url-create-object-url')
          && expressionKinds(node.arguments[0], bindings, strings, projectContext)
            .has('project-blob')) {
        report(node, 'project object URL creation');
      }
    }
    if (node.type === 'NewExpression'
        && !DOWNLOAD_APPROVED.has(relativePath)
        && expressionKinds(node.callee, bindings, strings, projectContext)
          .has('blob-constructor')
        && node.arguments.some(argument => (
          expressionKinds(argument, bindings, strings, projectContext).has('project')
        ))) {
      report(node, 'project Blob construction');
    }
  });
  return [...violations].sort((left, right) => {
    const leftLine = Number(left.split(':').at(-2));
    const rightLine = Number(right.split(':').at(-2));
    return leftLine - rightLine || left.localeCompare(right);
  });
}

async function analyzeRepository() {
  const violations = [];
  for (const relativePath of publicJavaScriptFiles()) {
    violations.push(...await analyzeSource(
      readFileSync(resolve(ROOT, relativePath), 'utf8'),
      relativePath,
    ));
  }
  return violations;
}

const BYPASS_FIXTURES = [
  {
    label: 'direct project serialization',
    relativePath: 'public/utils/project-direct.js',
    source: `const project = { fpic_version: 5, state: {} };

JSON.stringify(project);`,
    expected: ['public/utils/project-direct.js:3: project serialization'],
  },
  {
    label: 'locally aliased project serialization',
    relativePath: 'public/utils/project-alias.js',
    source: `const encode = JSON.stringify;
const project = { fpic_version: 5, state: {} };
encode(project);`,
    expected: ['public/utils/project-alias.js:3: project serialization'],
  },
  {
    label: 'computed constant-property project serialization',
    relativePath: 'public/utils/project-computed.js',
    source: `const method = 'stringify';
const project = { fpic_version: 5, state: {} };
JSON[method](project);`,
    expected: ['public/utils/project-computed.js:3: project serialization'],
  },
  {
    label: 'JSX project serialization mapped to its original line',
    relativePath: 'public/components/ProjectBypass.jsx',
    source: `const Preview = () => <div>Project</div>;
const project = { fpic_version: 5, state: {} };
JSON.stringify(project);`,
    expected: ['public/components/ProjectBypass.jsx:3: project serialization'],
  },
  {
    label: 'direct project Blob construction',
    relativePath: 'public/utils/project-blob.js',
    source: `import { serializeProjectExport } from './project-security.js';
const result = await serializeProjectExport(stateBag, 'name');
const serialized = result.serialized;
new Blob([serialized]);`,
    expected: ['public/utils/project-blob.js:4: project Blob construction'],
  },
  {
    label: 'aliased project export and Blob construction',
    relativePath: 'public/utils/project-blob-alias.js',
    source: `import { serializeProjectExport as exportProject } from './project-security.js';
const BlobAlias = Blob;
const result = await exportProject(stateBag, 'name');
const serialized = result.serialized;
new BlobAlias([serialized]);`,
    expected: ['public/utils/project-blob-alias.js:5: project Blob construction'],
  },
  {
    label: 'locally aliased project export function',
    relativePath: 'public/utils/project-export-local-alias.js',
    source: `import { serializeProjectExport } from './project-security.js';
const exportAlias = serializeProjectExport;
const result = await exportAlias(stateBag, 'name');
new Blob([result.serialized]);`,
    expected: [
      'public/utils/project-export-local-alias.js:4: project Blob construction',
    ],
  },
  {
    label: 'computed constant-property project Blob construction',
    relativePath: 'public/utils/project-blob-computed.js',
    source: `import { serializeProjectExport } from './project-security.js';
const result = await serializeProjectExport(stateBag, 'name');
const constructorName = 'Blob';
new globalThis[constructorName]([result.serialized]);`,
    expected: [
      'public/utils/project-blob-computed.js:4: project Blob construction',
    ],
  },
  {
    label: 'direct project object URL creation',
    relativePath: 'public/utils/project-url-direct.js',
    source: `import { serializeProjectExport } from './project-security.js';
const result = await serializeProjectExport(stateBag, 'name');
const projectBlob = new Blob([result.serialized]);
URL.createObjectURL(projectBlob);`,
    expected: [
      'public/utils/project-url-direct.js:3: project Blob construction',
      'public/utils/project-url-direct.js:4: project object URL creation',
    ],
  },
  {
    label: 'locally aliased project object URL creation',
    relativePath: 'public/utils/project-url-alias.js',
    source: `import { serializeProjectExport } from './project-security.js';
const result = await serializeProjectExport(stateBag, 'name');
const projectBlob = new Blob([result.serialized]);
const makeUrl = URL.createObjectURL;
makeUrl(projectBlob);`,
    expected: [
      'public/utils/project-url-alias.js:3: project Blob construction',
      'public/utils/project-url-alias.js:5: project object URL creation',
    ],
  },
  {
    label: 'computed project object URL creation',
    relativePath: 'public/utils/project-url.js',
    source: `import { serializeProjectExport } from './project-security.js';
const result = await serializeProjectExport(stateBag, 'name');
const projectBlob = new Blob([result.serialized]);
const method = 'createObjectURL';
URL[method](projectBlob);`,
    expected: [
      'public/utils/project-url.js:3: project Blob construction',
      'public/utils/project-url.js:5: project object URL creation',
    ],
  },
  {
    label: 'sanitized v5 payload retaining a restoration table',
    relativePath: 'public/utils/project-table.js',
    source: `const candidate = {
  fpic_version: 5,
  security: { mode: 'sanitized' },
  state: { sanitizationTable: [{ original: 'secret' }] },
};
JSON.stringify(candidate);`,
    expected: [
      'public/utils/project-table.js:1: sanitized v5 payload includes sanitizationTable',
      'public/utils/project-table.js:6: project serialization',
    ],
  },
];

describe('project export security enforcement analyzer', () => {
  it.each(BYPASS_FIXTURES)('rejects $label', async fixture => {
    await expect(analyzeSource(fixture.source, fixture.relativePath))
      .resolves.toEqual(fixture.expected);
  });
});

describe('project export security enforcement', () => {
  it('allows project serialization and download only at approved boundaries', async () => {
    expect(await analyzeRepository()).toEqual([]);
  });

  it('does not expose plaintext reversible project mode', () => {
    for (const relativePath of publicJavaScriptFiles()) {
      const source = readFileSync(resolve(ROOT, relativePath), 'utf8');
      expect(source, relativePath).not.toMatch(/mode\s*:\s*['\"]reversible['\"]/);
    }
  });
});
