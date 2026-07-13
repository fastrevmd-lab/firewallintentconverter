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
const DOWNLOAD_APPROVED_PATH = 'public/hooks/useProject.js';
const DOWNLOAD_APPROVED_FUNCTION = 'downloadValidatedProject';

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

function staticPropertyName(member, model) {
  const property = member.type === 'Property' ? member.key : member.property;
  if (!member.computed && property.type === 'Identifier') {
    return property.name;
  }
  return constantString(property, model);
}

function resolveBinding(model, node, name) {
  let scope = model.nodeScopes.get(node) || model.rootScope;
  while (scope) {
    if (scope.bindings.has(name)) return scope.bindings.get(name);
    scope = scope.parent;
  }
  return undefined;
}

function constantString(node, model) {
  if (!node) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier') return resolveBinding(model, node, node.name)?.stringValue;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0].value.cooked;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = constantString(node.left, model);
    const right = constantString(node.right, model);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}

function objectProperty(object, name, model) {
  if (object?.type !== 'ObjectExpression') return undefined;
  return object.properties.find(property => (
    property.type === 'Property'
      && property.kind === 'init'
      && staticPropertyName(property, model) === name
  ));
}

function containsProperty(node, name, model) {
  let found = false;
  walkAst(node, child => {
    if (child.type === 'Property' && staticPropertyName(child, model) === name) found = true;
  });
  return found;
}

function literalValue(node) {
  return node?.type === 'Literal' ? node.value : undefined;
}

function isSanitizedV5WithTable(node, model) {
  if (node?.type !== 'ObjectExpression') return false;
  const version = objectProperty(node, 'fpic_version', model);
  const security = objectProperty(node, 'security', model);
  const state = objectProperty(node, 'state', model);
  const mode = objectProperty(security?.value, 'mode', model);
  return literalValue(version?.value) === 5
    && literalValue(mode?.value) === 'sanitized'
    && containsProperty(state?.value, 'sanitizationTable', model);
}

function isProjectModule(source) {
  return /project-(?:security|crypto|io)/.test(String(source));
}

function isProjectContext(source, ast) {
  if (source.includes('.fpic')) return true;
  let projectImport = false;
  walkAst(ast, node => {
    if (node.type === 'ImportDeclaration'
        && isProjectModule(node.source.value)) {
      projectImport = true;
    }
  });
  return projectImport;
}

function createScope(parent = null, type = 'block') {
  return { parent, type, bindings: new Map() };
}

function declareIdentifier(scope, identifier, role) {
  const current = scope.bindings.get(identifier.name) || {
    declarations: [],
    kinds: new Set(),
    name: identifier.name,
    roles: new Set(),
    stringValue: undefined,
  };
  current.declarations.push(identifier);
  current.roles.add(role);
  scope.bindings.set(identifier.name, current);
  return current;
}

function declarePattern(scope, pattern, role, nodeScopes) {
  nodeScopes.set(pattern, scope);
  if (pattern.type === 'Identifier') {
    return [declareIdentifier(scope, pattern, role)];
  }
  if (pattern.type === 'RestElement') {
    return declarePattern(scope, pattern.argument, role, nodeScopes);
  }
  if (pattern.type === 'AssignmentPattern') {
    return declarePattern(scope, pattern.left, role, nodeScopes);
  }
  const bindings = [];
  if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties) {
      nodeScopes.set(property, scope);
      if (property.key) nodeScopes.set(property.key, scope);
      const child = property.value ?? property.argument;
      if (child) bindings.push(...declarePattern(scope, child, role, nodeScopes));
    }
  } else {
    for (const child of pattern.elements || []) {
      if (child) bindings.push(...declarePattern(scope, child, role, nodeScopes));
    }
  }
  return bindings;
}

function buildScopeModel(ast) {
  const rootScope = createScope(null, 'program');
  const scopes = [rootScope];
  const nodeScopes = new WeakMap();
  const childScope = (parent, type = 'block') => {
    const scope = createScope(parent, type);
    scopes.push(scope);
    return scope;
  };
  const nearestVarScope = scope => {
    let current = scope;
    while (current && !['function', 'program'].includes(current.type)) {
      current = current.parent;
    }
    return current || rootScope;
  };

  const visitChildren = (node, scope, omitted = new Set()) => {
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'type'].includes(key) || omitted.has(key)) continue;
      if (Array.isArray(value)) {
        for (const child of value) visit(child, scope);
      } else {
        visit(value, scope);
      }
    }
  };
  const visit = (node, scope) => {
    if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;
    nodeScopes.set(node, scope);
    if (node.type === 'Program') {
      for (const statement of node.body) visit(statement, scope);
      return;
    }
    if (node.type === 'ImportDeclaration') {
      for (const specifier of node.specifiers) {
        nodeScopes.set(specifier, scope);
        const binding = declareIdentifier(scope, specifier.local, 'import');
        binding.importSource = String(node.source.value);
        binding.importedName = specifier.imported?.name;
        binding.importNamespace = specifier.type === 'ImportNamespaceSpecifier';
      }
      return;
    }
    if (node.type === 'VariableDeclaration') {
      const declarationScope = node.kind === 'var' ? nearestVarScope(scope) : scope;
      for (const declaration of node.declarations) {
        nodeScopes.set(declaration, scope);
        declarePattern(declarationScope, declaration.id, 'variable', nodeScopes);
        visit(declaration.init, scope);
      }
      return;
    }
    if (node.type === 'FunctionDeclaration') {
      if (node.id) declareIdentifier(scope, node.id, 'function');
      const functionScope = childScope(scope, 'function');
      for (const parameter of node.params) {
        declarePattern(functionScope, parameter, 'parameter', nodeScopes);
      }
      visit(node.body, functionScope);
      return;
    }
    if (['FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) {
      const functionScope = childScope(scope, 'function');
      if (node.id) declareIdentifier(functionScope, node.id, 'function');
      for (const parameter of node.params) {
        declarePattern(functionScope, parameter, 'parameter', nodeScopes);
      }
      visit(node.body, functionScope);
      return;
    }
    if (node.type === 'BlockStatement') {
      const blockScope = childScope(scope);
      for (const statement of node.body) visit(statement, blockScope);
      return;
    }
    if (node.type === 'CatchClause') {
      const catchScope = childScope(scope);
      if (node.param) declarePattern(catchScope, node.param, 'parameter', nodeScopes);
      visit(node.body, catchScope);
      return;
    }
    if (['ForStatement', 'ForInStatement', 'ForOfStatement'].includes(node.type)) {
      const loopScope = childScope(scope);
      if (node.type === 'ForStatement') {
        visit(node.init, loopScope);
        visit(node.test, loopScope);
        visit(node.update, loopScope);
      } else {
        visit(node.left, loopScope);
        visit(node.right, loopScope);
      }
      visit(node.body, loopScope);
      return;
    }
    if (node.type === 'SwitchStatement') {
      visit(node.discriminant, scope);
      const switchScope = childScope(scope);
      for (const switchCase of node.cases) {
        nodeScopes.set(switchCase, switchScope);
        visit(switchCase.test, switchScope);
        for (const consequent of switchCase.consequent) visit(consequent, switchScope);
      }
      return;
    }
    if ((node.type === 'ClassDeclaration' || node.type === 'ClassExpression') && node.id) {
      declareIdentifier(scope, node.id, 'class');
    }
    visitChildren(node, scope);
  };
  visit(ast, rootScope);
  return { ast, nodeScopes, rootScope, scopes };
}

function addKinds(binding, kinds) {
  if (!binding) return false;
  const before = binding.kinds.size;
  for (const kind of kinds) binding.kinds.add(kind);
  return binding.kinds.size !== before;
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
  if (sourceKinds.has('project-export-namespace')
      && PROJECT_EXPORT_FUNCTIONS.has(property)) {
    kinds.add('project-export-function');
    if (property === 'serializeProjectExport') kinds.add('project-export-serializer');
  }
  if (sourceKinds.has('project')
      && ['serialized', 'security', 'state', 'payload', 'envelope'].includes(property)) {
    kinds.add('project');
  }
  if (sourceKinds.has('project-download-snapshot') && property === 'serialized') {
    kinds.add('validated-project');
  }
  if (sourceKinds.has('untrusted-download-result') && property === 'serialized') {
    kinds.add('project');
  }
  return kinds;
}

function explicitProjectName(name, projectContext) {
  if (/^(?:project|stateBag|projectPayload)$/i.test(name)) return true;
  return projectContext
    && /^aad(?:Object|Bytes)?$/i.test(name);
}

function combinedKinds(...groups) {
  const combined = new Set();
  for (const group of groups) {
    for (const kind of group) combined.add(kind);
  }
  return combined;
}

function expressionKinds(node, model, projectContext) {
  const kinds = new Set();
  if (!node) return kinds;
  if (['AwaitExpression', 'ChainExpression'].includes(node.type)) {
    return expressionKinds(node.argument ?? node.expression, model, projectContext);
  }
  if (node.type === 'SpreadElement') {
    return expressionKinds(node.argument, model, projectContext);
  }
  if (node.type === 'ConditionalExpression') {
    return combinedKinds(
      expressionKinds(node.consequent, model, projectContext),
      expressionKinds(node.alternate, model, projectContext),
    );
  }
  if (node.type === 'LogicalExpression') {
    return combinedKinds(
      expressionKinds(node.left, model, projectContext),
      expressionKinds(node.right, model, projectContext),
    );
  }
  if (node.type === 'TemplateLiteral') {
    return combinedKinds(...node.expressions.map(expression => (
      expressionKinds(expression, model, projectContext)
    )));
  }
  if (node.type === 'SequenceExpression') {
    return expressionKinds(node.expressions.at(-1), model, projectContext);
  }
  if (node.type === 'AssignmentExpression') {
    if (node.operator === '=') return expressionKinds(node.right, model, projectContext);
    return combinedKinds(
      expressionKinds(node.left, model, projectContext),
      expressionKinds(node.right, model, projectContext),
    );
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return combinedKinds(
      expressionKinds(node.left, model, projectContext),
      expressionKinds(node.right, model, projectContext),
    );
  }
  if (node.type === 'Identifier') {
    const binding = resolveBinding(model, node, node.name);
    if (binding) {
      for (const kind of binding.kinds) kinds.add(kind);
    } else {
      if (node.name === 'JSON') kinds.add('json-namespace');
      if (node.name === 'Blob') kinds.add('blob-constructor');
      if (node.name === 'URL') kinds.add('url-namespace');
      if (node.name === 'globalThis') kinds.add('global-namespace');
    }
    if (explicitProjectName(node.name, projectContext)) kinds.add('project');
    return kinds;
  }
  if (node.type === 'MemberExpression') {
    const sourceKinds = expressionKinds(node.object, model, projectContext);
    const property = staticPropertyName(node, model);
    for (const kind of propertyKinds(sourceKinds, property)) kinds.add(kind);
    return kinds;
  }
  if (node.type === 'CallExpression') {
    const calleeKinds = expressionKinds(node.callee, model, projectContext);
    if (calleeKinds.has('project-export-function')) kinds.add('project');
    if (calleeKinds.has('project-export-serializer')) kinds.add('project-export-result');
    if (calleeKinds.has('project-download-consumer')) kinds.add('project-download-snapshot');
    if (node.callee.type === 'Identifier'
        && node.callee.name === 'ownDataValue'
        && expressionKinds(node.arguments[0], model, projectContext)
          .has('untrusted-download-result')
        && constantString(node.arguments[1], model) === 'serialized') {
      kinds.add('project');
    }
    if (calleeKinds.has('json-stringify')
        && expressionKinds(node.arguments[0], model, projectContext).has('project')) {
      kinds.add('project');
    }
    return kinds;
  }
  if (node.type === 'NewExpression') {
    const calleeKinds = expressionKinds(node.callee, model, projectContext);
    const argumentKinds = node.arguments.map(argument => (
      expressionKinds(argument, model, projectContext)
    ));
    const projectData = argumentKinds.some(group => group.has('project'));
    const validatedProjectData = argumentKinds.some(group => group.has('validated-project'));
    if (calleeKinds.has('blob-constructor') && projectData) kinds.add('project-blob');
    if (calleeKinds.has('blob-constructor') && validatedProjectData) {
      kinds.add('validated-project-blob');
    }
    return kinds;
  }
  if (node.type === 'ArrayExpression') {
    const elementKinds = node.elements.map(element => (
      expressionKinds(element, model, projectContext)
    ));
    if (elementKinds.some(group => group.has('project'))) kinds.add('project');
    if (elementKinds.some(group => group.has('validated-project'))) {
      kinds.add('validated-project');
    }
    return kinds;
  }
  if (node.type === 'ObjectExpression') {
    if (objectProperty(node, 'fpic_version', model)
        && (objectProperty(node, 'state', model) || objectProperty(node, 'security', model))) {
      kinds.add('project');
    }
    if (node.properties.some(property => (
      (property.type === 'Property'
        && expressionKinds(property.value, model, projectContext).has('project'))
      || (property.type === 'SpreadElement'
        && expressionKinds(property.argument, model, projectContext).has('project'))
    ))) kinds.add('project');
  }
  return kinds;
}

function namedFunction(ast, name) {
  for (const statement of ast.body) {
    const declaration = statement.type === 'ExportNamedDeclaration'
      ? statement.declaration
      : statement;
    if (declaration?.type === 'FunctionDeclaration' && declaration.id?.name === name) {
      return declaration;
    }
  }
  return undefined;
}

function identifierFromPattern(pattern) {
  if (pattern?.type === 'Identifier') return pattern;
  if (pattern?.type === 'AssignmentPattern' && pattern.left.type === 'Identifier') {
    return pattern.left;
  }
  return undefined;
}

function bindPattern(pattern, sourceKinds, model, projectContext) {
  let changed = false;
  if (pattern.type === 'Identifier') {
    changed = addKinds(resolveBinding(model, pattern, pattern.name), sourceKinds) || changed;
  } else if (pattern.type === 'RestElement') {
    changed = bindPattern(pattern.argument, sourceKinds, model, projectContext) || changed;
  } else if (pattern.type === 'AssignmentPattern') {
    const defaultKinds = expressionKinds(pattern.right, model, projectContext);
    changed = bindPattern(
      pattern.left,
      combinedKinds(sourceKinds, defaultKinds),
      model,
      projectContext,
    ) || changed;
  } else if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties) {
      if (property.type !== 'Property') continue;
      const name = staticPropertyName(property, model);
      changed = bindPattern(
        property.value,
        propertyKinds(sourceKinds, name),
        model,
        projectContext,
      ) || changed;
    }
  }
  return changed;
}

function collectBindings(model, projectContext) {
  const declarators = [];
  const assignments = [];
  for (const scope of model.scopes) {
    for (const binding of scope.bindings.values()) {
      if (binding.importNamespace && isProjectModule(binding.importSource)) {
        addKinds(binding, ['project-export-namespace']);
      } else if (isProjectModule(binding.importSource)
          && PROJECT_EXPORT_FUNCTIONS.has(binding.importedName)) {
        addKinds(binding, ['project-export-function']);
        if (binding.importedName === 'serializeProjectExport') {
          addKinds(binding, ['project-export-serializer']);
        }
      }
      if (isProjectModule(binding.importSource)
          && binding.importedName === 'consumeValidatedProjectDownload') {
        addKinds(binding, ['project-download-consumer']);
      }
      if (isProjectModule(binding.importSource)
          && binding.importedName === 'inspectProjectImport') {
        addKinds(binding, ['project-inspection-function']);
      }
      if (binding.importedName === DOWNLOAD_APPROVED_FUNCTION) {
        addKinds(binding, ['project-download-helper']);
      }
    }
  }
  walkAst(model.ast, node => {
    if (node.type === 'VariableDeclarator') declarators.push(node);
    if (node.type === 'AssignmentExpression') assignments.push(node);
  });

  let changed = true;
  while (changed) {
    changed = false;
    for (const declarator of declarators) {
      changed = bindPattern(
        declarator.id,
        expressionKinds(declarator.init, model, projectContext),
        model,
        projectContext,
      ) || changed;
    }
    for (const assignment of assignments) {
      changed = bindPattern(
        assignment.left,
        expressionKinds(assignment.right, model, projectContext),
        model,
        projectContext,
      ) || changed;
    }
  }
}

function collectConstantStrings(model) {
  const declarations = [];
  walkAst(model.ast, node => {
    if (node.type === 'VariableDeclaration' && node.kind === 'const') {
      declarations.push(...node.declarations);
    }
  });
  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of declarations) {
      if (declaration.id.type !== 'Identifier') continue;
      const binding = resolveBinding(model, declaration.id, declaration.id.name);
      const value = constantString(declaration.init, model);
      if (value !== undefined && binding?.stringValue !== value) {
        binding.stringValue = value;
        changed = true;
      }
    }
  }
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
  const model = buildScopeModel(ast);
  collectConstantStrings(model);
  const projectContext = isProjectContext(source, ast);
  const approvedDownloadFunction = relativePath === DOWNLOAD_APPROVED_PATH
    ? namedFunction(ast, DOWNLOAD_APPROVED_FUNCTION)
    : undefined;
  if (approvedDownloadFunction) {
    const resultParameter = identifierFromPattern(approvedDownloadFunction.params[0]);
    const environmentParameter = identifierFromPattern(approvedDownloadFunction.params[1]);
    if (resultParameter) {
      addKinds(resolveBinding(model, resultParameter, resultParameter.name), [
        'untrusted-download-result',
      ]);
    }
    if (environmentParameter) {
      addKinds(resolveBinding(model, environmentParameter, environmentParameter.name), [
        'global-namespace',
      ]);
    }
    addKinds(resolveBinding(
      model,
      approvedDownloadFunction.id,
      approvedDownloadFunction.id.name,
    ), ['project-download-helper']);
  }
  collectBindings(model, projectContext);
  const decodedMap = transformed.map ? decodeSourceMap(transformed.map) : null;
  const violations = new Set();
  const report = (node, operation) => {
    violations.add(`${relativePath}:${mappedLine(node, decodedMap)}: ${operation}`);
  };
  const isApprovedDownloadNode = node => Boolean(
    approvedDownloadFunction
    && node.start >= approvedDownloadFunction.start
    && node.end <= approvedDownloadFunction.end,
  );

  if (approvedDownloadFunction) {
    let consumesSnapshot = false;
    let inspectsSnapshot = false;
    walkAst(approvedDownloadFunction.body, node => {
      if (node.type !== 'CallExpression') return;
      const calleeKinds = expressionKinds(node.callee, model, projectContext);
      if (calleeKinds.has('project-download-consumer')) consumesSnapshot = true;
      if (calleeKinds.has('project-inspection-function')
          && expressionKinds(node.arguments[0], model, projectContext)
            .has('validated-project')) {
        inspectsSnapshot = true;
      }
    });
    if (!consumesSnapshot) {
      report(approvedDownloadFunction, 'download helper missing boundary snapshot consumption');
    }
    if (!inspectsSnapshot) {
      report(approvedDownloadFunction, 'download helper missing runtime inspection');
    }
  }

  walkAst(ast, node => {
    if (isSanitizedV5WithTable(node, model)) {
      report(node, 'sanitized v5 payload includes sanitizationTable');
    }
    if (node.type === 'Property'
        && staticPropertyName(node, model) === 'mode'
        && literalValue(node.value) === 'reversible') {
      report(node, 'plaintext reversible project mode');
    }
    if (node.type === 'CallExpression') {
      const calleeKinds = expressionKinds(node.callee, model, projectContext);
      if (calleeKinds.has('project-download-helper')
          && !expressionKinds(node.arguments[0], model, projectContext)
            .has('project-export-result')) {
        report(node, 'unproven project download helper call');
      }
      if (!SERIALIZATION_APPROVED.has(relativePath)
          && calleeKinds.has('json-stringify')
          && expressionKinds(node.arguments[0], model, projectContext)
            .has('project')) {
        report(node, 'project serialization');
      }
      if (calleeKinds.has('url-create-object-url')) {
        const argumentKinds = expressionKinds(node.arguments[0], model, projectContext);
        const projectBlob = argumentKinds.has('project-blob')
          || argumentKinds.has('validated-project-blob');
        const approvedValidatedBlob = isApprovedDownloadNode(node)
          && argumentKinds.has('validated-project-blob');
        if (projectBlob && !approvedValidatedBlob) {
          report(node, 'project object URL creation');
        }
      }
    }
    if (node.type === 'NewExpression'
        && expressionKinds(node.callee, model, projectContext)
          .has('blob-constructor')
    ) {
      const argumentKinds = node.arguments.map(argument => (
        expressionKinds(argument, model, projectContext)
      ));
      const projectData = argumentKinds.some(group => (
        group.has('project') || group.has('validated-project')
      ));
      const approvedValidatedData = isApprovedDownloadNode(node)
        && argumentKinds.some(group => group.has('validated-project'));
      if (projectData && !approvedValidatedData) {
        report(node, 'project Blob construction');
      }
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
    label: 'download helper without runtime project inspection',
    relativePath: 'public/hooks/useProject.js',
    source: `import { consumeValidatedProjectDownload } from '../utils/project-security.js';
export function downloadValidatedProject(result, environment = globalThis) {
  const snapshot = consumeValidatedProjectDownload(result);
  const serialized = snapshot.serialized;
  const BlobImpl = environment.Blob;
  const blob = new BlobImpl([serialized], { type: 'application/json' });
  return environment.URL.createObjectURL(blob);
}`,
    expected: [
      'public/hooks/useProject.js:2: download helper missing runtime inspection',
    ],
  },
  {
    label: 'download helper without boundary snapshot consumption',
    relativePath: 'public/hooks/useProject.js',
    source: `import { inspectProjectImport } from '../utils/project-security.js';
export function downloadValidatedProject(result, environment = globalThis) {
  const serialized = result.serialized;
  inspectProjectImport(serialized);
  const blob = new environment.Blob([serialized], { type: 'application/json' });
  return environment.URL.createObjectURL(blob);
}`,
    expected: [
      'public/hooks/useProject.js:2: download helper missing boundary snapshot consumption',
      'public/hooks/useProject.js:2: download helper missing runtime inspection',
      'public/hooks/useProject.js:5: project Blob construction',
      'public/hooks/useProject.js:6: project object URL creation',
    ],
  },
  {
    label: 'another hook function calling the helper with a hand-built result',
    relativePath: 'public/hooks/useProject.js',
    source: `import { consumeValidatedProjectDownload, inspectProjectImport } from '../utils/project-security.js';
export function downloadValidatedProject(result, environment = globalThis) {
  const snapshot = consumeValidatedProjectDownload(result);
  const serialized = snapshot.serialized;
  inspectProjectImport(serialized);
  const blob = new environment.Blob([serialized]);
  return environment.URL.createObjectURL(blob);
}
export function bypassDownload() {
  return downloadValidatedProject({ serialized: '{}', filename: 'x.fpic.json', security: {} });
}`,
    expected: [
      'public/hooks/useProject.js:10: unproven project download helper call',
    ],
  },
  {
    label: 'another public file calling the helper with a hand-built result',
    relativePath: 'public/components/ProjectBypass.js',
    source: `import { downloadValidatedProject } from '../hooks/useProject.js';
downloadValidatedProject({ serialized: '{}', filename: 'x.fpic.json', security: {} });`,
    expected: [
      'public/components/ProjectBypass.js:2: unproven project download helper call',
    ],
  },
  {
    label: 'raw project download in another function in the approved hook file',
    relativePath: 'public/hooks/useProject.js',
    source: `import { serializeProjectExport } from '../utils/project-security.js';
export async function unsafeDownload(stateBag) {
  const result = await serializeProjectExport(stateBag, 'unsafe');
  const blob = new Blob([result.serialized], { type: 'application/json' });
  URL.createObjectURL(blob);
}`,
    expected: [
      'public/hooks/useProject.js:4: project Blob construction',
      'public/hooks/useProject.js:5: project object URL creation',
    ],
  },
  {
    label: 'raw state in the named download helper without validated-result provenance',
    relativePath: 'public/hooks/useProject.js',
    source: `import { consumeValidatedProjectDownload, inspectProjectImport } from '../utils/project-security.js';
export function downloadValidatedProject(result, environment = globalThis) {
  const snapshot = consumeValidatedProjectDownload(result);
  inspectProjectImport(snapshot.serialized);
  const stateBag = { fpic_version: 5, state: {} };
  const blob = new environment.Blob([stateBag], { type: 'application/json' });
  environment.URL.createObjectURL(blob);
}`,
    expected: [
      'public/hooks/useProject.js:6: project Blob construction',
      'public/hooks/useProject.js:7: project object URL creation',
    ],
  },
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
    label: 'object-spread project serialization',
    relativePath: 'public/utils/project-object-spread.js',
    source: `const project = { fpic_version: 5, state: {} };
const copy = { ...project };
JSON.stringify(copy);`,
    expected: ['public/utils/project-object-spread.js:3: project serialization'],
  },
  {
    label: 'conditional project serialization',
    relativePath: 'public/utils/project-conditional.js',
    source: `const project = { fpic_version: 5, state: {} };
JSON.stringify(enabled ? project : {});`,
    expected: ['public/utils/project-conditional.js:2: project serialization'],
  },
  {
    label: 'nullish project serialization',
    relativePath: 'public/utils/project-nullish.js',
    source: `const project = { fpic_version: 5, state: {} };
JSON.stringify(project ?? {});`,
    expected: ['public/utils/project-nullish.js:2: project serialization'],
  },
  {
    label: 'sequence project serialization',
    relativePath: 'public/utils/project-sequence.js',
    source: `const project = { fpic_version: 5, state: {} };
JSON.stringify(({}, project));`,
    expected: ['public/utils/project-sequence.js:2: project serialization'],
  },
  {
    label: 'assignment-expression project serialization',
    relativePath: 'public/utils/project-assignment-expression.js',
    source: `const project = { fpic_version: 5, state: {} };
let candidate;
JSON.stringify(candidate = project);`,
    expected: [
      'public/utils/project-assignment-expression.js:3: project serialization',
    ],
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
    label: 'namespace project-export member call',
    relativePath: 'public/utils/project-namespace.js',
    source: `import * as security from './project-security.js';
const output = await security.serializeProjectExport(stateBag, 'name');
new Blob([output.serialized]);`,
    expected: ['public/utils/project-namespace.js:3: project Blob construction'],
  },
  {
    label: 'namespace project-export destructuring',
    relativePath: 'public/utils/project-namespace-destructure.js',
    source: `import * as security from './project-security.js';
const { serializeProjectExport: exportProject } = security;
const output = await exportProject(stateBag, 'name');
new Blob([output.serialized]);`,
    expected: [
      'public/utils/project-namespace-destructure.js:4: project Blob construction',
    ],
  },
  {
    label: 'defaulted namespace project-export destructuring',
    relativePath: 'public/utils/project-namespace-default.js',
    source: `import * as security from './project-security.js';
const { serializeProjectExport: exportProject = fallback } = security;
const output = await exportProject(stateBag, 'name');
new Blob([output.serialized]);`,
    expected: [
      'public/utils/project-namespace-default.js:4: project Blob construction',
    ],
  },
  {
    label: 'project-export and Blob alias chains',
    relativePath: 'public/utils/project-alias-chain.js',
    source: `import * as security from './project-security.js';
const firstExport = security.serializeProjectExport;
const secondExport = firstExport;
const FirstBlob = Blob;
const SecondBlob = FirstBlob;
const output = await secondExport(stateBag, 'name');
new SecondBlob([output.serialized]);`,
    expected: ['public/utils/project-alias-chain.js:7: project Blob construction'],
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
    label: 'array-spread project Blob construction',
    relativePath: 'public/utils/project-array-spread.js',
    source: `import { serializeProjectExport } from './project-security.js';
const output = await serializeProjectExport(stateBag, 'name');
new Blob([...output.serialized]);`,
    expected: ['public/utils/project-array-spread.js:3: project Blob construction'],
  },
  {
    label: 'interpolated-template project Blob construction',
    relativePath: 'public/utils/project-template.js',
    source: `import { serializeProjectExport } from './project-security.js';
const output = await serializeProjectExport(stateBag, 'name');
new Blob([\`\${output.serialized}\`]);`,
    expected: ['public/utils/project-template.js:3: project Blob construction'],
  },
  {
    label: 'binary-concatenated project Blob construction',
    relativePath: 'public/utils/project-binary.js',
    source: `import { serializeProjectExport } from './project-security.js';
const output = await serializeProjectExport(stateBag, 'name');
new Blob(['prefix:' + output.serialized]);`,
    expected: ['public/utils/project-binary.js:3: project Blob construction'],
  },
  {
    label: 'global JSON after a loop-local shadow',
    relativePath: 'public/utils/project-loop-scope.js',
    source: `const project = { fpic_version: 5, state: {} };
for (let JSON of []) {}
JSON.stringify(project);`,
    expected: ['public/utils/project-loop-scope.js:3: project serialization'],
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
  {
    label: 'plaintext reversible project mode',
    relativePath: 'public/utils/project-plaintext-reversible.js',
    source: `const project = {
  security: { mode: 'reversible' },
};`,
    expected: [
      'public/utils/project-plaintext-reversible.js:2: plaintext reversible project mode',
    ],
  },
];

const SAFE_FIXTURES = [
  {
    label: 'validated serialized result in the real download helper',
    relativePath: 'public/hooks/useProject.js',
    source: `import { consumeValidatedProjectDownload, inspectProjectImport } from '../utils/project-security.js';
export function downloadValidatedProject(result, environment = globalThis) {
  const snapshot = consumeValidatedProjectDownload(result);
  const serialized = snapshot.serialized;
  inspectProjectImport(serialized);
  const BlobImpl = environment.Blob;
  const urlApi = environment.URL;
  const blob = new BlobImpl([serialized], { type: 'application/json' });
  return urlApi.createObjectURL(blob);
}`,
  },
  {
    label: 'sole helper call using the direct serializeProjectExport result',
    relativePath: 'public/hooks/useProject.js',
    source: `import { consumeValidatedProjectDownload, inspectProjectImport, serializeProjectExport } from '../utils/project-security.js';
export function downloadValidatedProject(result, environment = globalThis) {
  const snapshot = consumeValidatedProjectDownload(result);
  const serialized = snapshot.serialized;
  inspectProjectImport(serialized);
  const blob = new environment.Blob([serialized]);
  return environment.URL.createObjectURL(blob);
}
export async function handleExportProject(stateBag) {
  const result = await serializeProjectExport(stateBag, 'safe', { mode: 'sanitized' });
  downloadValidatedProject(result);
}`,
  },
  {
    label: 'shadowed JSON parameter',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `export function renderProject(JSON) {
  const project = { fpic_version: 5, state: {} };
  return JSON.stringify(project);
}`,
  },
  {
    label: 'shadowed local JSON binding',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const JSON = { stringify: value => String(value) };
const project = { fpic_version: 5, state: {} };
JSON.stringify(project);`,
  },
  {
    label: 'shadowed Blob and URL parameters',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `export function preview(Blob, URL) {
  const project = { fpic_version: 5, state: {} };
  const blob = new Blob([project]);
  return URL.createObjectURL(blob);
}`,
  },
  {
    label: 'unrelated report and API payload serialization in project-aware code',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `import { inspectProjectImport } from '../utils/project-security.js';
const payload = await fetchReport(inspectProjectImport);
const serialized = JSON.stringify(payload);
const blob = new Blob([serialized], { type: 'application/json' });
URL.createObjectURL(blob);`,
  },
  {
    label: 'conditional unrelated report serialization',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const report = enabled ? await fetchReport() : {};
JSON.stringify(report);`,
  },
  {
    label: 'project used only as a conditional test',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const project = { fpic_version: 5, state: {} };
const report = await fetchReport();
JSON.stringify(project ? report : {});`,
  },
  {
    label: 'sequence expression that discards project data',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const project = { fpic_version: 5, state: {} };
JSON.stringify((project, {}));`,
  },
  {
    label: 'unrelated interpolated report download',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const report = await fetchReport();
new Blob([\`report:\${report}\`]);`,
  },
  {
    label: 'unrelated binary-concatenated report download',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const report = await fetchReport();
new Blob(['report:' + report]);`,
  },
  {
    label: 'unrelated assignment-expression serialization',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `const report = await fetchReport();
let candidate;
JSON.stringify(candidate = report);`,
  },
  {
    label: 'function-hoisted var JSON declared inside a block',
    relativePath: 'public/components/ProjectDashboard.jsx',
    source: `export function render(enabled) {
  const project = { fpic_version: 5, state: {} };
  if (enabled) { var JSON = customJson; }
  return JSON.stringify(project);
}`,
  },
];

describe('project export security enforcement analyzer', () => {
  it.each(BYPASS_FIXTURES)('rejects $label', async fixture => {
    await expect(analyzeSource(fixture.source, fixture.relativePath))
      .resolves.toEqual(fixture.expected);
  });

  it.each(SAFE_FIXTURES)('allows $label', async fixture => {
    await expect(analyzeSource(fixture.source, fixture.relativePath))
      .resolves.toEqual([]);
  });
});

describe('project export security enforcement', () => {
  it('runs complete Vitest discovery in CI while leaving standalone harnesses separate', () => {
    const workflow = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8');
    const vitestStep = workflow.match(/- name: Run Vitest suites\n(?<body>[\s\S]*?)(?=\n\s+- name:)/)?.groups?.body;
    expect(vitestStep).toBeDefined();
    expect(vitestStep).toMatch(/run:\s+npx vitest run\s*$/m);
    expect(vitestStep).not.toMatch(/tests\/[\w-]+\.test\.(?:js|jsx)/);
    expect(workflow).toContain('for test_file in tests/*.test.js');
  });

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
