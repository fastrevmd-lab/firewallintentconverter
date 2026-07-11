# Canonical Conversion Output Design

## Problem

The conversion pipeline does not have one enforced representation for generated SRX configuration. Converter functions return an object whose set-format content is stored in `commands`, while the validation and license-enforcement path reads `srxCommands`. The missing field is converted to an empty string, so validation can report success without inspecting the configuration displayed to the user or sent to the PyEZ bridge.

The same contract drift appears elsewhere. Batch conversion reads `commands` and `warnings` from the engine response even though the engine returns them under `output`. Most UI consumers understand the converter object, but each independently extracts configuration text and defaults malformed data to an empty value. Those fallbacks turn shape errors into silent omissions.

## Goals

- Define one runtime-enforced representation for SRX conversion output.
- Ensure validation, license enforcement, rendering, export, reporting, project persistence, batch conversion, and push operate on the same content.
- Reject missing, empty, mismatched, or malformed output instead of treating it as valid.
- Preserve warnings, summaries, and other converter metadata when license enforcement replaces set commands.
- Normalize supported legacy project output into the canonical representation during import.
- Prevent set-oriented validation from silently accepting XML output.
- Add regression tests that reproduce the `commands` versus `srxCommands` bypass.

## Non-goals

- Converting the application to TypeScript.
- Adding XML equivalents for the existing set-command hardware, operational, compliance, and license checks.
- Redesigning converter internals that assemble set commands or XML.
- Changing license tiers or feature-detection patterns.
- Changing the PyEZ bridge protocol.

## Approaches Considered

### Direct property correction

Change `srxCommands` to `commands` in `useConversion` and update the filtered result in place. This closes the reported path with a very small patch, but every consumer would retain its own permissive extraction logic. Empty and malformed output would still be accepted, the batch mismatch would remain, and another property-name drift could recreate the bypass.

### Canonical runtime output contract

Introduce a small dependency-free module that defines, normalizes, validates, reads, and updates conversion output. Conversion results become a discriminated object, and all security-sensitive consumers use the same helpers. This is the recommended approach because it closes the current bypass while establishing a narrow boundary that JavaScript can enforce without a broad language migration.

### TypeScript migration

Convert the conversion engine, contexts, hooks, and consumers to TypeScript and use a discriminated union. Static checking would be useful, but the migration would touch substantially more code than the vulnerability requires and would still need runtime validation for imported projects and external data.

## Canonical Data Contract

The canonical output is a discriminated object. `format` is part of the output so the content cannot silently drift from `ConversionContext.outputFormat`.

Set output:

```js
{
  format: 'set',
  commands: ['set system host-name edge-1'],
  warnings: [],
  summary: {},
}
```

XML output:

```js
{
  format: 'xml',
  xml: '<configuration>...</configuration>',
  warnings: [],
  summary: {},
}
```

The object may retain additional converter metadata, but its discriminant and content field are strict:

- `format` must be exactly `set` or `xml`.
- Set output must have a non-empty array of strings in `commands`.
- XML output must have a non-empty string in `xml`.
- Set output cannot rely on `xml`, and XML output cannot rely on `commands`.
- The canonical content must pass the existing Junos artifact validator before entering application state.

## Shared Output Module

A new dependency-free module under `src/conversion/conversion-output.js` will own the contract. It will export:

- `ConversionOutputError`, a safe typed error containing a reason but not configuration content.
- `normalizeConversionOutput(rawOutput, formatHint)`, which converts a converter result or supported legacy value into the canonical object and validates it.
- `assertConversionOutput(output)`, which validates an already-canonical object and returns it.
- `getConversionOutputText(output)`, which returns the exact set or XML text after validation.
- `getSetCommands(output)`, which returns a copy of canonical set commands and rejects XML.
- `replaceSetCommands(output, commands)`, which returns a new canonical set object with filtered commands while preserving metadata.
- `hasConversionOutput(output)`, which returns true only for valid, non-empty canonical output.

The normalizer accepts legacy string output only when a `set` format hint is supplied. It splits the string into non-empty lines and returns canonical set output. This compatibility exists for project migration; new conversion paths must supply converter objects. Arbitrary malformed objects, empty strings, mixed shapes, unknown formats, non-string commands, and XML passed as set output are rejected.

## Data Flow

### Conversion engine

`convertConfig` and `mergeConvert` will normalize their converter result before returning. Their existing envelope remains:

```js
{
  output: canonicalOutput,
  format: canonicalOutput.format,
  validation,
}
```

The engine remains the first boundary after converter generation. Existing Junos set/XML artifact validation runs before normalization, and normalization verifies the public result shape.

### Conversion context

`SET_CONVERSION_RESULT` stores only canonical output. `outputFormat` is derived from `output.format` when output is supplied, rather than trusted as an independent action value. Clearing output retains the selected format as today.

Project load normalizes supported legacy output before dispatch. New project saves contain canonical output. The project format version will be incremented, with migration coverage for legacy string output and pre-discriminant converter objects.

### Validation and license enforcement

`runValidation` will accept canonical conversion output rather than a loose string. It obtains commands through `getSetCommands`, so empty, malformed, or XML output raises `ConversionOutputError` before any checks run.

The current validation rules are set-command rules. When the UI holds XML output, validation and license enforcement will fail closed with an actionable message directing the user to switch to Set Commands. The UI must not show validation success or update findings for an XML attempt.

When enforcement removes commands, `replaceSetCommands` creates the updated canonical object. Warnings, summary data, and other metadata remain unchanged. The same updated object is subsequently displayed, exported, saved, and pushed.

If enforcement removes every generated command, the application clears `srxOutput` while retaining the enforcement findings and shows a blocking error. This preserves the non-empty canonical contract and disables render, export, and push actions instead of leaving the original unlicensed output available.

### Consumers

Security-sensitive consumers must not independently default missing content to an empty string. `SRXOutput`, `usePush`, PDF generation, configuration diff, report generation, Terraform/Ansible export, and workflow enablement will use the shared contract helpers or receive already-extracted canonical text/commands.

Batch migration will read `convertResult.output`, validate it as canonical set output, and derive its downloaded text with `getConversionOutputText`. This fixes the separate engine-envelope mismatch.

## Error Handling

All malformed-output failures are blocking. The application clears stale conversion output before conversion, as it already does, and displays a safe error that identifies the invalid contract without echoing configuration content.

Validation failures leave the canonical output untouched but do not create or retain a success result for that validation attempt. License enforcement cannot update output unless it received valid set output and produced a non-empty canonical replacement; an all-removed enforcement result clears output as described above.

Push, copy, download, infrastructure-as-code export, PDF export, and project save controls must be disabled or throw a handled blocking error when no valid canonical output exists. They must never submit or download an empty fallback caused by a shape mismatch.

## Project Compatibility

The project file version will be incremented from 2 to 3.

Migration behavior:

- A legacy set string plus `outputFormat: 'set'` becomes canonical set output.
- A legacy object with `commands` plus `outputFormat: 'set'` gains `format: 'set'` after validation.
- A legacy object with `xml` plus `outputFormat: 'xml'` gains `format: 'xml'` after validation.
- `null` output remains `null`.
- Empty, mixed, or malformed legacy output makes project validation fail with an actionable error; it is not silently discarded.

The migration does not accept the obsolete `srxCommands` property as a canonical source because no converter version in this project produced that field. Accepting it would conceal precisely the contract drift being removed.

## Testing Strategy

Tests will follow red-green-refactor cycles.

Unit coverage for the shared module will include:

- canonical set and XML objects;
- supported legacy string and object normalization;
- metadata preservation after command replacement;
- empty strings and arrays;
- missing or unknown formats;
- mixed set/XML shapes;
- non-string commands and XML;
- XML rejection by set-only access;
- safe errors that do not contain rejected configuration.

Integration and regression coverage will include:

- the exact former `commands` versus `srxCommands` validation bypass;
- unsupported set configuration being detected and removed in enforce mode;
- the filtered output being the same object content rendered and pushed;
- XML validation producing a blocking error rather than an empty successful check;
- malformed conversion output being rejected by the engine/context boundary;
- batch conversion consuming `convertResult.output`;
- project version 2 string/object migration and version 3 round trips;
- copy, download, IaC export, PDF/report, and push helpers reading canonical content.

The complete existing JavaScript, Python bridge, build, dependency-audit, and artifact-validation gates will run before publication.

## Acceptance Mapping

- Unsupported or unlicensed configuration cannot proceed unnoticed because validation reads canonical `commands` and rejects all other shapes.
- Rendering and push use the same canonical object updated by enforcement.
- Missing, empty, malformed, mixed, or format-mismatched output raises a blocking error.
- `replaceSetCommands` preserves metadata while replacing only `commands`.
- Runtime normalization protects converter, context, persistence, batch, and consumer boundaries.
- JSDoc typedefs on the shared module document the discriminated type without requiring a TypeScript migration.
