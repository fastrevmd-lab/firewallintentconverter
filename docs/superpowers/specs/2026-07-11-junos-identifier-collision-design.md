# Junos Identifier Collision Defense Design

## Problem

The conversion pipeline repeatedly calls `sanitizeJunosName()` while definitions and references are emitted. The function replaces unsupported punctuation and whitespace with dashes, collapses adjacent dashes, trims, prefixes names that begin with a digit, substitutes `unnamed` for an empty result, and truncates to 63 characters. Distinct source names can therefore become the same Junos identifier. Because definitions and references are normalized independently, the converter can silently merge objects, policies, applications, NAT rules, profiles, logical systems, or other named configuration.

Case is not currently folded and this design preserves that behavior. `Web` and `web` remain distinct. Collisions addressed here include punctuation, whitespace, collapsed dashes, empty normalized names, numeric-prefix transformations, and truncation.

## Goals

- Prove that every generated Junos identifier is unique in the namespace where Junos requires uniqueness.
- Preserve current output names for non-colliding definitions.
- Resolve normalization collisions with stable, deterministic, source-derived names that do not depend on input order.
- Resolve every definition and reference through one immutable conversion-scoped plan shared by Set Commands and XML.
- Block conversion when duplicate definitions or references are semantically ambiguous.
- Retain a complete, auditable definition/reference/output mapping in canonical conversion output and saved projects.
- Report resolved collisions through the existing Warnings UI without exposing generated configuration content in errors.
- Preserve source names in parsers so collision detection remains possible.
- Cover all current and future converter-owned identifier namespaces with an enforceable catalog.

## Non-goals

- Folding identifier case.
- Renaming non-colliding definitions solely for consistency.
- Guessing which duplicate definition or ambiguous reference the user intended.
- Changing Junos free-text, enum, address, prefix, interface, numeric, or other non-symbol scalar serialization.
- Redesigning the intermediate configuration schema beyond retaining source identity and attaching planner metadata.
- Combining names that are legitimately identical in different Junos namespace contexts.
- Replacing the existing injection-defense serializers or output validators.

## Approaches Considered

### Reject every normalized collision

This is simple and safe, but it makes otherwise convertible source configurations require manual edits even when the source names are distinct and references are unambiguous.

### Rename only later colliding entries

This preserves more familiar names, but the result depends on source array order. Reordering an equivalent configuration could rename a different object and change all of its references.

### Conversion-scoped symbol plan

The selected approach catalogs all definitions and references before emission. Non-colliding names remain unchanged. Every member of a normalized collision group receives a stable suffix derived from its source identity. Exact duplicate definitions and ambiguous references block conversion. Set and XML emitters consume the same immutable plan.

## Security Invariants

- No two definitions share an output identifier within the same Junos namespace and context.
- A reference can bind to at most one cataloged definition.
- A normalized but otherwise unknown reference cannot accidentally bind to a differently named definition.
- Allocation is deterministic for semantically identical input, regardless of array order.
- Set and XML conversion use identical mappings for identical input.
- Merged conversion isolates logical-system-local namespaces and resolves cross-logical-system references explicitly.
- Every converter-emitted identifier position is classified in the namespace catalog or conversion fails.
- No emitter independently calls `sanitizeJunosName()` for a cataloged definition or reference after planning.
- Imported output is usable only when its identifier mapping validates against the canonical mapping schema.

## Architecture

Create `src/security/junos-identifiers.js` as a dependency-free planning module. `sanitizeJunosName()` remains the base normalization function, but only the planner may use it to allocate cataloged symbols. The existing `setIdentifier()` serializer remains available for non-symbol scalar positions and bootstrap validation; a source-contract test prevents it or `sanitizeJunosName()` from bypassing the planner at cataloged positions.

The module will export:

- `JunosIdentifierPlanningError`, a typed blocking error with safe structured details;
- `JUNOS_IDENTIFIER_MAPPING_VERSION`, initially `1`;
- `planJunosIdentifiers(config, options)`, which returns an immutable plan;
- `validateIdentifierMappings(mapping)`, which validates persisted mapping metadata;
- planner lookup helpers for definitions, references, and generated identifiers; and
- catalog constants used by coverage tests.

The conversion entry point validates the intermediate configuration, builds the identifier plan, and only then invokes either output builder. Set and XML builders receive the plan as a required argument. Merged conversion builds a complete plan across all slots and cross-logical-system links before emitting any slot.

## Symbol Catalog

Every catalog entry declares:

- a stable catalog key;
- definition and reference paths or a generated-identifier producer;
- the Junos namespace;
- the function that derives the namespace context;
- the symbol kind;
- supported literal or built-in bypasses; and
- reference resolution rules.

The initial catalog must classify every current `sanitizeJunosName()` and `setIdentifier()` call in both converters. It includes at least:

- target tenant/logical-system names and cross-logical-system endpoints;
- security zones and cross-link shared zones;
- addresses, address sets, and any emitted dynamic address entries in one unified address-book namespace per address-book context;
- custom applications and application sets in the appropriate shared applications namespace, with Junos predefined applications treated as explicit literals;
- security policies per resolved `from-zone`/`to-zone` pair;
- schedulers;
- source, destination, and static NAT rule sets, rules, and pools in their Junos-specific scopes;
- routing instances, BGP groups per instance, generated routing policies, and other named routing objects;
- IKE proposals, policies, and gateways, plus IPsec proposals, policies, and VPNs;
- screen profiles;
- AppFW, UTM, IDP, SecIntel, SSL/decryption, and other named security profiles;
- VLANs and bridge domains;
- policy-based-forwarding filters, terms, and generated forwarding instances;
- DHCP pools and ranges;
- class-of-service classifiers, scheduler maps, and related named objects;
- flow-monitoring instances and templates;
- AAA profiles/users and SNMP communities or named objects; and
- every additional generated identifier found by the converter catalog audit.

Addresses and address sets intentionally share a namespace because Junos requires names to be distinct within an address book. Security-policy uniqueness is scoped to the resolved source-zone/destination-zone pair. Logical-system-local objects include logical-system identity in their context, so the same source name may remain unchanged in separate logical systems.

Values such as interface names, IP addresses, prefixes, enums, application predefined literals, extension match values, and free text are not automatically symbols. Their existing field-aware serializers remain responsible for validation. Any direct use of the base name sanitizer must be documented in the catalog as a non-symbol scalar exception.

## Stable Source Identity

Each definition receives a `stableKey` that is independent of its array position:

- imported definitions use catalog version, context, namespace, kind, and the exact case-sensitive source name;
- generated definitions use the stable identity of their parent plus a fixed catalog role such as `source-nat-pool` or `ssl-forward-profile`; and
- generic policy names are first expanded by the existing descriptive-name generator and then treated as source names by the planner.

Paths and array indices are never identity inputs. A parser-provided stable source UID may confirm reference binding, but it does not make duplicate exact source names safe in one `(context, namespace, kind)` tuple.

Two definitions with the same stable identity in one context are duplicates and block conversion. Multiple definitions with the same exact source name across compatible kinds are also blocked when a reference in that namespace could not distinguish their kinds. For example, an address and address set with the same source name are ambiguous when a policy address reference may target either.

A single empty or punctuation-only source name keeps the current `unnamed` base when it is otherwise unique. Multiple indistinguishable empty definitions in the same namespace fail as exact duplicates. Distinct source names that both normalize to `unnamed` are an ordinary resolvable collision.

Definition paths are retained only for diagnostics and mapping output. They do not affect allocation, so reordering arrays does not change names.

## Deterministic Allocation Algorithm

Planning occurs separately for every `(context, namespace)` pair:

1. Catalog all definitions, references, and generated identifiers without emitting output.
2. Reject duplicate stable identities and source-name ambiguities that reference semantics cannot disambiguate.
3. Compute each definition's base with the unchanged `sanitizeJunosName()` behavior. Case is preserved.
4. Group definitions by exact base name.
5. Reserve every singleton base unchanged. Collision candidates must avoid these fixed names; singleton definitions are never renamed because of a generated candidate.
6. Rename every member of a group containing two or more distinct identities. This avoids privileging whichever entry happened to appear first.
7. Build the suffix input as the UTF-8 bytes of `junos-id-v1`, context, namespace, kind, stable key, and decimal retry counter, separated by NUL delimiters. Hash it with FNV-1a 64-bit arithmetic using offset basis `14695981039346656037`, prime `1099511628211`, and a `0xffffffffffffffff` mask after each multiplication. Encode the unsigned result in lower-case base36, left-padded to 13 characters.
8. Form the candidate as `<base-prefix>-<13-character-suffix>`. Truncate only the base prefix so the complete identifier is at most 63 characters.
9. Start every candidate's retry counter at zero. Compare every candidate against all unchanged singleton names and all other candidates in the namespace. Increment the counter for every candidate involved in a conflict, recompute those candidates, and re-evaluate the entire candidate set.
10. Stop after 32 complete conflict rounds and raise `allocation_failed` if uniqueness cannot be proven. A test-only hash injection point will force this path.
11. Perform one final namespace-wide uniqueness assertion before freezing the plan.

The hash is an allocation token, not a cryptographic trust primitive. Safety comes from comparing all completed candidates and failing closed if any conflict remains. The hash input and retry procedure are versioned so a future algorithm change is explicit and migrated rather than silently changing saved names.

## Reference Resolution

References are resolved against exact source identity before output names are considered:

- exact case-sensitive source-name matches bind when exactly one compatible definition exists;
- source UIDs bind only to the definition carrying that UID;
- built-in Junos literals such as `any` and recognized predefined applications bypass allocation through explicit catalog rules;
- a reference matching multiple compatible definitions raises `ambiguous_reference`;
- a missing internal reference keeps the converter's existing undefined-reference error or warning policy, but is cataloged as an unresolved external symbol;
- an unresolved external symbol receives a deterministic output name reserved against definitions and other distinct unresolved symbols, so its normalized spelling cannot bind accidentally to a different definition; and
- a reference never resolves by comparing `sanitizeJunosName(reference)` with an output definition name.

Every emitter lookup supplies the catalog key, context, exact source value, and intermediate-config path. Looking up a path that was not cataloged raises `missing_catalog_coverage`. This converts incomplete migration work or a future unplanned identifier field into a blocking failure rather than a silent normalization bypass.

## Mapping Data Contract

Canonical Set and XML output contain a required `identifierMappings` object:

```js
{
  identifierMappings: {
    version: 1,
    entries: [{
      context: 'logical-system:branch-a/address-book:global',
      namespace: 'address-book-entry',
      kind: 'address',
      sourceName: 'Web Server',
      outputName: 'Web-Server-02ks8j4f8z3qp',
      definitionPath: 'address_objects[4].name',
      referencePaths: [
        'security_policies[2].src_addresses[0]',
      ],
      resolution: 'collision-renamed',
    }],
  },
}
```

An entry is emitted for every definition, including unchanged definitions, and for every unresolved external symbol. `definitionPath` is `null` only for an unresolved external symbol. `resolution` is one of `unchanged`, `collision-renamed`, `generated`, `generated-collision-renamed`, `unresolved-reference`, or `unresolved-collision-renamed`. Entries and `referencePaths` are sorted by stable semantic identity/path before serialization, making project diffs deterministic. Built-in/literal bypasses are omitted.

Validation requires:

- exactly version `1`;
- an array of entries with the documented fields and allowed resolution values;
- safe scalar values and valid Junos `outputName` values;
- unique `(context, namespace, kind, sourceName)` definition entries;
- unique `(context, namespace, outputName)` values across definitions and distinct unresolved external symbols;
- sorted, unique reference paths; and
- consistency between `resolution`, `sourceName`, and `outputName`.

The mapping is attached to the canonical output object, so project persistence retains the exact mapping next to the artifact it describes. The conversion summary includes collision totals, while warnings provide the user-facing subset. No second independently mutable mapping is stored in React state.

## Parser Changes

Check Point and SonicWall parsers currently normalize some names and references before conversion. Those calls will be removed from definition and reference fields so exact source names survive into the planner. Stable source UIDs already available from a parser are retained as metadata when useful.

Parser utilities may still normalize non-symbol generated labels only when the catalog marks the field as an exception. Parser regression tests prove that punctuation, whitespace, case, and long names remain unchanged in intermediate definitions and references.

## Set, XML, and Merge Integration

The two single-conversion builders receive the same plan shape and use catalog lookups for all identifier definitions and references. Neither builder allocates or normalizes cataloged symbols. Generated names such as NAT pools, rule sets, SSL profiles, and PBF instances are registered by role during planning and retrieved by role during emission.

Merged conversion plans logical-system names first, then plans slot-local symbols with the resolved logical-system context, then plans cross-link identifiers and references. A slot may reuse a local name used by another logical system. Logical-system names themselves and any root-level generated identifiers remain unique at root scope.

Set and XML conversion tests compare their `identifierMappings` objects for deep equality. Artifact-specific order or syntax may differ, but definition and reference binding may not.

## Errors, Warnings, and UI

`JunosIdentifierPlanningError` contains only safe structured fields:

- `code`;
- `namespace`;
- `context`;
- `sourceName` when safe and relevant;
- `definitionPaths` and/or `referencePaths`; and
- a generic reason.

Blocking codes include:

- `duplicate_definition`;
- `ambiguous_reference`;
- `allocation_failed`;
- `missing_catalog_coverage`; and
- `invalid_identifier_mapping`.

Errors stop conversion before Set/XML emission and clear stale successful output through the existing conversion error path. Error messages do not include generated configuration or unrelated object content.

Each resolved collision adds an `identifier_collision` warning compatible with the existing Warnings panel. It includes namespace, context, source name, normalized base, output name, definition path, and reference count, with an actionable message that the mapping was made deterministic. A summary field named `identifier_collisions_resolved` contains the number of renamed definitions. Because the existing panel already renders conversion warnings, no dedicated collision panel is added.

## Project Compatibility and Migration

The project format increments from version 3 to version 4.

New saves require any non-null `srxOutput` to contain a valid `identifierMappings` object. Project load validates the mapping before making the artifact available for rendering, export, validation, or push.

For version 1-3 projects:

- source text, intermediate configuration, parser warnings/statistics, sanitization state, mappings, target/model/site settings, interface mappings, translated policies, merge slots/links, and UI preferences are preserved;
- null generated output remains null;
- generated output with a valid version-1 identifier mapping may be normalized and retained;
- generated output without a valid identifier mapping is cleared;
- output-derived conversion warnings and conversion summary are cleared with that artifact; and
- project validation returns a visible migration warning instructing the user to reconvert before export or push.

Malformed mapping data is never ignored. A version 4 project with missing or invalid mapping for non-null output is rejected as an invalid project. A legacy project that claims to contain a mapping but provides malformed or contradictory entries is also rejected rather than treated as trustworthy.

Clearing legacy generated output naturally disables copy, download, infrastructure-as-code export, validation, and device push through the canonical output boundary. The selected output format and conversion settings remain available for reconversion.

## Testing Strategy

Implementation follows red-green-refactor cycles.

### Planner unit tests

- punctuation, whitespace, repeated-dash, empty, numeric-prefix, and 63-character truncation collisions;
- case-only names remain distinct;
- non-colliding names remain unchanged;
- every collision-group member is renamed;
- stable output across reordered definitions and references;
- exact duplicate definitions and ambiguous references block;
- a candidate conflicting with an unchanged singleton retries deterministically;
- a test-injected hash collision retries and, when forced persistently, fails closed;
- generated child identities and output names remain stable when arrays reorder; and
- mapping validation rejects duplicates, malformed fields, unknown versions, and contradictory resolution values.

### Namespace and reference tests

- addresses and address sets collide in their shared namespace;
- identical policy names are allowed in different zone pairs but not in the same pair;
- identical local names are allowed in different logical systems;
- root logical-system names remain unique;
- NAT rule-set, rule, and pool scopes bind correctly;
- custom applications and application sets resolve references while predefined applications bypass planning;
- scheduler, routing, BGP, VPN/IKE/IPsec, screen, UTM/IDP/SecIntel, VLAN/bridge-domain, PBF, DHCP, QoS, flow-monitoring, AAA, SNMP, and generated profile names use their catalog scopes; and
- missing or unknown references retain existing warning/error behavior but cannot bind by normalized spelling.

### Integration and migration tests

- Set and XML artifacts use the renamed definitions everywhere they are referenced;
- Set and XML mapping objects are identical for the same input;
- merged output keeps logical-system mappings isolated and cross-link references correct;
- collision warnings appear in `convertWarnings` and the summary count is correct;
- Check Point and SonicWall parsers preserve original definition and reference names;
- canonical output rejects missing or invalid mappings at save boundaries;
- version 4 projects round-trip valid mappings;
- legacy projects without mappings preserve editable configuration but clear output, warnings, and summary;
- legacy projects with valid mappings retain output;
- malformed claimed mappings reject the project; and
- randomized fixtures prove namespace uniqueness, order independence, and reference integrity.

A source-contract/catalog audit scans both converters for identifier serialization and requires each dynamic identifier position to use a planner lookup or an explicit non-symbol exception. The complete JavaScript, Python bridge, dependency-audit, production-build, and artifact-validation gates remain required before publication.

## Acceptance Mapping

- Distinct source names never silently share a generated Junos identifier because every namespace receives a final uniqueness proof.
- Stable source-derived suffixes resolve ordinary normalization collisions without input-order dependence.
- Exact duplicates and ambiguous references fail closed.
- Definitions and references use the same immutable symbol plan in Set, XML, and merge conversion.
- Complete mapping metadata is retained in canonical output and projects.
- Existing UI warnings report each resolution and its output name.
- Parser preservation and catalog enforcement prevent collisions from being erased or bypassed before planning.
- Tests cover punctuation, whitespace, case, dash collapse, empty names, numeric prefixes, truncation, forced hash collisions, namespace scoping, and reference integrity.

## References

- [Juniper address books and address sets](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-address-books-sets.html) documents address and address-set naming within an address book.
- [Juniper security policy configuration](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html) documents policy organization by source and destination zone context.
- [Juniper CLI configuration editing](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/modifying-configuration.html) provides the configuration-editing context used by this design.
