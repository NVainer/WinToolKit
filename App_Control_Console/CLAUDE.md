# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Tooling for **App Control for Business** (formerly WDAC) policy XML. Each console is a **single, dependency-free HTML file** — open it directly in a browser (no build, no server, no npm). Everything runs client-side; policy files never leave the tab. That privacy stance is stated in the UI and is a hard requirement.

- `AppControlConsole_1.html` — v1: view/edit an existing policy XML (deny-list focused). ES5-style, superseded by v2 but kept.
- `AppControlConsole_2.html` — v2 "App Control Studio": full console (multi-policy workspace, 12 views). Modern ES2020 JS, ~240 KB single file. This is the active version.
- `samples/` — realistic fixtures: base policy, supplemental, Event Viewer XML export (3076/3077/3089/8029). Used for manual testing; keep in sync with parser expectations.

## Run / test

Open the HTML file in a browser (Edge/Chrome — the File System Access API enables save-in-place there). No build step, no test suite; verification is manual/console-driven via exposed hooks (v2: `window.__acs` — `App`, `openPolicyText`, `exportText`, `validatePolicy`, `diffPolicies`, `mergePolicies`, `inspectFile`, `parseEventsXml`, `buildTriageItems`, `evaluateFile`, `buildTemplate`). Typical smoke test: `__acs.openPolicyText(xmlString, 'name.xml', null)`, mutate, then assert `__acs.exportText(p)` round-trips.

The PE/Authenticode/TBS implementation in v2 was validated against Windows' own tooling: `New-CIPolicyRule -Level Hash` (Authenticode SHA1/SHA256) and `Add-SignerRule` (TBS values) produce byte-identical results. If you touch `inspectFile`/`parseCert`/the DER code, re-verify against those cmdlets with a small embedded-signed driver (e.g. `C:\Windows\System32\drivers\amdgpio2.sys`).

## Architecture (v2, `AppControlConsole_2.html`)

One file, sequential `<script>` chunks (B–H), all sharing global scope; boot runs on DOMContentLoaded in the last chunk:

- **Chunk B — core**: ns-agnostic XML helpers (`ln/kids/all/att` — `all(root,'*')` returns every element), catalogs (`OPTIONS` with all rule options 0–20 + unnumbered, `SUPPL_OK` = {5,6,7,13,14,18}, `WELLKNOWN_ROOTS`, `KNOWN_EKUS`, `BLOCK_RECS` LOLBin list, `VULN_DRIVERS`), app state (`App`, `activePolicy()`), the **text patch engine** (`pAttr`, `pDelete`, `pInsert` — creates missing containers per `CONTAINER_ORDER`, `pSetTextByTag`, `pAddOption/pRemoveOption`, `pSyncEl`/`pSyncContainer` — lazy replace-or-insert that serializes the live DOM element at export time), modal/toast, prefs (localStorage) + recents (IndexedDB, stores FileSystemFileHandles), open/save (FSA API with download fallback).
- **Chunk C — model**: `openPolicyText` → `reindex(p)` builds `p.info/options/ekus/rules/signers/scenarios` + membership maps; **mutation API** (`mSetAttr`, `mAddFileRule`, `mDeleteRule`, `mAddSigner`, `mDeleteSigner`, `mToggleOption`, `mSetTopText`, `mSetPolicyInfo`, `mSetRootAttr`…) — every mutation does the **dual write**: live DOM change + ledger entry `{patch(txt), undo()}`; `exportText` replays non-undone patches over `p.raw` (byte-preserving), falls back to `serializeDoc`; `validatePolicy` (~30 lint checks incl. broken refs, orphans, deny-version-semantics gotcha, supplemental option constraints, Intune size, LOLBin allows) with optional `fix` actions.
- **Chunk D — binary**: minimal DER/ASN.1 walker → `parseCert` (subject/issuer CN, TBS hashes per cert-sig-alg), `parsePkcs7` + `orderChain` (leaf found via SignerInfo serial), `inspectFile` (PE parse, **Authenticode hash** via linear method — skip checksum + security-dir entry + cert table, version resource walk, WIN_CERTIFICATE → chain), `evaluateFile` (policy simulation; deny→allow order, version semantics differ for deny: min = "≤ min"), event parsers (`parseEventsXml` normalizes `*Buffer/*Length` field names, correlates 3089 by ActivityID; `parseAhCsv` for MDE Advanced Hunting).
- **Chunks E–H — views**: `setView`/`renderView` dispatch; each `render*(el)` rebuilds its section's innerHTML and wires listeners. Views: library, dashboard (identity edit, audit/enforce switch, explainer), options, rules, signers (+ builder dialogs), rules also has `addFromReferenceFile` (MS Wizard "reference file" flow: drop a binary → `inspectFile` → pick level Publisher/FilePublisher/Leaf/attributes/Hash → `mAddSigner`/`mAddFileRule`; deny drops version bounds to avoid the ≤-semantics trap), inspector, triage (event board → one-click rules / build supplemental), diff (semantic, by content keys `ruleKey`/`signerKey`), merge (dedup + ID rename + ref fix-up, first-policy-wins; `mergePolicies(sources,{optionsFrom:'first'|'union'})`), validate, deploy (generated PS/CiTool/OMA-URI), xml (editable, Apply re-parses + resets ledger).
- **Chunk I — embedded assets** (`ACS_ASSETS`): the machine's real Microsoft template policies (DefaultWindows_Audit, AllowMicrosoft, DefaultWindows_Supplemental, AllowAll, DenyAllAudit, SmartAppControl — raw JSON strings, sourced from `C:\Windows\schemas\CodeIntegrity\ExamplePolicies` on 2026-08-11) plus the Microsoft recommended block rules as gzip+base64 (`blockGz.user` = user-mode v10.2.0.0 from learn.microsoft.com, `blockGz.kernel` = machine's RecommendedDriverBlock_Enforced.xml), decoded at runtime via `gunzipB64` (DecompressionStream). These lines are enormous — never Read the file by raw line range around chunk I; Grep instead. To refresh assets, re-run the PowerShell injection flow (gzip → base64 → replace) and beware here-string backtick mangling of `</script>`.
- **Chunk J — creation wizard** (`createPolicyWizard`): 5-step MS-Wizard-parity flow (type/format incl. legacy + AppId tagging → template cards → name/tags → rule-toggle grid preset from the template's own `<Option>` strings, `WIZ_MAIN_OPTS`/`WIZ_ADV_OPTS` mirror the MS Wizard layout → review + block-rules merge). Builds on an unregistered `parsePolicyText` policy with direct/m* mutations (ledger discarded — final XML re-serialized), strips the blocklists' allow-all rules before merging, merges with `optionsFrom:'first'`. Signed & Reputable = AllowMicrosoft + options 14/15.

### Invariants to preserve

1. **Dual-write**: any new mutation must mutate the DOM *and* attach a working `patch`/`undo` pair; a failing patch silently degrades export to full re-serialization (visible to user via save toast).
2. `pSyncEl`/`pSyncContainer` patches read the DOM **at export time** — safe with undo because undo reverts the DOM first.
3. All user/policy strings pass through `esc()` before `innerHTML`.
4. Deny-rule version semantics are inverted (Min = "that version and lower") — builders default deny versions to `65535.65535.65535.65535`; keep the lint that flags `Min=0.0.0.0` denies.
5. No external requests, one self-contained file, both themes. (Outbound **links** are fine: `DOCS`/`docLink(key,label)` in chunk B render "docs ↗" anchors to learn.microsoft.com — every user-facing mode/choice/option should carry one. All 18 URLs verified live 2026-08-11; `OPT_DOCS` maps option numbers with dedicated pages, everything else falls back to the rules doc.)

## Architecture (v1, `AppControlConsole_1.html`)

One IIFE, ES5-style code, zero dependencies. Key structure:

- **Namespace-agnostic XML helpers** — `ln()`, `kids()`, `all()`, `att()` match elements/attributes case-insensitively by local name, because real-world policies vary in namespace prefixes and attribute casing (`ID` vs `Id`, `SignerId` vs `SignerID`). Always use these instead of `querySelector`/`getAttribute` directly.
- **Central state `S`** — parsed `doc`, the original raw text `raw`, derived collections, ledger, selection, filters, UI prefs.
- **`index()`** rebuilds derived collections from the DOM after every mutation:
  - `S.attribs` — `FileAttrib` rules joined to their referencing `Signer`s and to allow/deny decisions resolved through `SigningScenarios` (`scenarioMap()`).
  - `S.direct` — `Allow`/`Deny` elements directly under `FileRules` (hash/path/PFN/name rules).
  - `S.blanket` — signer-level denies with no `FileAttribRef` narrowing, feeding the risk engine.
  - `S.view` — flattened list for View mode.
- **Risk engine** — `classifySigner()` + `renderRisk()` heuristics: CA-wide denies (critical when the same CertRoot is also allowed, or the CA matches broad Microsoft CAs), version-gap "downgrade bypass" denies, winget/PFN coverage gap, orphaned FileAttribs.
- **Dual-write edit model (THE key invariant)** — every mutating operation must do BOTH:
  1. mutate the live DOM (and push a ledger entry with an `undo` closure), and
  2. attach a **byte-preserving text patch** — a `patch(rawText) -> newText|null` closure (built via `pAttr`/`pDelete`/`pAddPfn`/`pVersion`) that applies the same change to the original file text.
  On export, patches are replayed against `S.raw` so untouched bytes survive verbatim; if any patch fails, export falls back to `XMLSerializer` with a visible warning. New edit features must implement both halves.
- **Ledger** — append-only change log with per-entry undo, "revert all", and TSV export.
- **Rendering** — full re-render via `render()`; tables paginated (`PAGE=250`), column config in `COLS` drives headers/widths/resizing.

## Conventions

- All user/policy-derived strings go through `esc()` before entering `innerHTML`.
- Keep everything in one file per console; no CDN/external requests.
- Light + dark theme via CSS variables on `html[data-theme]`; every new color needs both theme values.
- File naming: consoles are versioned as `AppControlConsole_<n>.html`.
