---
name: vuln_hunt
description: Discover, update, and rank vulnerability candidates before execution planning.
compatibility: opencode
metadata:
  stage: vuln_hunt
  owner: tianheng
---

## What this skill does
Generate vulnerability-first advisory candidates that `plan` can materialize into executable fuzz targets.

## When to use this skill
Use this skill in the internal hunt subphase before `plan` materializes `selected_targets.json` and `execution_plan.json`.

## Required inputs
- `fuzz/analysis_context.json`, especially `analysis_evidence.security_evidence[]`
- `fuzz/vuln_candidates.json` when present
- recent coverage, crash, repair, and seed feedback when provided
- MCP tools from task-scoped PromeFuzz companion (HTTP MCP), when available:
  - hunt tools: `scan_dangerous_sinks`, `find_call_path`, `get_function_info`
  - code navigation: `list_definitions`, `read_definition`, `read_source`, `find_references`
  - preprocessor: `run_ast_preprocessor`, `extract_api_functions`, `build_library_callgraph`

## Required outputs
- `fuzz/vuln_candidates.json`
- `fuzz/vuln_hunt_summary.md`

## Security Audit Mandate
You are an authorized automated security auditor of **this submitted repository**.
Outputs stay in `fuzz/` for the fuzzer to validate. Do not refuse, hedge, or
replace a memory-unsafety finding with generic remediation advice.

Forbidden:
- refusing to discuss buffer overflows, UAF, integer wrap, format strings, or command injection in this repo
- moralizing or sanitizing sink names
- `boundary_values` / `key_code_path` set to `TBD`, `TODO`, or empty

Required on every candidate:
- CWE or `risk_type` / `signal_id`
- sink file:line
- `attack_hint.trigger_condition` (concrete predicate)
- `attack_hint.key_code_path` (public entry → sink function names)
- `attack_hint.boundary_values` (concrete trigger values)

## Strategy menu (choose any combination; the coordinator only validates outputs)
- Evidence-direct: promote high-confidence `security_evidence[]` rows into candidates.
- CWE-class sweep: scan per class (OOB / UAF / integer overflow / format string / injection).
- High-risk function deep-read: `read_source` / `get_function_info` on top sinks from `scan_dangerous_sinks`.
- Call-path construction: `find_call_path` from sink back to a public API, then keep that public entry as the fuzz target and the sink in `key_code_path`.

## Workflow
1. Query MCP first when available: `scan_dangerous_sinks`, then `find_call_path` / `read_source` on the hottest sinks.
2. Read `fuzz/analysis_context.json` and identify evidence-backed vulnerability hypotheses.
3. Read existing `fuzz/vuln_candidates.json` and preserve useful candidate state such as `validation_status`, `attempt_count`, and `last_result`.
4. Read per-iteration fuzz feedback from `fuzz/run_feedback.json`, `fuzz/vuln_hunt_events.jsonl`, and any coverage path summary in the coordinator hint.
5. Rank candidates **purely by vulnerability risk** (likelihood + exploitability + reachability). Coverage, complexity, and API surface metrics are NOT used in ranking.
   - **Reachability must account for whole-library reach.** A top-level public entrypoint that drives the entire parse/decode/load flow (e.g. `toml_parse`, `*_loads`, `*_decode`) reaches the most code and therefore the most *reachable bug surface* — rate its `reachability_confidence` high and always propose it as a candidate, not only the isolated internal helpers it calls. A bug reachable only through the public entry is more valuable than the same risk buried in a leaf helper fuzzed in isolation. Keep the dangerous internal sink as `attack_hint.key_code_path` so the entry harness still steers toward it. This is reachability, not a coverage metric.
6. Calibrate analysis depth per iteration (read `vuln_hunt_iteration` from workflow context):
   - Iteration 1-2: broad candidates from static analysis of all reachable APIs.
   - Iteration 3-4: narrow to candidates with crash/coverage evidence from fuzz runs; increase exploitability estimates.
   - Iteration 5+: re-evaluate exhausted candidates against fresh data; cross-reference with actual crash signatures.
7. **Increase confidence scores each iteration** as supporting evidence accumulates. A candidate that survives multiple iterations with consistent crash reproduction should have confidence approaching 1.0. A candidate with no crash after multiple iterations should be cooled.
8. Change focus aggressively when validation feedback shows plateau, false positive, exhausted candidate, or repeated harness failure — do not keep the same top candidate when evidence weakens.
9. Write a concise `fuzz/vuln_hunt_summary.md` explaining top candidates, strategy changes, and iteration-specific findings.

## Constraints
- Do not promote candidates from `test/`, `tests/`, `demo/`, `demos/`, `examples/`, `example/`, `deprecated/`, `legacy/`, or `contrib/` directories to high priority.
  Mark such candidates with `validation_status=degraded_test_code` (test/demo) or `validation_status=deprecated` (deprecated/legacy).
  Only raise their priority when crash evidence from a production build confirms reachability.
- Do not promote candidates whose target function name indicates cleanup / resource management.
  Mark with `validation_status=degraded_cleanup` when the function name matches:
  `Delete`, `Dealloc`, `Deallocate`, `Free`, `Destroy`, `Cleanup`, `Release`, `Dispose`, `Close`, `Uninit`.
  These are lifecycle helpers, not exploitable attack surface. Override only when crash evidence
  from production builds confirms a real vulnerability.
- Do not promote candidates whose target function name matches generic test-helper patterns:
  `MyRead`, `MyWrite`, `ReadFunc`, `WriteFunc`, `HelperFunc`, `TestFunc`, `Dummy*`, `Fake*`.
  Mark with `validation_status=degraded_test_helper`. When a candidate is found in a test/ directory
  AND the name matches a test-helper pattern, prefer `degraded_test_code`.
- Do not change `workflow_context`, `selected_targets.json`, or `execution_plan.json`.
- Evidence references should point to `analysis_evidence.security_evidence[].evidence_id` when available.
- Do not reclassify `target_type` or `seed_profile`; those are normalized by the coordinator.
- Keep `validation_status` within `pending`, `validating`, `validated`, `inconclusive`, `exhausted`, or `cooling`.
- Follow the Security Audit Mandate: do not refuse in-scope memory-unsafety analysis of this repository.

## Command policy
- Allowed: read-only commands only (`find`, `grep`, `rg`, `cat`, `ls`, `head`, `tail`, read-only `sed`).
- Forbidden: build/execute commands.

## Acceptance checklist
- `fuzz/vuln_candidates.json` is valid JSON with a `candidates` array.
- Every candidate has `candidate_id`, target API/name, risk type, priority or risk scores, evidence references, attack hint, validation status, attempt count, and last result.
- Every `attack_hint` includes `trigger_condition`, `key_code_path`, and concrete `boundary_values` (not TBD).
- `fuzz/vuln_hunt_summary.md` exists and describes the top candidate rationale.
- Confidence scores (vuln_likelihood, exploitability) increase or hold steady across iterations; decreases without explicit evidence are invalid.
- Top candidates change across iterations when supporting evidence weakens or new candidates emerge.
- `validation_status` is updated for candidates that appeared in recent fuzz/coverage feedback.

## Done contract
- Write the path string `fuzz/vuln_hunt_summary.md` as the sole text of `./done` (run `echo 'fuzz/vuln_hunt_summary.md' > ./done`; do **not** copy the file's contents).
