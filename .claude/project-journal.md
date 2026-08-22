# Project Journal — Sherpa

Coarse-grained event log. Major changes only: bug fixes, new features, architecture decisions, discoveries.

<!-- JOURNAL-START -->

## 2026-08-22

- **Fix**: Unstuck two CI-failing tests — `fix_build` skill now includes the contract phrase `canonical vcpkg names`; missing-vcpkg `run_cmd` test aligned to `SHERPA_VCPKG_STRICT` fail-open default. Sentinel overlayfs mtime failures left untouched.

## 2026-05-15

- **Fix**: CK2 idle timeout — opencode CLI buffers Write tool calls internally during large JSON generation; model takes 10+ min to generate 79KB vuln_candidates.json with zero stdout. Added stage-specific idle timeout overrides: vuln_hunt (1800s via `SHERPA_OPENCODE_IDLE_TIMEOUT_VULN_HUNT_SEC`), plan (1200s via `SHERPA_OPENCODE_IDLE_TIMEOUT_PLAN_SEC`). Deployed to dev (b5784efc1).
- **Jobs**: Submitted cJSON (7e3fe1bc), uriparser (9fd5d884), libwebp (d3ae0b32) for vuln hunting on dev.
- **Docs**: Created CLAUDE.md at project root with 14-node workflow graph, routing rules, CK reference, and self-update rules. Created `.claude/project-journal.md` and `.claude/habits.md` for self-evolving documentation.

<!-- JOURNAL-END -->
