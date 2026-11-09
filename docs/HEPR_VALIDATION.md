# HEPR Stage 1 validation (Phase 6)

**Date:** 2026-11-08.

**Environment:**
- Windows 11 Home (26300), Rust stable.
- herdr-core and herdr-app on branch `feature/hepr-v2`.
- Every result below comes from a test or measurement that ran. Anything not run says so.

## Acceptance criteria (PRD §11)

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Herdr works normally with HEPR disabled | **Met (Windows)** | Without `guard.toml`, the mode is Standard: no checks and no receipts. Both full suites pass. In the performance table, the Standard row matches the pre-HEPR behavior (no Guard work). |
| 2 | Guard can be enabled through a user-facing control | **Met** | Settings > Agent Protection: mode picker plus "Ask before sensitive actions" and "Strict" switches. Checked by hand: the switch wrote `guard.toml`. Render test `agent_protection_settings_…`. |
| 3 | Controlled Core commands evaluated before dispatch | **Met** | `terminal.run` and `machine.exec`. e2e `guard_stops_what_its_policy_does_not_allow_before_it_happens`: no terminal was made and the marker file was not written. |
| 4 | Controlled Core file operations evaluated before mutation | **Met** | `file.write` and `file.edit`. Same e2e: the file is unchanged and no temp file was started. Also `guard_sees_through_junctions_and_trailing_dots`. |
| 5 | Plugin actions evaluated before spawning | **Not met (out of scope)** | Desktop-only by decision (D-011, D-028). Herdr 1's plugin runtime is not part of the desktop app. Nothing was built for it. |
| 6 | Unauthorized operation prevented at the boundary | **Met** | e2e tests above; the review findings fixed below. |
| 7 | Users can approve with a scoped grant | **Met** | e2e `guard_lets_an_approved_request_through_once`. Manual: the dialog's Allow once and Allow for this session both worked. |
| 8 | Single-use grants cannot be consumed twice | **Met** | `an_approval_is_used_once_even_by_requests_racing_for_it` (16 threads, 1 wins). e2e: the third write is stopped again. |
| 9 | Decisions and outcomes produce receipts | **Met** | e2e `guard_keeps_verifiable_receipts_of_what_it_decided` (write, stop, exec failure, run). |
| 10 | Offline verifier detects defined integrity failures | **Met** | Receipt tests (below). e2e `hc receipts verify` exits 13 and 14 on tampered copies. |
| 11 | Core and desktop suites pass in the validated environment | **Met (Windows, the only target: D-043)** | Core 202/202 and app 322 + 4 (logs `phase6-*-tests.log`). Unix-only tests (`tests/guard.rs`, `m0`, the Unix symlink tests) are outside this version's scope and were not run. |
| 12 | Performance measurements documented | **Met** | Below and in `HEPR_TEST_RESULTS.md`. |
| 13 | Product explains Guard's limitations | **Met** | Dialog ("not a sandbox"), Settings limitation text, `SKILL.md`, `HEPR_KNOWN_LIMITATIONS.md`. |
| 14 | No separate heavyweight app | **Met** | Two QuickJS frame mods inside the existing app. No server, no web UI. |
| 15 | Changes documented and organized for upstream review | **Met (not submitted)** | One commit per phase on `feature/hepr-v2` in each repo, plus the `HEPR_*` documents. Nothing was pushed or proposed upstream. |

**Stage 1 verdict:** complete for the desktop on Windows, the only platform this version targets (D-043), except criterion 5 (out of scope by decision). Under PRD §10, Stage 2 implementation waits for an independent validation of Stage 1. This report is the developer's own validation, not an independent one.

## PRD §8 test lists

**Policy:**

| Case | Evidence |
|---|---|
| Allowed, denied, approval-required | `inside_a_workspace_…`, `rules_match_…` |
| Invalid policy, engine unavailable | `invalid_policies_…`, `a_missing_policy_is_standard_and_a_broken_one_stops_everything` |
| Policy reload | Read per call (cached at most 1 s and only while the file is unchanged). e2e tests rewrite `guard.toml` between calls. |
| Workspace mismatch, normalization | `normalize_…`, `windows_paths_…`, `windows_trailing_dots_and_spaces_…` |
| Symlink, reparse point | Windows: e2e `guard_sees_through_junctions_and_trailing_dots` (a junction out, and a junction to a folder not there yet). Unix symlinks: `a_link_out_of_the_workspace_is_outside`, written but **not run**. `a_dangling_link_is_judged_by_where_it_leads` **skips itself on this machine**, because Windows symlinks need developer mode or admin. |
| Argument matcher mismatch | `rules_match_…` |

**Grants:**

| Case | Evidence |
|---|---|
| Valid, expired, revoked, wrong workspace or command | `grants.rs` tests, e2e |
| Wrong remote target | By construction, with no dedicated test. Grants live in one core. A `--on` request is checked by the target machine's core against its own grants. |
| Single use, race, restart | See criterion 8; `an_unused_once_grant_outlives_a_restart_…` |
| Different environment or content | `targets_match_only_after_normalization` (new: `extra` is part of the target) |

**Execution:**

| Case | Evidence |
|---|---|
| Denied run or file change has no effect | See criteria 3 and 4 |
| Denied plugin command | n/a (criterion 5) |
| Approved operation reaches the existing path | e2e (approved write lands) |
| Execution failure produces a receipt | e2e (`exit 3` gives `failed`) |
| Existing API clients remain compatible | `compat.rs` (the API only grows) passes. The schema diff is additions, plus 2 corrected descriptions. New params (`context`) are optional. |

**Receipts:** every case has a test. See the Phase 4 table in `HEPR_TEST_RESULTS.md`, plus the new `a_record_must_be_written_its_one_way` and `an_anchor_says_what_it_cannot_show_…`.

**UI:**

| Case | Evidence |
|---|---|
| Settings persist, mode changes take effect | Manual: the Strict switch wrote `preset`. The core reads the policy per call. |
| Approval details | Render tests (operation, file, reason, environment variables) and the manual check |
| Denials show useful messages | `guarded` errors carry the reason, the policy, and a hint naming the request ID. Checked by hand. |
| Cancellation does not authorize | Manual check found that Esc closed the dialog without answering; fixed in `9972f3b` and re-checked. `a_request_has_one_dialog_closed_once_answered`. |
| History accurate | Render test plus the manual check of Activity |
| UI unavailable cannot authorize | `a_request_waits_for_a_person_only_while_herdr_can_ask` |

## Independent review and hardening

A separate review agent read the Guard code without seeing my reasoning, and was told to report only findings it could trace through the code. It reported 11 findings. Each was checked against the code before fixing:

| # | Finding | Severity | Outcome |
|---|---|---|---|
| 1 | A write through a symlink to a file not there yet was judged by the link's name, but the write followed the link (could reach `~/.ssh/authorized_keys` or the grants file) | High | **Fixed:** `real()` follows dangling links as the write does. Windows e2e via a dangling junction; the Unix test is written. |
| 2 | Home secret folders protected only by how they're written (`~/.ssh` as a link escaped) | High/Med | **Fixed:** protected both as written and where they lead. `home_secrets_are_protected_where_they_really_lead`. |
| 3 | Windows trailing dots or spaces (`.aws.\credentials`) got past protection for entries not there yet | Med | **Fixed** in `normalize`. Unit test and e2e. |
| 4 | `machine.add` / `connect --via` runs a local shell command unchecked (Unix) | Med | **Documented** as not controlled (limitation). |
| 5 | Grants and rule-allows ignored the request's env, stdin and content (`GIT_SSH_COMMAND`, `PATH`, `LD_PRELOAD`) | Med | **Fixed:** grants bind to env names plus a digest of env, content or edits. A rule-allowed program with a code-loading variable asks (`env_override`). The dialog shows the variables. The request digest covers them. |
| 6 | A checkpoint "proved" no earlier record was removed even when the journal's start was cut | Med | **Fixed:** docs corrected; a note says what can't be shown when the journal doesn't start at record 1. |
| 7 | Deleting `guard.toml` silently turned Guard off | Med | **Fixed:** once Guard has been on, a missing policy fails closed until Settings (or the file) says `mode = "off"`. `a_deleted_policy_does_not_turn_guard_off`. |
| 8 | `terminal.run` receipts took "remote" from the caller's claim | Low | **Fixed:** now from the connection. |
| 9 | The verifier accepted non-canonical lines (duplicate keys) | Low | **Fixed:** each line must be its canonical form. Test added. |
| 10 | An invalid journal that couldn't be moved aside got the new chain appended | Low | **Fixed:** the journal records nothing; best-effort operations go on and `required` ones stop. |
| 11 | Secret hiding missed `Key: value` inside a longer argument | Low | **Fixed:** an inline scan, which also fixed a bug it exposed (a shell line was cut short). Test added. |

## Performance: Standard vs Guard (PRD §7)

Measured end to end through `hc connect`:
- Release build, Windows 11.
- 3 interleaved rounds, each mode in its own fresh scratch session.
- 500 file writes of 1 KB and 100 `machine.exec` of `cmd /c exit 0`, after 20 warm-up writes.
- The script is in the session scratchpad, not committed.

| Mode | Core start | file.write p50 / p99 | machine.exec p50 / p99 | Memory idle / after load | Receipts |
|---|---|---|---|---|---|
| Standard (no guard.toml) | 77 ms | 1.24 / 2.29 ms | 187 / 322 ms | 9.8 / 11.3 MB | 0 |
| Guard observe | 98 ms | 1.43 / 3.45 ms | 184 / 299 ms | 9.8 / 13.1 MB | 1860 |
| Guard enforce | 91 ms | 1.53 / 3.64 ms | 187 / 244 ms | 9.8 / 13.3 MB | 1860 |
| Guard enforce, receipts required | 87 ms | 1.93 / 4.88 ms | 149 / 219 ms | 9.8 / 13.3 MB | 1860 |

- **Writes:** enforce adds about 0.3 ms per call at the median, and `required` receipts (an fsync per record) about 0.7 ms.
- **Program starts:** the cost is lost in process-spawn time (a ~180 ms exec; the spread between rounds is larger than Guard's cost).
- **Startup:** no measurable difference (77–98 ms, noise).
- **Memory:** no idle difference. +2 MB after load, from the in-memory window of recent receipts (at most 2000).
- **Background work:** none. No task or polling exists for HEPR.
- **PRD targets:** median policy evaluation < 5 ms (met); idle memory overhead < 25 MB (met); no persistent polling (met).
- **The hardening's cost:** before the policy cache, the same workload measured 2.5 ms per enforced write. Resolving the home secret folders on every call cost about 1 ms. The cache, keyed on the policy file's size and time and held at most 1 s, removed that.

## Not done in Phase 6

- **Linux and macOS runs:** out of scope; this version is Windows only (D-043).
- **An independent human validation of Stage 1,** which the PRD requires before Stage 2 implementation.
