# HEPR decisions

- **D-001 Fresh start.** An earlier attempt left uncommitted edits in `Herdr-Dev/herdr*`. This workspace starts from clean `master` and leaves that attempt untouched.
- **D-002 v1 = Guard, no UX interruption.** The owner's direction: v1 does what it can without interrupting the user experience, and v2 (Isolated) is the robust one. As a result:
  - the default mode is Standard;
  - the `default` preset asks only for protected paths, writes outside trusted workspaces, and explicit rules.
- **D-003 The engine lives in herdr-core.** Desktop's effects all go through herdr-core. A mod or external plugin can't block anything.
- **D-004 Pure evaluator.** No IO and no clock (herdr-core rule: "deciding code stays separate from IO"). The caller supplies the timestamp. Same inputs give the same decision.
- **D-005 The policy file is separate (`guard.toml`) and always protected.** It isn't a `config.toml` table. This lets the guard protect its own folder without making ordinary config edits ask.
- **D-006 Unknown keys are errors.** `deny_unknown_fields`, because a typo must not silently weaken a policy.
- **D-007 Protected paths match ignoring case on every OS. Workspace containment folds case only on Windows.** Over-matching protection is safe because it only asks more often. Over-matching a workspace would allow writes outside it.
- **D-008 Path normalization is lexical in the engine.** Symlink and reparse-point resolution belongs to the Phase 2 IO wrapper, which canonicalizes the longest existing ancestor.
- **D-009 OS difference behind `platform::WINDOWS_PATHS`.** The engine takes it as a flag, so the Windows rules are tested on every OS.
- **D-010 No new dependencies in Phase 1.** Phase 4 will need `sha2`, to be recorded when it's added.

- **D-011 Desktop only.** The owner chose to leave Herdr 1 (`herdr` repo) plugins out of v1.
- **D-012 Check sites are in the handlers, not one central chokepoint.** Only the handlers know the final argv (after the shell or template is resolved) and the final path. `server.rs` only sees raw params.
- **D-013 The policy is read on every call** (like `config.toml`): no cache, no watcher, no background task. It costs about 0.2 ms when on and about 12 µs when off.
- **D-014 New error kind `guarded`, exit code 12.** Additive: existing clients see one more error kind on four methods. The agent manual tells agents not to work around it.
- **D-015 Policy paths are resolved like request paths.** A workspace written through a link still matches.
- **D-016 Commit style.** herdr-core's AGENTS.md asks for single-line commits with no AI co-author lines on upstream PRs. Commits on this private branch follow this session's attribution rule. Squash and reword before any upstream PR.

- **D-017 The approval key is a per-start file in the core's state folder,** not an environment variable or a CLI command. A desktop that attaches to an already-running core can still approve, and nothing puts the key into an agent's environment or `--help`.
- **D-018 Approvals are bound to a waiting request, never to a caller-made target.** `guard.approve` names a request the core itself created from a normalized operation. Callers can't describe an operation of their own to approve.
- **D-019 Wait only when someone can answer.** With no approver connection, a request fails at once. A UI that's gone can never approve by timing out.
- **D-020 Save before use.** A grant's use is written to disk before the effect. A crash afterwards leaves it used ("authorized, not dispatched" will be recorded by Phase 4 receipts), never usable again.
- **D-021 Session grants aren't saved.** They end with the core, as their name says.

- **D-022 Phase 5 before Phase 4.** The owner chose to build the desktop side first, so approvals are usable before receipts exist.
- **D-023 Answers are not app commands.** Agents run app commands with `herdr-app do`. So answering is a host function, `guardAnswer`, that only Herdr's own frame mods (`frame-approve`, `frame-settings`) may call. Any other mod gets an error.
- **D-024 The approval dialog has no Enter shortcut.** Someone typing into a terminal must not approve by accident. Esc denies.
- **D-025 The desktop finds the key through `guard.status.key_file`.** The app launches `hc connect` and doesn't know the core's state folder. Exposing the path, not the key, is harmless. A core on another machine has no key file locally, so the app doesn't answer for remote cores.
- **D-026 Settings edit only `mode` and `preset` in `guard.toml`.** Workspaces, rules and protected folders stay hand-edited, and the page shows them and the file's path. Writes use the same "only if unchanged since read" retry that settings.json uses.
- **D-027 Only live requests open a dialog.** Requests already pending when Herdr connects show under Settings > Agent Protection, "Waiting for you", instead of a burst of dialogs at startup (v1: no interruption).
- **D-028 The Herdr 1 plugin adapter (HEPR-008) is out of scope** (D-011).
- **D-029 SHA-256 is implemented in-house** (`sha256.rs`, ~70 lines, checked against the FIPS 180-4 vectors, including the million-'a' one). The alternative was `sha2`, about seven crates in a core that keeps 51. This is a hash function, not a protocol, so the risk is small and the test vectors cover it.
- **D-030 Receipts are on by default whenever Guard is (observe or enforce), and best-effort** (v1: no interruption). If writing fails, it's logged and the operation goes ahead. `receipts = "required"` flushes each record to disk and stops an operation whose authorization or dispatch can't be recorded (PRD: "failure to record that authorization must prevent dispatch"). Standard mode keeps no receipts, so it has no overhead.
- **D-031 One journal per core state folder**, `receipts.jsonl`, as canonical JSON lines (keys sorted, no spaces). Sequence numbers and the hash chain continue across restarts and rotations. At `receipt_retention_mb / 2` (default 16 MB, so 8 MB) the file becomes `receipts.1.jsonl` and a new file continues the chain with a `journal`/`continued` record.
- **D-032 Receipts per operation:** an authorization (the decision, the grant, a claimed actor and correlation ID, a request digest), a dispatch just before the effect, and a completion that the core saw itself (`verified: true`). Nothing is "reported" yet: no caller reports results. `terminal.run` completes when the terminal starts. Its program's later exit is not a receipt.
- **D-033 Ends the core couldn't see are recorded, never guessed.** An operation dropped after authorization gets `recovery`/`not_dispatched`. One dropped after dispatch, or a core stopped mid-operation, gets `recovery`/`interrupted`; the next start records it.
- **D-034 Verification states:**
  - Changed, missing-in-the-middle, reordered or renumbered records, and a checkpoint mismatch, are `INVALID`.
  - A record cut short by a crash, an unknown version, a signature, an empty journal, or a checkpoint beyond the end, is `INCOMPLETE_OR_UNVERIFIABLE`.
  - Operations with no end yet are listed (`open`) but don't change the state: a live journal always has some.
  - `hc receipts verify` exits 0, 13 (invalid) or 14 (incomplete), and needs no core.
- **D-035 A journal that fails verification at start is kept aside** (`receipts.<ms>.invalid.jsonl`), and a new chain starts with a record saying so. Appending to a broken chain would hide where it broke. A record cut short at the end is removed, and the removal is itself recorded.
- **D-036 Receipts hide secret-looking arguments** (a value after `--token`/`--password`-style flags, `NAME=...` or `Name: ...` where the name contains token, secret, password, auth, apikey or credential, `Bearer ...`, and common token prefixes). They keep 32 arguments of at most 200 characters each. The request digest covers the real request. This is a heuristic, listed as a limitation.
- **D-037 Checkpoints are the anchor for now:** `hc receipts checkpoint` prints `<seq>:<hash>`, kept wherever the person likes, and `verify --checkpoint` gives `VALID_ANCHORED`. Signed checkpoints are designed for (a `sig` field makes a record unverifiable to this version, not silently accepted) but not built.
- **D-038 A request's environment and content are part of what is approved.** A grant binds to the env names plus a digest of the env values and of the content written or the edits made. A rule allowing a program doesn't allow it with a code-loading variable set (PATH, LD_*/DYLD_*, GIT_SSH_COMMAND, NODE_OPTIONS, ...): that asks (`env_override`). In the default preset, programs in the workspace are already allowed, so nothing new asks there (v1). For `terminal.run` the caller's env is weighed before the core adds its own pager variables.
- **D-039 Once Guard has been on, a missing `guard.toml` fails closed** (marker `<state>/guard.was-on`, in the protected state folder). Turning Guard off is a policy that says `mode = "off"`, which Settings writes.
- **D-040 Links that lead nowhere yet are followed** when Guard resolves a path, as `files` does for the write. Home secret folders are protected both as written and where they lead. On Windows, trailing dots and spaces are dropped from names, as Windows does.
- **D-041 The parsed policy is cached** for as long as `guard.toml`'s size and modification time are unchanged, and at most 1 second. Re-reading and re-resolving it per call cost about 1 ms per enforced write.
- **D-042 Receipt lines must be canonical.** A reformatted line, or one with a repeated key, is INVALID: different readers could see different content.
- **D-043 This version of HEPR targets Windows only** (owner's decision, 2026-11-09). Validation, acceptance and support claims cover Windows. Unix code paths that Guard touches are left in place and still compile, but are not validated or claimed; Unix-only tests are kept, not deleted, and are not part of the acceptance run.
- **D-044 The Stage 2 proof of concept ran before M0**, at the owner's request (2026-11-09). It is a standalone probe (`poc/`), in neither repo and with no product wiring, so it is not the production implementation PRD §10 gates. M2 and later still wait for M0.
- **D-045 Workspaces under `C:\Users` use a one-time admin setup step** (owner, 2026-11-09; PoC F1). The step grants a Herdr capability SID, derived from a fixed capability name, *read attributes + traverse* on `C:\Users` alone, not inherited. Every Herdr container carries that capability. Without the step, Isolated refuses workspaces under `C:\Users`, says why, and suggests one outside the profile. Nothing runs elevated after the step.
- **D-046 hepr-run, a standalone launcher, was built before M0** at the owner's request (2026-11-09). It runs an agent in the Stage 2 sandbox (AppContainer + job, per-project grants, the D-045 setup step) from any terminal, outside Herdr. It is opt-in per run and has none of the built-in mode's guarantees (no holder frame, no `hc` principal, no receipts), so it is not the Stage 2 product; M2 and later still wait for M0.

## Open questions for the owner

1. **Upstream rules.** herdr-core and herdr-app AGENTS.md require the maintainer's agreement for behavior changes and new core features. That's fine for a private fork, but it matters if this is ever offered upstream.
