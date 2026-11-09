# HEPR Stage 2 proof of concept (M1)

**Date:** 2026-11-09.

**Machine:** Windows 11 Home 26300, not elevated.

**How it ran:**
- Started at the owner's request before M0 (the independent validation of Stage 1). See D-044.
- The probe is a standalone crate, `poc/`. It lives in neither repo, has no product wiring, and was built offline from cached crates, so nothing was downloaded.
- Each run creates the AppContainer profile `Herdr.Isolated.PocProbe`, then deletes it with every ACL grant it added.
- Every check below ran. Results come from `poc/runs/stage2-poc-run10.md`, the 10th run; runs 1–9 fixed the probe itself.

**Verdict:** the base design holds. AppContainer, job object, ConPTY and the per-session pipe all work without admin, and every OS-enforcement check (T1–T14) passed. Three findings change the design:
1. **Parent folders:** a workspace's parent folders must be made visible to the container.
2. **Node:** Node can't run from its own install, and needs flags to start a script inside a container.
3. **Per-session ACL grants are too slow** for big trees.

The gemini CLI didn't run; Claude Code, tried instead at the owner's request, ran fully inside (§3).

## 1. What held (go)

| Mechanism | Evidence (all PASS) |
|---|---|
| AppContainer + ConPTY + job (P1) | `cmd` and Windows PowerShell started inside, took input, printed, resized and exited normally. Same result as an uncontained control |
| Conhost as a broker (P8) | The child couldn't open its Medium conhost for write or inject (access denied, even query-limited). Posting to the console window failed: invalid handle, from the job's handle limit. *Partial:* console API calls themselves weren't explored |
| Secrets (T1) | A secret outside the workspace, the real `~/.ssh` (open only) and the profile root: all access denied. The same read uncontained succeeds |
| Writes (T2) | Outside dir, the user's `%TEMP%`, `C:\Users\Public`: denied. Inside the workspace: works |
| Junctions (T3) | Reading through a junction from the workspace to outside: denied. Creating one from inside was itself denied |
| Process tree (T4, T5, T11) | `processes = 5`: 4 children started, the 5th got error 1816. `CREATE_BREAKAWAY_FROM_JOB`: denied. A child still running at session end was gone with the job |
| Memory (T7) | `memory_mb = 256`: 64 MB fine, 512 MB refused |
| Network (T6) | Off: external connections denied (10013); loopback times out. On: external works, loopback still blocked. Matches the design's table |
| Session pipe and principal (P7, T8) | The container connects to its own pipe, and the server identifies it by the token's AppContainer SID. A pipe with herdr's DACL and label is denied |
| Env and credentials (T9) | A variable the host has but didn't pass is absent. Credential Manager enumeration is denied |
| Other processes (T12) | Opening the host process (Medium) for write or inject: denied |
| Auto-run files (T13) | `.git/hooks/pre-commit` is writable, as expected; the M6 report stays necessary |
| Launch cost (T14) | Median start-to-exit of a trivial process: 27.3 ms contained vs 29.4 ms uncontained (no measurable cost) |

## 2. What changes the design

**F1. A workspace's parent folders must be made visible (P3).**
- **Under the profile, git fails** inside the container: `cannot lock ref 'HEAD': unable to create directory`. Your repos live under `Documents\GitHub`, so this is the common case.
- **Cause:** git checks each parent folder, and an AppContainer can't see them. `C:\Users`, the profile and `AppData` grant no AppContainer access.
- **Proof, rebuilt in scratch** (`C:\hepr-poc-ws\a\b\ws`):

  | Setup | git |
  |---|---|
  | Workspace directly under `C:\` | Works (the drive root isn't needed) |
  | Parents not visible | Fails, exactly as in the profile |
  | Each parent granted *read attributes + traverse* only (non-inherited, set with `SetFileSecurity`, so nothing propagates) | Works. Listing a parent and reading a file beside the workspace are still denied |
  | Top parent left ungranted | Fails |

  So **every parent except the drive root** must be granted.
- **Mapping the workspace to its own drive with `subst`** didn't help: git resolves the real path anyway.
- **What it costs:**
  - The parents up to the profile root are the user's own folders, so they can be granted without admin.
  - **`C:\Users` needs admin.**
- **Design change:**
  - A **one-time, admin-approved setup step** grants a Herdr capability SID (derived from a fixed capability name) read-attributes + traverse on `C:\Users` alone, non-inherited. Every Herdr container carries that capability.
  - Without that step, Isolated refuses workspaces under `C:\Users`, says why, and suggests a workspace outside the profile (for example `C:\dev\…`), where no admin is needed.
  - Parent grants go in the ledger like workspace grants.

**F2. Node (P2).**
- **Node's own install can't run.** `C:\Program Files\nodejs` has a protected ACL with no ALL APPLICATION PACKAGES entry, unlike `C:\Program Files` and `Git`. So the design's assumption that "Program Files is readable" is **wrong for Node**. Granting it would need admin.
  - A user-owned copy of `node.exe` runs fine (`v22.16.0`).
- **Starting a script fails** with `EPERM: lstat 'C:\'`: Node's `realpathSync` stats the drive root, which a container can't read.
  - `--preserve-symlinks --preserve-symlinks-main` avoids it: `node hello.js` then ran and read the workspace.
- **Design change:**
  - A `tools` entry can be a **copied runtime**: Herdr keeps a user-owned copy, refreshed when the source changes.
  - Node-based agents start with those two flags.
  - **The same admin setup step** could grant the Herdr capability read access on chosen tool folders instead.

**F3. Per-session ACL grants are too slow on big trees (P5).**
- An inheritable grant then revoke took **3.1 s / 3.0 s on 10,000 files** and **15.8 s / 14.9 s on 50,000 files** (about 0.3 ms per file).
- A Node repo with `node_modules`, or a Rust repo with `target/`, easily passes 50,000 files.
- **Design change:** grants are **per profile** (workspace), set once and kept until "Forget workspace". This is the fallback the design named.
  - **The cost:** while no session runs, the container SID keeps access to the workspace. No process holds that SID then, so it is harmless.

## 3. Not done or not settled

- **Claude Code runs inside (P2, agent run).** The owner chose a different agent over chasing gemini. `hepr-poc agent` ran a copy of `~/.local/bin/claude.exe` (v2.1.319, a native binary) in the tools folder, network off, in a git workspace at `C:\hepr-poc-ws\a\ws` whose parents had the setup step's grant. Results in `poc/runs/stage2-poc-agent2.md`: 8 checks, all PASS.
  - `git init` and `commit` inside: work.
  - `claude --version` and `--help`: work. No Node, so none of F2's problems.
  - `claude -p` with no login: exits 1 after 3.7 s, "Not logged in". It never sees the user's login: its home is the container's own folder, and Credential Manager is denied.
  - Interactive behind ConPTY: the welcome screen draws, then reports "Failed to connect to api.anthropic.com: ENOTFOUND", so network-off held. It didn't exit on two Ctrl+C at its first-run screen; the job ended it.
  - It kept state only in its own folder (`.claude`, `.claude.json`, `Temp`); a file beside the workspace stayed denied.
  - **Network on (owner's go-ahead; runs 3 off and 4 on, 9 checks each, all PASS):**
    - `curl` to `api.anthropic.com` from inside: "Could not resolve host" with the network off; HTTP 405 (reached, no credentials) with it on.
    - The interactive TUI with the network on got past the connection check to its first-run theme picker. With it off, it showed the connection error and exited 1.
    - Every denial held with the network on as well: a file beside the workspace stayed "Access is denied".
  - **Logged in (run 6, network on, 12 checks, all PASS).** The owner made a separate token with `claude setup-token` and saved it to a file; the probe read it on the host side and passed it in as `CLAUDE_CODE_OAUTH_TOKEN`, as `pass_env` would. The user's own login file was never touched; the token appears in no log, and the file was deleted afterwards.
    - `claude -p` answered in 4.0 s.
    - With the `Read` tool it read the workspace's `README.md`.
    - Asked to read the file beside the workspace, it couldn't. Claude Code's own `Read` tool refused because it couldn't examine the path, which the container hides. The OS denial itself shows in the shell check ("Access is denied").
    - Run 5 doesn't count for the last two: `--allowedTools Read` took the prompt as a tool name, so those prompts never ran. Run 6 uses `--allowedTools=Read`.
- **The gemini CLI didn't run** (not pursued further).
  - Via `gemini.cmd`, `cmd` reports "Access is denied".
  - Run directly with the flags, `node gemini.js --version` hangs until the 90 s timeout, with the network off.
  - Cause unknown. **Unverified guess:** gemini re-launches itself as a child `node` without the flags.
  - Next: trace with network still off, or try a different agent. Nothing reached the network.
- **LPAC:** `cmd` itself is denied under LPAC with only these grants. LPAC stays out of the base.
- **Not run:**
  - an SSH push (no remote);
  - `cargo build` (needs a copied or granted `~/.rustup`, about 1–2 GB);
  - console API abuse beyond the window and process checks (P8 is partial);
  - T10 (refusal when a launch step fails), which belongs with product code;
  - per-host network filtering (M7, admin).
- **Cleanup verified:**
  - the profile was deleted (no `%LOCALAPPDATA%\Packages\Herdr.Isolated.PocProbe`);
  - no `subst` drive and no `C:\hepr-poc-ws` remain;
  - no probe file was left in `%TEMP%` or `C:\Users\Public`.

## 4. Next

**The owner decides:**
- decided: the admin setup step for workspaces under `C:\Users` (F1, D-045);
- ~~whether to chase gemini or test another agent~~: decided, another agent; Claude Code ran (§3).

**Then:** M2 (`isolation.rs`, the pure planner) can start once M0 is done, with F1–F3 folded into the design (`HEPR_STAGE2_DESIGN.md`, §3.4 and §4).
