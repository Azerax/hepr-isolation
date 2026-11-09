# HEPR Stage 2 "Isolated": technical design (Phase 7)

**Date:** 2026-11-09.

**Status:** design only. Nothing here is built. The proof of concept ran on 2026-11-09 (`HEPR_STAGE2_POC.md`); its findings are marked **[PoC]** below.
- PRD §10 gate: building Stage 2 waits for an independent validation of Stage 1 (milestone M0 below).
- Platform: Windows only (D-043).
- Where this says "to verify in the PoC", the claim comes from Windows documentation and experience, and has not been tried on this machine.

## 1. What Isolated adds over Guard

**Guard decides at Herdr's own doors.** A program already running with the user's rights can still read `~/.ssh`, write anywhere the user can, and open any network connection.

**Isolated has Windows enforce the limits on the process itself, and on everything it starts:**

| Limit | Enforced by |
|---|---|
| Filesystem | AppContainer token: no access unless granted |
| Process tree | Job object (no breakaway, process count) |
| Network | AppContainer capabilities |
| Resources | Job object (memory, CPU, process count) |
| Credentials | A clean environment, and no access to the profile or the user's agents |
| Herdr's own controls | The agent reaches `hc` only through its own pipe, as a known principal |

Everything Guard does still applies inside the session: policy, approvals, grants, receipts.

**The rule from PRD §4.1:** if any part of the isolation can't be set up, the session doesn't start. Herdr says which part failed and why. It never starts the session under Guard instead.

## 2. Where it attaches in today's code

The design rests on these facts from `herdr-core` (`feature/hepr-v2`, `e2610f1`).

**Terminals:**
- The core asks a **holder** process to start each terminal: the `SPAWN` frame in `holder_proto.rs`, handled by `Holder::spawn` in `holder.rs`.
- The holder calls `platform::spawn_pty` (`platform/windows.rs`). That function:
  - creates a ConPTY;
  - starts the program with `CreateProcessW(CREATE_SUSPENDED)`, with handle inheritance off;
  - puts it in a new job object (`KILL_ON_JOB_CLOSE | BREAKAWAY_OK`), then resumes it.
- `BREAKAWAY_OK` exists so that `hc`'s own core and holders, started from inside a terminal, outlive it. Isolated must remove it.
- `spawn_pty` doesn't check the result of `AssignProcessToJobObject`. Guard doesn't depend on the job. Isolated does, so its path must fail if assignment fails.

**`machine.exec`:**
- It starts the program in the core itself: tokio `Command` with `CREATE_SUSPENDED`.
- `ExecGroup::new` (`platform/windows_exec.rs`) then joins it to a job and resumes it.
- std's `Command` can't pass `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, so isolated exec needs its own `CreateProcessW` path.

**The `hc` pipe:**
- `pipe_security()` allows only the user's own SID and SYSTEM, with a Medium (or High) no-write-up label.
- An AppContainer process can't open it: its access check also needs the container's SID or ALL APPLICATION PACKAGES, and its integrity level is Low.
- That is the safe default. Isolated adds a separate pipe for each session (§3.5).

**The holder protocol:**
- The protocol has a `VERSION` field and `DRAIN` for older builds.
- An older holder doesn't know the isolation fields. If it got isolation inside the ordinary `SPAWN` frame, serde would drop the unknown field and start the program **unisolated**. That is a silent downgrade.
- So isolation needs a new frame and a capability check (§3.3).

**This machine** is Windows 11 **Home**:
- **Not available:** Windows Sandbox, and Hyper-V management (both need Pro or Enterprise).
- **Available:** the hypervisor (virtualization-based security is running), and WSL2 can be installed.
- **Where the agent tools live:**
  - `gemini` is under `%APPDATA%\npm`, inside the user profile;
  - `node` is under `Program Files`;
  - `python` is under the profile;
  - `cargo` is under `~/.cargo`.
- This shapes the design: tools inside the profile aren't readable from an AppContainer until they're granted.

## 3. Architecture

### 3.1 Modules

These follow the rules Guard already uses: deciding code kept pure, OS code in `platform/`, and small files.

```
herdr-core/src/
  isolation.rs              pure: IsolationPolicy, Plan, plan(), Capabilities, refusal reasons
  isolation/tests.rs
  isolation/ledger.rs       the record of ACL grants we added (for undo and crash recovery)
  platform/windows_isolation.rs   OS: profile, ACLs, token attributes, job limits, session pipe
  holder_proto.rs           + SPAWN_ISOLATED frame, Welcome.isolation
```

The PRD's illustrative trait, split so the pure part can be tested:

```rust
/// What this machine can do: probed once, cheap, no side effects.
pub struct Capabilities {
    pub app_container: bool,        // CreateAppContainerProfile present and usable
    pub less_privileged: bool,      // LPAC (all-application-packages policy)
    pub conpty_in_container: bool,  // found by the PoC; probe at startup
    pub loopback_exempt: bool,      // only with an admin-installed exemption (§3.6)
    pub os_build: u32,
}

/// Pure: from the policy and request to an exact plan, or a refusal that names the reason.
pub fn plan(policy: &IsolationPolicy, caps: &Capabilities, req: &Request) -> Result<Plan, Refusal>;

/// Platform: carries out a Plan. The only code that touches the OS.
pub trait Backend {
    fn capabilities(&self) -> Capabilities;
    fn prepare(&self, plan: &Plan) -> io::Result<Prepared>;   // profile, ACL grants (ledgered)
    fn launch(&self, prepared: &Prepared, spawn: &Spawn) -> io::Result<(Pty, Process)>;
    fn release(&self, prepared: Prepared) -> io::Result<()>;  // undo grants, delete session pipe
}
```

A `Plan` is plain data that can be serialized, so it can:
- cross to the holder in `SPAWN_ISOLATED`;
- appear in a receipt as a digest;
- be compared in tests.

### 3.2 Policy (`guard.toml`)

The existing policy file gains a new section. Isolated shares Guard's policy, approvals and receipts (PRD §1).

```toml
mode = "isolated"            # standard | observe | enforce | isolated

[isolated]
network = "off"              # off | on   (allowlist later; §3.6)
memory_mb = 8192             # job memory limit, whole tree
processes = 256              # active process limit
cpu_percent = 100            # hard CPU cap (job CPU rate control); 100 = none
tools = ["%APPDATA%\\npm", "%USERPROFILE%\\.cargo"]   # read+execute only
pass_env = ["ANTHROPIC_API_KEY"]                      # only these from the user's env, by name
```

- **The workspace** is read-write: the workspaces Guard already knows.
- **Program Files and Windows** are mostly readable by ALL APPLICATION PACKAGES, unless the profile is LPAC. **[PoC]** Not all of it: `C:\Program Files\nodejs` has a protected ACL without it, so Node needs a user-owned copy in `tools`, or the admin setup step.
- **Nothing else** is reachable: not the profile, other drives, `~/.ssh`, `%APPDATA%` beyond what `tools` grants, or Herdr's state folder.

### 3.3 Launch path (terminals)

The core asks the holder to start a terminal with a `SPAWN_ISOLATED` frame that carries the `Plan`. Ten steps, in order:

1. **Check the holder.** The core sends `SPAWN_ISOLATED` only to a holder whose `Welcome` says `isolation: 1`.
   - Any other holder: the request is refused (`isolation_unavailable: holder too old`).
   - The ordinary `SPAWN` frame never carries isolation.
2. **Profile.** The holder creates or opens the AppContainer profile (`Herdr.Isolated.<workspace-hash>`). One profile per workspace, so sessions of one workspace share a SID.
3. **Grants.** The holder grants the profile's SID access to the workspace and the `tools` paths:
   - the workspace gets modify;
   - `tools` get read and execute;
   - each ACE is written to the ledger before it is set.
4. **Session pipe.** The holder creates the session's own `hc` pipe (§3.5) and adds `HC_ENDPOINT=<session pipe>` to the env.
5. **Environment.** The env is built only from:
   - the Windows essentials: `SystemRoot`, `PATH` limited to granted directories, `TEMP` pointing inside the container's own folder;
   - the variables `pass_env` names;
   - the variables the request sets after Guard weighed them.

   Nothing else is inherited.
6. **ConPTY**, created as today.
7. **Attribute list:**
   - `PSEUDOCONSOLE`;
   - `SECURITY_CAPABILITIES` (the container SID plus the network capabilities, if any);
   - for LPAC, `ALL_APPLICATION_PACKAGES_POLICY`;
   - `HANDLE_LIST` (empty);
   - `CHILD_PROCESS_POLICY` is **not** set, because agents must be able to start child processes.
8. **Create** the process with `CreateProcessW(CREATE_SUSPENDED)`.
9. **Job object:**
   - limit flags: `KILL_ON_JOB_CLOSE`, `ACTIVE_PROCESS`, `JOB_MEMORY` and `DIE_ON_UNHANDLED_EXCEPTION`; **no** `BREAKAWAY_OK` or `SILENT_BREAKAWAY_OK`;
   - CPU rate control;
   - UI restrictions: desktop, clipboard read, global atoms, handles, system parameters, exit Windows.

   **Any failed call stops the launch.** The process is terminated, the grants are released, and the core gets `SPAWN_FAILED` with the reason.
10. **Resume.** Receipts: the dispatch receipt carries `isolation: {plan_digest, profile_sid}`.

`machine.exec` in an isolated workspace uses the same backend from the core: the same plan, but no ConPTY.

### 3.4 Filesystem: a ledger of ACL grants

An AppContainer can reach a file only if its ACL names the container's SID (or ALL APPLICATION PACKAGES). That makes the container default-deny, which is the point. But granting the workspace means **changing ACLs on the user's own folders**.

**The rules:**
- **Ledger before change.** Every ACE added is recorded first (path, SID, mask) in `<state>/isolation-ledger.jsonl`, using the journal's write discipline.
  - When the session ends, the ACEs are removed.
  - When the core starts, any left behind after a crash are removed.
  - Only ACEs we added are removed: we match on the SID, which is ours alone.
- **Inheritable ACEs on the workspace root, per profile.** **[PoC]** A grant costs about 0.3 ms per file (15.8 s for 50,000 files), too slow per session. So the grant lives as long as the workspace's profile, and "Forget workspace" removes it.
- **[PoC] Parent folders.** Every parent of the workspace except the drive root gets *read attributes + traverse*, non-inherited, set with `SetFileSecurity` (no propagation). Without it, git fails. With it, listing a parent and reading its other files are still denied.
  - Under the profile, `C:\Users` needs admin. A one-time, admin-approved setup step grants a Herdr capability SID that access on `C:\Users` alone. The owner chose this (D-045).
  - Without the setup step, Isolated refuses workspaces under `C:\Users` and says why.
- **Never grant** these:
  - the drive root, the profile root, `%APPDATA%` as a whole, or Herdr's config or state folders;
  - any path that `protect` names.

  `plan()` refuses those, and the refusal names the path.
- **Links.** A junction or symlink inside the workspace that points outside it gets no access. Windows checks the target's own ACL, and the target doesn't name our SID. Stage 1 could only reason about this case (D-040); here the OS blocks it (tested by T3).

### 3.5 Herdr's own controls

The agent inside reaches `hc` only through `\\.\pipe\herdr-<session>-iso-<id>`. That pipe's DACL allows only the container's SID, with a Low label. This gives the core a **runtime-established principal** (PRD HEPR-001):
- A request on that pipe comes from that isolated session, and nothing the caller says can change that.
- The server also checks the client token's AppContainer SID (`GetNamedPipeClientProcessId` plus the token), so a stolen handle doesn't help.
- Receipts record `principal: isolated:<session>`.

**On that pipe, Guard's rules apply as usual, plus three more:**
- A `--on <machine>` request is refused. Leaving the box through Herdr is a separate decision (§9).
- Approvals still go to a person. The container can't read `guard.key`, the grants file or `guard.toml`, because the state and config folders are never granted.
- Asking for another isolated session is allowed, and gets the same plan or a stricter one, never a looser one.

### 3.6 Network

**AppContainer network control is coarse:**

| Setting | Capabilities | Result |
|---|---|---|
| `off` | none | No outbound connections at all, loopback included |
| `on` | `internetClient`, `privateNetworkClientServer` | Internet and LAN. Loopback is still blocked, unless an admin exemption is set |

**Per-host allowlists.** A rule like "only `api.anthropic.com`" would need either:
- a loopback proxy in the core plus a loopback exemption for the container (installing it needs admin); or
- Windows Filtering Platform filters on the container's SID (also admin).

Both are **later and optional** (milestone M7). Isolated won't quietly install either.

Most agents need their model API, so **`network = "on"` is the practical default for agent sessions**:
- Isolated then protects files, processes and credentials, not network exfiltration.
- The settings page says exactly this.
- A session with `network = "on"` is labelled **"Isolated, network open"**, in the Settings mode line and in its receipts.

### 3.7 Credentials

- **The profile** is unreadable: `~/.ssh`, `~/.aws`, browser profiles, `.gitconfig` credentials, `%APPDATA%` secrets.
- **The user's ssh-agent and Git Credential Manager pipes** are user-only, so the container can't use them.
  - git push over SSH from inside fails by design. The agent asks Herdr instead, and Guard's approval path handles it.
  - A later option is a narrow, approved forwarder.
- **Windows Credential Manager** is out of reach, because the container can't reach its broker the way the user can (to verify in the PoC, T9).
- **Environment:** only the variables `pass_env` names, which the dialog shows when it asks.
  - A key passed this way is readable by the agent. That's the trade-off the user makes by naming it.
  - Receipts record the name, never the value.

## 4. Platform capability matrix (Windows)

| Mechanism | Home | Pro/Ent | Admin needed | What it enforces | In the design |
|---|---|---|---|---|---|
| AppContainer token | yes | yes | no | Default-deny files, registry, named objects, other processes; Low integrity; network by capability | **Core of Isolated** |
| LPAC | yes (Win10 1703+) | yes | no | Also drops ALL APPLICATION PACKAGES access (Program Files, much of Windows) | Optional "strict"; breaks most toolchains. PoC P2 measures how badly |
| Job object | yes | yes | no | Kills the tree as one; process, memory and CPU limits; no breakaway; UI limits | **Yes** |
| Restricted or Low-integrity token alone | yes | yes | no | Blocks write-up only. Can still **read** almost all user files | Rejected as the base (no read confidentiality) |
| ACL grants (SID-specific ACE) | yes | yes | no (own files) | Gives the container the workspace and tools | **Yes**, with the ledger, per profile [PoC] |
| Parent-folder grants (attributes + traverse) | yes | yes | no, except `C:\Users` (admin, once) | git and similar tools can walk up to the workspace | **Yes** [PoC] |
| Node in a container | yes | yes | no, with a copied `node.exe` | Node stats `C:\` when starting a script: needs `--preserve-symlinks --preserve-symlinks-main` | **Yes** [PoC] |
| Loopback exemption | yes | yes | **yes** | The container can reach a local proxy | M7, optional |
| WFP filters on the container SID | yes | yes | **yes** | Per-host or per-port network rules | M7, optional |
| Windows Sandbox | **no** | yes (feature) | to enable | A whole disposable VM | Not baseline. Possible later backend for Pro |
| Hyper-V VM | **no** (no manager) | yes | to enable | A VM boundary | Not baseline |
| WSL2 | yes (to install) | yes | to install | A Linux VM with Linux isolation inside | Possible later "VM" backend. Not in this Windows-only version's baseline |
| Mandatory Integrity Control / UIPI | yes | yes | no | Low process can't send messages to or write into Medium windows and processes | Comes with AppContainer |

The capability probe reports each row that matters. When the baseline (AppContainer, job, ConPTY-in-container) can't be set up, `mode = "isolated"` refuses. Settings shows that state as "Isolated: not available on this PC: <reason>".

## 5. Threat model

**Assets:**
- user secrets (profile, keys, tokens);
- files outside the workspace;
- other processes and windows;
- network reach;
- Herdr's own controls: `guard.toml`, grants, `guard.key`, the receipt journal, the main `hc` pipe;
- the integrity of the workspace as the user's own unisolated tools will later see it.

**The adversary:** an agent, or code it runs, that is compromised or prompt-injected and has arbitrary code execution **inside** an isolated session.

**Out of scope:**
- Windows kernel or driver exploits;
- an administrator, or a same-user unisolated process, attacking the user;
- hardware side channels;
- a person approving a harmful request;
- availability attacks beyond the job limits.

| Vector | Control | Residual risk |
|---|---|---|
| Read `~/.ssh`, browser data, tokens | AppContainer default-deny; profile never granted | Anything a `pass_env` or `tools` grant exposes |
| Write outside the workspace | Default-deny; only the workspace is granted | Folders whose ACL already grants ALL APPLICATION PACKAGES write (rare; T2 scans common ones) |
| Junction or symlink out of the workspace | The OS checks the target's ACL | None found. T3 tests it |
| Escape the process tree | Job without breakaway; checked assignment; suspended start | None by design. T5 |
| Open or inject into user processes | AppContainer plus Low integrity: no access to Medium processes | T12 |
| Window messages, clipboard | UIPI plus job UI limits | ConPTY's conhost runs at Medium and is driven by the child: a broker the PoC must examine (risk R1) |
| Re-enter Herdr unchecked | Main pipe unreachable; the session pipe is Guard-checked and principal-tagged | Approvals are still a human decision |
| Change policy or grants, forge approvals | State and config never granted | None by design. T8 |
| Tamper with receipts | The journal lives in state (not granted) | Same as Stage 1 for the user's own processes |
| Leave something that later runs **outside** the box: `.git/hooks`, `.vscode/tasks.json`, `package.json` scripts, `.envrc`, editor configs, DLLs beside tools | Not preventable by isolation: the workspace must be writable | **Real.** Mitigation: list auto-run files changed in the session, show them on the session summary, and record them in a receipt. M6 |
| Exfiltrate via the network | `network = "off"` blocks it; `on` doesn't | With `on`, anything the workspace holds can leave. Stated in the UI |
| Brokered OS services that AppContainers may call (some COM and RPC) | Not controlled individually | Windows' own AppContainer surface. LPAC narrows it |
| ACEs left after a crash | Ledger plus startup cleanup | A crash between the ACE and the ledger can't happen, because the ledger is written first. A ledger entry with no ACE is harmless |
| Holder too old, or isolation fails part-way | New frame plus the capability check; failure ends the launch | None by design. T10 |

## 6. Proof of concept (after M0)

Built as a standalone probe crate outside both repos (`poc/`), with no product wiring. Run only with scratch homes.

| Step | What it shows | Pass if |
|---|---|---|
| P1 | AppContainer + ConPTY + job: `cmd` and `pwsh` start, take input, resize, end | Interactive and stable. If ConPTY refuses a container child, Isolated can't host interactive agents and the design needs another console path (stop and decide) |
| P2 | A real agent CLI inside (the installed `gemini`, under `%APPDATA%\npm`) with `tools` grants; then the same under LPAC | It runs with only the declared grants. The list of what broke becomes the default `tools` set |
| P3 | `git status`, `git commit`, `cargo build` in a granted workspace | They work. A push over SSH fails, as designed |
| P4 | `network` off and on: TCP to an external host and to a loopback listener | Matches §3.6 exactly |
| P5 | Time to grant and remove an inheritable ACE on herdr-core's tree (with `target/`) | Picks between the per-session and per-profile grant |
| P6 | Job limits: process count, memory, breakaway attempt | Each limit holds |
| P7 | Session pipe: container reaches it, not the main pipe; the core sees the container SID | Matches §3.5 |
| P8 | Conhost (R1): what console APIs let a Low child do to the Medium conhost | No write to files, processes or windows outside the container |

**Needs from the owner before the PoC:**
- **Running `gemini` (P2)** talks to Google with the user's account. That needs a go-ahead, or a different agent. **[PoC]** gemini hung; Claude Code ran instead, network off (`HEPR_STAGE2_POC.md` §3).
- **P5 changes ACLs** on a scratch copy of the repo, never on the real one.
- **Nothing needs admin.** Nothing is downloaded.

**Output:** `HEPR_STAGE2_POC.md`, with a go or no-go for each mechanism.

## 7. OS-enforcement acceptance tests

PRD §6: they must show that **direct OS actions** are blocked, not only actions taken through `hc`.
- **How they run:** each test starts a real isolated session through the product path. A small test program then makes the raw calls itself: `CreateFileW`, `connect`, `CreateProcessW`, `OpenProcess`.
- **Where:** `tests/isolation_windows.rs`.
- **Isolation:** scratch `XDG_*` and HOME, and a scratch workspace.

| # | Inside the session, it tries | Expected |
|---|---|---|
| T1 | Read a secret file in a scratch "profile" outside the workspace; read the real `%USERPROFILE%\.ssh` (open only, no content read) | ACCESS_DENIED |
| T2 | Write outside the workspace (scratch dir, `%TEMP%` of the user, `C:\Users\Public`); write inside | Outside denied; inside works |
| T3 | Make a junction in the workspace to an outside folder, write through it; same with a pre-existing symlink | Denied |
| T4 | Start children and grandchildren; exceed `processes` | All in the job; the extra start fails |
| T5 | `CreateProcessW(CREATE_BREAKAWAY_FROM_JOB)`; end the holder | Breakaway fails; the whole tree ends with the job |
| T6 | `network = "off"`: connect to an external IP and to a local listener. `on`: the same | Off: both fail. On: external works, loopback fails |
| T7 | Allocate past `memory_mb` | The allocation fails, or the tree is ended, and it is recorded |
| T8 | Open the main `hc` pipe; read `guard.key`, grants, `guard.toml`; call `hc file write` outside the workspace through the session pipe | Pipe and files denied; the `hc` call goes through Guard and its receipt shows `principal: isolated:…` |
| T9 | Read a variable the user has set but `pass_env` doesn't name; call `CredEnumerateW` | Absent; no user credentials |
| T10 | Isolation unavailable: holder without the capability; a failure injected at each launch step | Session refused with the reason; nothing started; no Guard fallback; a receipt records the refusal |
| T11 | Kill the holder and core mid-session, then restart | The tree is gone; ledgered ACEs removed; recovery receipt written |
| T12 | `OpenProcess` on the user's herdr-app; `PostMessage` to a Medium window | Denied; dropped |
| T13 | Write `.git/hooks/pre-commit` | Allowed (it's the workspace), **and** listed in the session's auto-run report |
| T14 | Performance: isolated start vs Guard start; ACL grant time; idle memory | Measured against PRD §7, not assumed |

Tests T1–T13 run in CI-style `cargo test` on Windows, without admin. M7's admin-only network tests are separate and opt-in.

## 8. Milestones

| M | Content | Exit gate |
|---|---|---|
| **M0** | **Independent validation of Stage 1** (someone other than the developer: rerun `HEPR_VALIDATION.md`, review the code) | Written sign-off. **Nothing below starts before it** |
| M1 | PoC P1–P8 | `HEPR_STAGE2_POC.md`: go or no-go per mechanism; this design revised to match |
| M2 | `isolation.rs`: policy section, `plan()`, refusals, capability probe; unit tests | Pure, deterministic; `[isolated]` parses or refuses clearly |
| M3 | Holder `SPAWN_ISOLATED`, `Welcome.isolation`, backend launch (AppContainer, job, checked assignment); exec path | T4, T5, T10, T12 pass |
| M4 | ACL grant ledger, release, crash recovery | T1, T2, T3, T11 pass; P5's numbers acted on |
| M5 | Session pipe and principal; env building; `pass_env` in the dialog | T8 and T9 pass |
| M6 | Desktop: Isolated in the mode picker (today "Isolated (coming)"), "not available: why", "network open" label, auto-run report on session end, Activity shows the principal | Render tests; a manual check; T13 |
| M7 | Optional, admin-gated network allowlist (loopback proxy plus exemption, or WFP) | Only if the owner wants it; separate tests |
| M8 | Validation: T1–T14, performance, independent review as in Phase 6 | `HEPR_STAGE2_VALIDATION.md` |

**Version split** (the owner's rule: v1 never interrupts the user, v2 is the robust one):
- Isolated belongs to v2.
- It is opt-in per workspace.
- It asks once, the first time, which tool folders to grant. Settings shows a suggested list from P2.
- After that it asks nothing beyond what Guard already asks.

## 9. Decisions this design proposes

These are proposed here, and are recorded as D-044 to D-049 when M1 confirms them:
- **AppContainer plus a job object is the base backend.** A restricted or Low-integrity token alone is rejected, because it can still read the user's files.
- **VM backends are not the base:** Windows Sandbox, Hyper-V and WSL2. This PC (Home) lacks the first two, and WSL2 would be a Linux design.
- **Isolation never travels in the ordinary `SPAWN` frame.** An older holder means refusal.
- **An ACE is ledgered before it is set**, and removed by the SID we own.
- **`network = "on"` is allowed but labelled.** Per-host filtering needs admin and stays optional.
- **The principal comes from which pipe the call arrived on, plus the client token.** Never from what the caller says.
- **Requests from an isolated session that reach other machines (`--on`) are refused** until a design for them exists.

## 10. Open risks

- **R1, conhost:** ConPTY's conhost runs at Medium on behalf of a Low child. P8 must show it isn't a usable broker. If it is, interactive isolated sessions need a different console path, or a VM backend.
- **R2, toolchain breakage:** agents installed in the profile (npm globals, Python, cargo) need `tools` grants. Granting them read and execute also exposes whatever else is in those folders. P2 shows how wide the default must be.
- **R3, ACL work on big trees:** P5. Per-profile grants trade time for persistence.
- **R4, network-open sessions** can exfiltrate the workspace. The protection is mostly honest labelling, until M7.
- **R5, auto-run files:** the workspace is writable, so files the user later runs outside isolation (git hooks, task configs) can still be planted. M6 reports them; nothing in Stage 2 can stop it.
