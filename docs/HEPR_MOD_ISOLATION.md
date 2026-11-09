# HEPR mod isolation (design note)

**Status:** design note only. Nothing here is built, and nothing has been proposed upstream.

**Date:** 2026-11-09. **Code read:** herdr-app `feature/hepr-v2` (`2701554`), herdr-core `feature/hepr-v2` (`e2610f1`). Windows is the only target (D-043).

**In one line:** Stage 2 contains agents; this note covers what it leaves open, which is Herdr's mods. It gives every mod an explicit permission set, routes the programs mods run through Guard, and runs those programs in the Stage 2 container.

## 1. The gap

A mod is a folder of JavaScript in `~/.config/herdr-app/mods/<name>/`. People share mods as GitHub repos tagged `herdr-mod`, which herdr.dev/mods lists. Installing one means copying its folder: there is no manifest, no permission list, no version, no update and no record of where it came from. Herdr's own docs (`docs/security.md`) say a mod "can run programs with your environment, fetch URLs and read files … That is not a security boundary."

What every mod gets today (`src/mods.rs:1155`, `capabilities()`):

| Capability | Grant | What it allows |
| --- | --- | --- |
| Read files | the whole user home | `~/.ssh`, browser profiles, every repo |
| Write files | the app home | Other mods' code, layouts, `keys.json`: a mod can plant code that persists |
| Run programs | unrestricted | Anything the user can run, with the user's environment |
| Network | unrestricted | Any host, any port |
| Clipboard | read and write | Read secrets copied by the user; with `terminal.paste`, type into the focused terminal |
| App commands | all | Every command in the palette, including terminal ones |

Two facts make this matter for HEPR:

- **A mod's local programs bypass Guard.** `exec` without `on` starts the program directly (`run_blocking`, `src/mods.rs:770`), so herdr-core never sees it: no policy, no approval, no receipt. Only `exec` with `on` goes through `hc exec`, where Guard applies.
- **A mod can drive agents.** Through `exec` it can run `hc`, which starts terminals, reads their screens and sends them text. So a hostile mod can instruct an isolated agent from outside its container.

Already in place: only Herdr's own approval dialog and Settings may answer a Guard request (`src/mods.rs:1082`). A mod can see Guard's status but can't approve its own requests.

## 2. Goals and non-goals

**Goals**

1. Each mod runs with the permissions it declared and the user accepted, not with everything.
2. Every program a mod runs is a Guard request, with the mod as the principal: policy, approval and a receipt, like an agent's.
3. Under the Isolated mode, those programs run in the Stage 2 container, scoped to what the mod needs.
4. Installs and updates say what changed in permissions before any new code runs.

**Non-goals**

- Making a mod safe to run *whatever* it declares. A mod granted unrestricted programs can still do anything the user can, and gets a receipt for it.
- Containing the script itself at the OS level. Mods run inside herdr-app's QuickJS engine; their only way out is the host functions Herdr gives them, so those functions are the boundary (§3.1).
- Reviewing mod code, or a mod store with signing. Those are worth doing, but they belong to the herdr.dev side.

**Version split** (the owner's rule: v1 never interrupts, v2 is robust):

- **v1:** existing mods keep working unchanged and are labelled "full access". Programs they run get receipts. Nothing new is asked of the user.
- **v2:** a mod without a manifest asks once, at install, for full access. Declared permissions are enforced, and programs go through Guard approvals.

## 3. Design

### 3.1 A permission manifest for mods

The UI kit Herdr bundles already has this machinery, unused. `vendor/gpui-kit/crates/shell/src/plugin.rs` reads a manifest whose `capabilities` are shown and approved before any code runs, and `capability.rs` enforces:

- read and write roots (through `cap-std`, so `..` and links can't escape);
- programs: denied, an allow-list of names, or unrestricted;
- network: by host, plus HTTP grants scoped to method and path;
- storage, clipboard read, clipboard write.

The change: herdr-app reads each mod's manifest and builds that mod's `Capabilities` from it, instead of the one shared `capabilities()` for all. Herdr needs three grants the kit doesn't have, because they are Herdr's own API:

- `terminals: read` (screens, titles) and `terminals: write` (sending text, `terminal.paste`);
- `commands: [...]`, the app commands the mod may run;
- `hc` treated as a program like any other, so running it needs an explicit grant.

A mod with no manifest gets today's full grant, labelled "full access" in the mods list (v1), or asks once (v2).

### 3.2 Mod programs go through Guard

Local `exec` stops calling `run_blocking` directly. It becomes a `machine.exec` request to the local core, so Guard handles it like any other program:

- **Principal:** `mod:<name>`, which the core takes from the request's origin, not from what the mod says. herdr-app already holds the core connection, so it tags the request when it forwards it.
- **Policy:** `guard.toml` gains rules matched on the mod principal, for example to allow `git` for a git panel and ask for anything else.
- **Receipts:** every program a mod runs is in the hash chain, with the mod's name.
- **Approvals:** in v1 the defaults allow and record; in v2 an undeclared program needs approval.

Cost: one round trip to the local core per program. Stage 1 measured Guard's overhead at about 0.3 ms per decision.

### 3.3 Mod programs in the Stage 2 container

When the workspace is Isolated, a mod's programs run in their own AppContainer profile, `Herdr.Mod.<name>`, through the same backend as agents (`HEPR_STAGE2_DESIGN.md` §3):

- The mod's data folder and its declared read and write roots are the only grants.
- The network is on only if the manifest declares hosts.
- The job object bounds processes, memory and time, as `exec` already bounds time and output.
- The proof of concept already covers this backend: AppContainer plus job, no admin.

A mod's own programs then can't read `~/.ssh` or reach an agent's workspace unless the user granted it.

### 3.4 Installs and updates

Herdr keeps a record of third-party mods next to `installed.json`:

- where the mod came from (repo URL and commit);
- a hash of each file;
- the permissions the user accepted.

On an update, Herdr shows only what changed in permissions, and new permissions need the user's yes before the new code runs. A file that changes on disk with no update behind it, such as a mod writing into another mod, is flagged and the mod is paused.

The write grant also narrows: by default a mod writes only to its own data folder, not to the whole app home.

## 4. Threats this covers

| Threat | Today | With this design |
| --- | --- | --- |
| A mod reads `~/.ssh` and sends it out | Possible, unrecorded | Needs a declared read root and network host, both shown at install; recorded |
| A mod runs a program that does the same | Possible, unrecorded | A Guard request with a receipt; in the container under Isolated |
| A mod rewrites another mod to persist | Possible | Writes limited to its own folder; changed files flagged |
| A mod types into an agent's terminal | Possible (clipboard + paste, or `hc`) | Needs `terminals: write`; `hc` needs a program grant |
| An update adds network access quietly | Possible | The update shows the new permission first |

Not covered: a mod the user granted full access, or a hostile mod that only abuses what it declared. A receipt then records what it did; it doesn't stop it.

## 5. Milestones

Each one waits for M0, the independent validation of Stage 1, like Stage 2.

1. **MI-1, receipts for mod programs.** Local `exec` through `machine.exec` with the `mod:<name>` principal; allow and record by default. v1, no prompts.
2. **MI-2, manifests.** Read a mod's manifest; per-mod `Capabilities`; the three Herdr grants; "full access" label for mods without one.
3. **MI-3, installs and updates.** The source record, file hashes, permission changes on update, own-folder writes.
4. **MI-4, mod programs in the container.** `Herdr.Mod.<name>` profiles on the Stage 2 backend, after Stage 2's M3 and M4.
5. **MI-5, v2 enforcement.** Approvals for undeclared programs; a one-time ask for mods without a manifest.

## 6. Open questions

1. **Upstream.** MI-2 and MI-3 change how every mod is loaded. They work best as a change to Herdr itself, which needs the owner's go-ahead to propose upstream.
2. **The shipped mods.** Herdr's own mods need manifests too; some, like the git panel, need real program grants.
3. **Layouts that load mods.** A layout can pull in mods, so installing a layout should show its mods' permissions together.
4. **Remote `exec`.** Programs a mod runs on another machine already go through `hc exec`; they need the same `mod:<name>` principal on the far side.

## 7. Risks

- **Breaking mods.** Narrowing writes or requiring grants breaks mods that relied on full access. The v1 label-only path avoids that until authors add manifests.
- **Prompt fatigue.** If v2 asks too often, users grant full access to everything. Defaults should allow what a mod declared and only ask for the rest.
- **The engine as the boundary.** §3.1 is only as strong as herdr-app's host functions. Any host function that runs a program or touches files without checking the mod's grant breaks it, so each one needs a test.
