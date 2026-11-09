# hepr-isolation

Design notes and a Windows proof of concept for running coding agents, and the programs Herdr mods start, in OS-enforced isolation under [Herdr](https://herdr.dev).

This is part of HEPR, an execution policy, approval and receipt layer for Herdr. It is an independent project: it isn't part of Herdr or endorsed by its developers, and nothing here is in Herdr today.

## Status

- **Stage 1 (Guard)** gives Herdr policy, approvals and hash-chained receipts. It's built on development branches of herdr-core and herdr-app, which aren't in this repo. Its validation report is in [`docs/HEPR_VALIDATION.md`](docs/HEPR_VALIDATION.md). It still needs an independent review by someone other than its developer.
- **Stage 2 (Isolated)** runs each agent in a Windows AppContainer inside a job object. It's designed and its proof of concept passed; no product code exists yet, and building it waits for that independent review.
- **Mod isolation** is a design note only.

Windows is the only target. Nothing here has been run on Linux or macOS.

## What's here

| Path | What it is |
| --- | --- |
| [`docs/HEPR_STAGE2_DESIGN.md`](docs/HEPR_STAGE2_DESIGN.md) | The Stage 2 design: architecture, launch path, threat model, tests, milestones |
| [`docs/HEPR_STAGE2_POC.md`](docs/HEPR_STAGE2_POC.md) | The proof-of-concept report: what held, and the three findings that changed the design |
| [`docs/HEPR_MOD_ISOLATION.md`](docs/HEPR_MOD_ISOLATION.md) | Design note: permissions for Herdr mods, their programs through Guard and in the container |
| [`docs/HEPR_DECISIONS.md`](docs/HEPR_DECISIONS.md) | Every HEPR decision so far, numbered (D-001 onward) |
| [`docs/HEPR_VALIDATION.md`](docs/HEPR_VALIDATION.md) | The Stage 1 validation report |
| [`poc/`](poc/) | The proof of concept: a standalone Rust crate, `hepr-poc` |
| [`poc/runs/`](poc/runs/) | The raw output of every run. Run 10 and agent run 6 are the final ones |

## Results in brief

On Windows 11 Home, without admin:

- **Containment held.** The agent couldn't read or write outside its workspace, escape through a junction, leave its job, open other processes, reach Credential Manager or see variables it wasn't given. Network on and off both behaved as designed. Starting a process in the container cost nothing measurable (27.3 ms vs 29.4 ms).
- **A real agent works inside.** Claude Code ran logged in, with a token passed in as an environment variable. It answered prompts and read its workspace, and couldn't read a file next to it.
- **Three findings changed the design.**
  1. Git needs to see every parent folder of the workspace, so workspaces under `C:\Users` need a one-time admin setup step.
  2. Node can't run from its own install folder and needs two flags to start a script.
  3. Per-session permission grants are too slow on big repos, so grants are kept per workspace.

Details and numbers are in [`docs/HEPR_STAGE2_POC.md`](docs/HEPR_STAGE2_POC.md).

## Running the proof of concept

You need Windows 10 or 11 and a Rust toolchain. It doesn't need admin.

```powershell
cd poc
cargo build --release
.\target\release\hepr-poc.exe suite <scratch folder>
```

**What `suite` changes on your machine**, and removes at the end:

- an AppContainer profile, `Herdr.Isolated.PocProbe`;
- permission entries on folders under the scratch folder, and on a folder it creates at `C:\hepr-poc-ws`;
- a temporary drive letter (`subst`) for one check;
- about 60,000 small files under the scratch folder, for the timing check.

If a run is interrupted, delete `C:\hepr-poc-ws` and the scratch folder by hand. Then run the suite once more, and it removes the leftover profile when it finishes.

**`agent` mode** runs Claude Code in the container:

```powershell
.\target\release\hepr-poc.exe agent <scratch folder>       # network off
.\target\release\hepr-poc.exe agent <scratch folder> net   # network on
```

- It copies `~/.local/bin/claude.exe` into the scratch folder, and deletes the copy at the end.
- With `net`, it reaches Anthropic's API.
- If `~/.hepr-poc-token` exists, it also runs three short prompts logged in, using that token. Make the token with `claude setup-token`. These prompts use your plan's quota. Delete the file when you're done.

**Logs:** the Windows username in the logs' file paths is replaced with `<user>`.

## License

[MIT](LICENSE).
