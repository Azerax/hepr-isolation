# hepr-run

Run a coding agent sandboxed to one project folder. Type `hepr-run claude` instead of `claude` in a Herdr pane, or any Windows terminal. Inside the project, the agent works as usual. Outside it, Windows answers **Access is denied**.

```text
C:\code\my-app> hepr-run claude
hepr-run: claude sandboxed to C:\code\my-app (network on)
```

It uses a Windows AppContainer, the sandbox Windows itself uses for Store apps, inside a job object. There's no VM and no driver, and it works on Windows 11 Home.

## Install

You need Windows 10 or 11 and a [Rust toolchain](https://rustup.rs).

```powershell
cd hepr-run
cargo build --release
copy target\release\hepr-run.exe $env:USERPROFILE\.local\bin\
```

Any folder on your PATH works; `~/.local/bin` is where Claude Code installs itself.

**Projects under `C:\Users`** (your Documents, `~/source`, and so on) need one setup step, once per PC. Run it from an administrator terminal:

```powershell
hepr-run --setup
```

This lets hepr-run's sandboxes pass through `C:\Users` to reach a project. They still can't list `C:\Users` or read anything in it. Projects elsewhere, like `C:\code\...`, need no setup. Undo it with `hepr-run --setup --undo`.

## Use

```powershell
hepr-run claude                    # in your project folder
hepr-run --offline claude          # no network
hepr-run --read C:\tools\sdk claude  # also let it read a folder
hepr-run --env CLAUDE_CODE_OAUTH_TOKEN claude   # pass a token in
```

- **The first run in a folder** sets up its sandbox and grants it the folder. A big repo takes a few seconds, once; later runs start straight away.
- **The agent's home is its own.** Its logins, settings and history live in the sandbox, one set per project, away from yours. So the agent starts logged out in each new project. Log in there, or pass a token with `--env`. Claude Code's `claude setup-token` makes one.
- **Ctrl+C, colors and resizing** work as they do without the sandbox. The agent shares the terminal.
- **When the agent exits** (or you close the pane), anything it left running is stopped.

| Command | What it does |
| --- | --- |
| `hepr-run --status` | This folder's sandbox, and what it was granted |
| `hepr-run --list` | Every folder with a sandbox |
| `hepr-run --forget` | Removes this folder's sandbox and every grant, including the agent's saved logins and history for it |

## What it stops, and what it doesn't

**Stopped by Windows:**
- reading or changing your files outside the project: `~/.ssh`, browser profiles, other repos;
- reading another project's files, even one that has its own sandbox;
- touching other apps' windows or other processes;
- seeing your environment variables, unless you pass one with `--env`;
- any network access, with `--offline`.

**Not stopped:**
- **What it does inside the project.** It can change or delete anything there, so use git.
- **Network access, when on.** With the network on (the default, since agents need their API), it can send what it can read, meaning the project, anywhere.
- **Running it without hepr-run.** Running `claude` on its own is unsandboxed. hepr-run is opt-in each time.

## Limits

- **Node-based agents aren't supported yet.** Agents installed with npm (Gemini CLI, Codex) are scripts that need Node, and Node's install folder doesn't allow sandboxes. hepr-run says so and stops. Single-file agents like Claude Code work: hepr-run copies them where the sandbox can run them, and copies again only when they update.
- **Herdr's `hc` command doesn't work inside the sandbox.** Herdr's control pipe doesn't accept sandboxed callers.
- **Tools you installed in your user folder** (`~/.cargo`, `~/.rustup`, Python in AppData) aren't visible unless you add them with `--read`.
- **Windows only.**

## Tested

On Windows 11 Home, not elevated:
- writing in the project works, and reading next door is denied;
- git works;
- a second project can't read the first;
- `--offline` blocks the network;
- variables pass only with `--env`;
- exit codes pass through;
- Claude Code runs, and its interactive screen draws in a pseudo console set up like a Herdr pane's;
- Ctrl+C behaves as without the sandbox;
- `--forget` leaves no grant or profile behind.

The `--setup` grant was tested on a scratch folder; the step on `C:\Users` itself needs admin and hasn't been run in testing yet. Logging in from inside the sandbox hasn't been tried; passing a token with `--env` worked in the proof of concept.
