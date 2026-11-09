| ID | Check | Expected | Observed | Result |
| --- | --- | --- | --- | --- |
| ctl | read the outside secret, NOT contained | OK | OK read 17 bytes | PASS |
| ctl | cmd in ConPTY, NOT contained | 2 replies, exit 0 | 2 replies, exit 0 | PASS |
| P1 | cmd in ConPTY: input, output, resize, exit | 2 replies, exit 0 | 2 replies, exit 0 | PASS |
| P1 | Windows PowerShell in ConPTY | reply, exit 0 | 1 replies, exit 0 | PASS |
| P8 | post WM_USER+1 to the console's window | not delivered | ERR Invalid window handle. (os error 1400) | PASS |
| P8 | open conhost (pid 24724) for write/inject | DENIED | DENIED Access is denied. (os error 5) (write/inject); query-limited: denied | PASS |
| T1 | read a secret outside the workspace | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T1 | open the real ~/.ssh for listing (no read) | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T1 | open the user profile for listing | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T2 | write outside the workspace | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T2 | write the user's %TEMP% | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T2 | write C:\Users\Public | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T2 | write inside the workspace | OK | OK written | PASS |
| T3 | make a junction in the workspace to outside | (recorded: allowed or not) | OK exit Some(1):  Access is denied. | PASS |
| T3 | read through a junction that was already there | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T4 | start 10 children with processes = 5 | at most 4 start (the probe is the 5th) | OK 4 of 10 started; then: Not enough quota is available to process this command. (os error 1816) | PASS |
| T5 | start a child with CREATE_BREAKAWAY_FROM_JOB | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T11 | a child still running when the session ends | ended with the job | 0 probe processes left (was 1); session: [timed out] | PASS |
| T7 | commit 64 MB with memory_mb = 256 | OK | OK 64 MB committed | PASS |
| T7 | commit 512 MB with memory_mb = 256 | fails | ERR could not reserve 512 MB: memory allocation failed because the memory allocator returned an error | PASS |
| ctl | connect 1.1.1.1:443, NOT contained | OK | OK connected to 1.1.1.1:443 | PASS |
| T6 | network off: connect to 1.1.1.1:443 | fails | DENIED An attempt was made to access a socket in a way forbidden by its access permissions. (os error 10013) | PASS |
| T6 | network off: connect to a local listener | fails | ERR connection timed out | PASS |
| T6 | network on: connect to 1.1.1.1:443 | OK | OK connected to 1.1.1.1:443 | PASS |
| T6 | network on: connect to a local listener | fails | ERR connection timed out | PASS |
| P7 | connect to its own session pipe | OK | OK connected | PASS |
| P7 | the server identifies the client by token | AppContainer SID matches | client pid 53832, AppContainer SID matches | PASS |
| T8 | connect to a pipe with herdr's DACL and label | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T9 | read a variable the host has but didn't pass | ERR | ERR absent | PASS |
| T9 | read PATH (passed) | OK | OK present | PASS |
| T9 | enumerate Windows Credential Manager | nothing of the user's | DENIED Access is denied. (os error 5) | PASS |
| T12 | open the host process (Medium) for write/inject | DENIED | DENIED Access is denied. (os error 5) (write/inject); query-limited: denied | PASS |
| T13 | write .git/hooks/pre-commit | OK | OK written | PASS |
| P3 | git in a workspace under the user profile | works | OK exit Some(1):  error: cannot lock ref 'HEAD': unable to create directory for C:/Users/<user>/AppData/Local/Temp/claude/C--Users-<user>-Documents-GitHub-Herdr-Dev/41877815-73fc-459c-beae-466c87dd9eeb/scratchpad/poc/ws/.git/HEAD | FAIL |
| P3 | git in a workspace at C:\hepr-poc-ws | (recorded) | OK exit Some(0): e8c5d66 first / ## master / HEPR_GIT_DONE | PASS |
| P3 | git in C:\hepr-poc-ws\a\b\ws, parents unseen | fails like the profile case | OK exit Some(1):  error: cannot lock ref 'HEAD': unable to create directory for C:/hepr-poc-ws/a/b/ws/.git/HEAD | PASS |
| P3 | the same with each parent granted attributes + traverse only | works | OK exit Some(0): e8c5d66 first / ## master / HEPR_GIT_DONE | PASS |
| P3 | list a parent folder (still not granted) | DENIED | DENIED Access is denied. (os error 5) | PASS |
| P3 | read a file beside the workspace in a parent | DENIED | DENIED Access is denied. (os error 5) | PASS |
| P3 | the same with the top parent left ungranted (as C:\Users would be) | (recorded) | OK exit Some(1):  error: cannot lock ref 'HEAD': unable to create directory for C:/hepr-poc-ws/a/b/ws/.git/HEAD | PASS |
| P3 | git in the workspace mapped to W:\ (subst) | works | OK exit Some(1):  error: cannot lock ref 'HEAD': unable to create directory for C:/Users/<user>/AppData/Local/Temp/claude/C--Users-<user>-Documents-GitHub-Herdr-Dev/41877815-73fc-459c-beae-466c87dd9eeb/scratchpad/poc/ws/mapped/.git/HEAD | FAIL |
| P3 | the container sees W:\ at all | OK | OK opened for listing | PASS |
| P2 | gemini --version, node.exe from Program Files (tools granted, network off) | (recorded) | OK exit Some(1):  Access is denied. | PASS |
| P2 | diagnose: read the node.exe copy | OK | OK read 85119640 bytes | PASS |
| P2 | diagnose: read gemini.cmd | OK | OK read 350 bytes | PASS |
| P2 | diagnose: node.exe copy --version | prints a version | OK exit Some(0): v22.16.0 | PASS |
| P2 | diagnose: node gemini.js --version directly | prints a version | OK exit Some(1):  node:fs:2745 /     const out = binding.lstat(base, false, undefined, true /* throwIfNoEntry */); /                         ^ /  / Error: EPERM: operation not permitted, lstat 'C:\' /     at Object.realpathSync (node:fs:2745:25) /     at toRealPath (node:internal/modules/helpers:61:13) /     at Function._findPath (node:internal/modules/cjs/loader:778:22) /     at resolveMainPath (node:internal/modules/run_main:39:23) /     at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:163:20) /     at node:internal/main/run_main_module:36:49 { /   errno: -4048, /   code: 'EPERM', /   syscall: 'lstat', /   path: 'C:\\' / } /  / Node.js v22.16. | FAIL |
| P2 | node --preserve-symlinks(-main) hello.js (reads the workspace) | runs | OK exit Some(0): HELLO_FROM_NODE 4 | PASS |
| P2 | node --preserve-symlinks(-main) gemini.js --version | prints a version | [timed out] | FAIL |
| P2 | gemini --version with node.exe copied into the tools folder | prints a version | OK exit Some(1):  Access is denied. | FAIL |
| P2 | the same under LPAC | (measuring: expected to break) | DENIED Access is denied. (os error 5) | PASS |
| T14 | start-to-exit of a trivial probe, median of 15 | measured | contained 27.3 ms, uncontained 29.4 ms | PASS |
| P5 | grant and revoke an inheritable ACE on 10000 files | measured | grant 3.11 s, revoke 2.96 s | PASS |
| P5 | grant and revoke an inheritable ACE on 50000 files | measured | grant 15.76 s, revoke 14.87 s | PASS |
