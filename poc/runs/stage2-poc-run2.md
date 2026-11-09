| ID | Check | Expected | Observed | Result |
| --- | --- | --- | --- | --- |
| ctl | read the outside secret, NOT contained | OK | OK read 17 bytes | PASS |
| ctl | cmd in ConPTY, NOT contained | 2 replies, exit 0 | 1 replies, exit 258 | FAIL |
| P1 | cmd in ConPTY: input, output, resize, exit | 2 replies, exit 0 | 1 replies, exit 258; output: "[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1b}[K\r\n\u{1 | FAIL |
| P1 | Windows PowerShell in ConPTY | reply, exit 0 | 1 replies, exit 0 | PASS |
| P8 | post WM_USER+1 to the console's window | DENIED or no window | [H]0;C:\Users\<user>\AppData\Local\Temp\claude\C--Users-<user>-Documents-GitHub-Herdr-Dev\41877815-73fc-459c-beae-466c87dd9eeb\scratchpad\poc\bin\hepr-poc.exe | FAIL |
| P8 | open conhost (pid 91328) for write/inject | DENIED | [H]0;C:\Users\<user>\AppData\Local\Temp\claude\C--Users-<user>-Documents-GitHub-Herdr-Dev\41877815-73fc-459c-beae-466c87dd9eeb\scratchpad\poc\bin\hepr-poc.exe | PASS |
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
| P7 | the server identifies the client by token | AppContainer SID matches | client pid 85436, AppContainer SID matches | PASS |
| T8 | connect to a pipe with herdr's DACL and label | DENIED | DENIED Access is denied. (os error 5) | PASS |
| T9 | read a variable the host has but didn't pass | ERR | ERR absent | PASS |
| T9 | read PATH (passed) | OK | OK present | PASS |
| T9 | enumerate Windows Credential Manager | nothing of the user's | DENIED Access is denied. (os error 5) | PASS |
| T12 | open the host process (Medium) for write/inject | DENIED | DENIED Access is denied. (os error 5) (write/inject); query-limited: denied | PASS |
| T13 | write .git/hooks/pre-commit | OK | OK written | PASS |
| P3 | git init, commit, log, status in the workspace | works | OK exit Some(1):  error: cannot lock ref 'HEAD': unable to create directory for C:/Users/<user>/AppData/Local/Temp/claude/C--Users-<user>-Documents-GitHub-Herdr-D | PASS |
| P2 | gemini --version (copy of the install, tools granted, network off) | prints a version | OK exit Some(1):  Access is denied. | FAIL |
| P2 | the same under LPAC | (measuring: expected to break) | DENIED Access is denied. (os error 5) | PASS |
| T14 | start-to-exit of a trivial probe, median of 15 | measured | contained 35.9 ms, uncontained 33.6 ms | PASS |
| P5 | grant and revoke an inheritable ACE on 10000 files | measured | grant 3.51 s, revoke 3.61 s | PASS |
| P5 | grant and revoke an inheritable ACE on 50000 files | measured | grant 18.81 s, revoke 17.37 s | PASS |
