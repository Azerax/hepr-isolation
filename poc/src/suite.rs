//! Runs every probe from the host and prints one table row per check.
//! Everything lives under the scratch dir given; the container profile and
//! every ACE added are removed at the end.

use crate::host::{self, Container, Opts, Output, MODIFY, READ_EXEC};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Ctx {
    c: Container,
    exe: PathBuf,
    base: Opts,
    rows: Vec<[String; 5]>,
}

fn verdict(out: &str) -> &str {
    let first = out.trim_start().split_whitespace().next().unwrap_or("");
    match first {
        "OK" | "DENIED" | "ERR" => first,
        _ => "?",
    }
}

impl Ctx {
    fn row(&mut self, id: &str, check: &str, expect: &str, observed: &str, pass: bool) {
        let observed = observed.trim().replace('\n', " / ").replace('|', "\\|");
        let observed: String = observed.chars().take(700).collect();
        let r = if pass { "PASS" } else { "FAIL" };
        println!("| {id} | {check} | {expect} | {observed} | {r} |");
        self.rows.push([id.into(), check.into(), expect.into(), observed, r.into()]);
    }

    fn probe(&self, contained: bool, o: &Opts, args: &[&str]) -> Output {
        let mut argv = vec![self.exe.display().to_string(), "probe".into()];
        argv.extend(args.iter().map(|s| s.to_string()));
        host::run(contained.then_some(&self.c), &argv, o).unwrap_or_else(|e| Output { code: 1, out: format!("ERR launch: {e}"), ms: 0.0 })
    }

    /// One probe in the container; passes when it did NOT succeed.
    fn refused(&mut self, id: &str, what: &str, o: &Opts, args: &[&str]) {
        let out = self.probe(true, o, args);
        let pass = verdict(&out.out) != "OK";
        self.row(id, what, "fails", &out.out, pass);
    }

    /// One probe in the container; passes when its verdict is `expect`.
    fn check(&mut self, id: &str, what: &str, o: &Opts, args: &[&str], expect: &str) {
        let out = self.probe(true, o, args);
        let pass = verdict(&out.out) == expect;
        self.row(id, what, expect, &out.out, pass);
    }
}

pub fn main(scratch: &Path) -> i32 {
    match run(scratch) {
        Ok(failed) => failed.min(100) as i32,
        Err(e) => {
            eprintln!("suite: {e}");
            101
        }
    }
}

fn run(scratch: &Path) -> std::io::Result<usize> {
    let scratch = std::path::absolute(scratch)?;
    let (bin, ws, outside, tools) = (scratch.join("bin"), scratch.join("ws"), scratch.join("outside"), scratch.join("tools"));
    for d in [&bin, &ws, &outside, &tools] {
        std::fs::create_dir_all(d)?;
    }
    let exe = bin.join("hepr-poc.exe");
    std::fs::copy(std::env::current_exe()?, &exe)?;
    std::fs::write(outside.join("secret.txt"), b"not for the agent")?;

    let c = Container::create("Herdr.Isolated.PocProbe")?;
    let sid = host::sid_string(c.sid);
    eprintln!("container SID {sid}");
    let folder = c.folder()?;
    host::set_access(&bin, c.sid, READ_EXEC, false)?;
    host::set_access(&ws, c.sid, MODIFY, false)?;
    host::set_access(&tools, c.sid, READ_EXEC, false)?;

    // A clean environment: Windows essentials only, nothing from ours.
    unsafe { std::env::set_var("HEPR_POC_SECRET", "x") };
    let sysroot = std::env::var("SystemRoot").unwrap_or(r"C:\Windows".into());
    let temp = folder.join("Temp");
    let path = [
        bin.display().to_string(),
        format!(r"{sysroot}\System32"),
        sysroot.clone(),
        format!(r"{sysroot}\System32\WindowsPowerShell\v1.0"),
        r"C:\Program Files\Git\cmd".into(),
        r"C:\Program Files\nodejs".into(),
        tools.join("npm").display().to_string(),
    ]
    .join(";");
    let env = vec![
        ("SystemRoot".into(), sysroot.clone()),
        ("windir".into(), sysroot.clone()),
        ("SystemDrive".into(), "C:".into()),
        ("ComSpec".into(), format!(r"{sysroot}\System32\cmd.exe")),
        ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
        ("PATH".into(), path),
        ("TEMP".into(), temp.display().to_string()),
        ("TMP".into(), temp.display().to_string()),
        ("USERPROFILE".into(), folder.display().to_string()),
        ("HOME".into(), folder.display().to_string()),
        ("APPDATA".into(), folder.display().to_string()),
        ("LOCALAPPDATA".into(), folder.display().to_string()),
    ];
    let base = Opts { env, cwd: ws.clone(), timeout: Duration::from_secs(30), ..Opts::default() };
    let mut x = Ctx { c, exe: exe.clone(), base: base.clone(), rows: Vec::new() };

    println!("| ID | Check | Expected | Observed | Result |");
    println!("| --- | --- | --- | --- | --- |");

    // Controls: the same probes outside the container succeed, so a DENIED
    // below is the container's doing.
    let ctl = x.probe(false, &base, &["read", &outside.join("secret.txt").display().to_string()]);
    x.row("ctl", "read the outside secret, NOT contained", "OK", &ctl.out, verdict(&ctl.out) == "OK");

    // P1: ConPTY + AppContainer + job, interactive.
    let cmd = format!(r"{sysroot}\System32\cmd.exe");
    let steps: &[(&str, &str)] = &[("echo HEPR_PTY^_OK\r\n", "HEPR_PTY_OK"), ("echo HEPR_RESIZED^_OK\r\n", "HEPR_RESIZED_OK"), ("exit\r\n", "")];
    match host::run_pty(None, |_| vec![cmd.clone()], &base, steps) {
        Ok(p) => x.row("ctl", "cmd in ConPTY, NOT contained", "2 replies, exit 0", &format!("{} replies, exit {}", p.steps_seen - 1, p.code), p.steps_seen == 3 && p.code == 0),
        Err(e) => x.row("ctl", "cmd in ConPTY, NOT contained", "2 replies, exit 0", &format!("ERR {e}"), false),
    }
    let r = host::run_pty(Some(&x.c), |_| vec![cmd.clone()], &base, steps);
    match r {
        Ok(p) => {
            let pass = p.steps_seen == 3 && p.code == 0;
            let tail: String = p.transcript.chars().rev().take(200).collect::<Vec<_>>().into_iter().rev().collect();
            let seen = format!("{} replies, exit {}", p.steps_seen - 1, p.code);
            let seen = if pass { seen } else { format!("{seen}; output: {tail:?}") };
            x.row("P1", "cmd in ConPTY: input, output, resize, exit", "2 replies, exit 0", &seen, pass)
        }
        Err(e) => x.row("P1", "cmd in ConPTY", "2 replies, exit 0", &format!("ERR {e}"), false),
    }
    let ps = format!(r"{sysroot}\System32\WindowsPowerShell\v1.0\powershell.exe");
    let r = host::run_pty(Some(&x.c), |_| vec![ps.clone(), "-NoLogo".into(), "-NoProfile".into()], &base, &[("$a='HEPR'; \"$($a)_PS_OK\"\r\n", "HEPR_PS_OK"), ("exit\r\n", "")]);
    match r {
        Ok(p) => x.row("P1", "Windows PowerShell in ConPTY", "reply, exit 0", &format!("{} replies, exit {}", p.steps_seen - 1, p.code), p.steps_seen == 2 && p.code == 0),
        Err(e) => x.row("P1", "Windows PowerShell in ConPTY", "reply, exit 0", &format!("ERR {e}"), false),
    }

    // P8: what the Low child can do to its Medium console host.
    let exe_s = exe.display().to_string();
    let r = host::run_pty(Some(&x.c), |_| vec![exe_s.clone(), "probe".into(), "conwin".into()], &base, &[("", "")]);
    if let Ok(p) = r {
        let seen = said(&p.transcript);
        let v = if seen.contains("DENIED") { "DENIED" } else if seen.contains("OK ") { "OK" } else { "?" };
        x.row("P8", "post WM_USER+1 to the console's window", "not delivered", &seen, v != "OK" && !seen.is_empty());
    }
    let r = host::run_pty(
        Some(&x.c),
        |conhost| vec![exe_s.clone(), "probe".into(), "openproc".into(), conhost.unwrap_or(0).to_string()],
        &base,
        &[("", "")],
    );
    if let Ok(p) = r {
        let seen = said(&p.transcript);
        x.row("P8", &format!("open conhost (pid {}) for write/inject", p.conhost.unwrap_or(0)), "DENIED", &seen, seen.contains("DENIED"));
    }

    // T1: secrets outside the grants.
    let secret = outside.join("secret.txt").display().to_string();
    x.check("T1", "read a secret outside the workspace", &base, &["read", &secret], "DENIED");
    let ssh = format!(r"{}\.ssh", std::env::var("USERPROFILE").unwrap_or_default());
    if Path::new(&ssh).exists() {
        x.check("T1", "open the real ~/.ssh for listing (no read)", &base, &["opendir", &ssh], "DENIED");
    }
    let profile = std::env::var("USERPROFILE").unwrap_or_default();
    x.check("T1", "open the user profile for listing", &base, &["opendir", &profile], "DENIED");

    // T2: writes.
    let user_temp = std::env::temp_dir().join("hepr-poc-t2.txt");
    let public = PathBuf::from(r"C:\Users\Public\hepr-poc-t2.txt");
    x.check("T2", "write outside the workspace", &base, &["write", &outside.join("new.txt").display().to_string()], "DENIED");
    x.check("T2", "write the user's %TEMP%", &base, &["write", &user_temp.display().to_string()], "DENIED");
    x.check("T2", r"write C:\Users\Public", &base, &["write", &public.display().to_string()], "DENIED");
    x.check("T2", "write inside the workspace", &base, &["write", &ws.join("inside.txt").display().to_string()], "OK");
    let _ = std::fs::remove_file(&user_temp);
    let _ = std::fs::remove_file(&public);

    // T3: a junction the agent makes, and one made for it, both pointing out.
    let made_inside = ws.join("out");
    let mk = x.probe(true, &base, &["run", &cmd, "/c", "mklink", "/J", &made_inside.display().to_string(), &outside.display().to_string()]);
    x.row("T3", "make a junction in the workspace to outside", "(recorded: allowed or not)", &mk.out, true);
    if made_inside.exists() {
        x.check("T3", "read the secret through that junction", &base, &["read", &made_inside.join("secret.txt").display().to_string()], "DENIED");
        x.check("T3", "write through that junction", &base, &["write", &made_inside.join("planted.txt").display().to_string()], "DENIED");
    }
    let host_made = ws.join("out2");
    let _ = std::process::Command::new(&cmd).args(["/c", "mklink", "/J"]).arg(&host_made).arg(&outside).output();
    x.check("T3", "read through a junction that was already there", &base, &["read", &host_made.join("secret.txt").display().to_string()], "DENIED");

    // T4/P6: process count.
    let limited = Opts { procs: Some(5), ..base.clone() };
    let out = x.probe(true, &limited, &["spawnmany", "10"]);
    let started: usize = out.out.split_whitespace().nth(1).and_then(|n| n.parse().ok()).unwrap_or(99);
    x.row("T4", "start 10 children with processes = 5", "at most 4 start (the probe is the 5th)", &out.out, started <= 4);

    // T5: breakaway.
    x.check("T5", "start a child with CREATE_BREAKAWAY_FROM_JOB", &base, &["breakaway"], "DENIED");

    // T11 (partly): the tree ends with the job.
    let before = count_probes();
    let _ = x.probe(true, &Opts { timeout: Duration::from_millis(1500), ..base.clone() }, &["spawnmany", "3"]);
    let orphan = x.probe(true, &Opts { timeout: Duration::from_millis(1500), ..base.clone() }, &["run", &exe_s, "probe", "sleep", "60000"]);
    std::thread::sleep(Duration::from_millis(300));
    let after = count_probes();
    x.row("T11", "a child still running when the session ends", "ended with the job", &format!("{} probe processes left (was {before}); session: {}", after.saturating_sub(before), orphan.out.trim()), after <= before);

    // T7/P6: memory.
    let mem = Opts { mem_mb: Some(256), ..base.clone() };
    x.check("T7", "commit 64 MB with memory_mb = 256", &mem, &["alloc", "64"], "OK");
    let big = x.probe(true, &mem, &["alloc", "512"]);
    x.row("T7", "commit 512 MB with memory_mb = 256", "fails", &big.out, verdict(&big.out) != "OK");

    // T6/P4: network.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let local = listener.local_addr()?.to_string();
    let external = "1.1.1.1:443";
    let ctl = x.probe(false, &base, &["connect", external]);
    x.row("ctl", "connect 1.1.1.1:443, NOT contained", "OK", &ctl.out, verdict(&ctl.out) == "OK");
    x.refused("T6", "network off: connect to 1.1.1.1:443", &base, &["connect", external]);
    x.refused("T6", "network off: connect to a local listener", &base, &["connect", &local]);
    let on = Opts { net: true, ..base.clone() };
    x.check("T6", "network on: connect to 1.1.1.1:443", &on, &["connect", external], "OK");
    x.refused("T6", "network on: connect to a local listener", &on, &["connect", &local]);
    drop(listener);

    // T8/P7: the session pipe, and a pipe shaped like herdr's own.
    let user = host::user_sid()?;
    let tag = std::process::id();
    let session = format!("hepr-poc-session-{tag}");
    let main_pipe = format!("hepr-poc-main-{tag}");
    let server = host::pipe_server(&session, &format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})(A;;GA;;;{sid})S:(ML;;NW;;;LW)"), Some(sid.clone()))?;
    let herdr_like = host::pipe_server(&main_pipe, &format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})S:(ML;;NRNW;;;ME)"), None)?;
    x.check("P7", "connect to its own session pipe", &base, &["pipe", &session], "OK");
    let who = server.join().unwrap_or_default();
    x.row("P7", "the server identifies the client by token", "AppContainer SID matches", &who, who.contains("matches"));
    x.check("T8", "connect to a pipe with herdr's DACL and label", &base, &["pipe", &main_pipe], "DENIED");
    host::unblock(&main_pipe);
    let _ = herdr_like.join();

    // T9: environment and credentials.
    x.check("T9", "read a variable the host has but didn't pass", &base, &["env", "HEPR_POC_SECRET"], "ERR");
    x.check("T9", "read PATH (passed)", &base, &["env", "PATH"], "OK");
    let cred = x.probe(true, &base, &["cred"]);
    x.row("T9", "enumerate Windows Credential Manager", "nothing of the user's", &cred.out, verdict(&cred.out) != "OK" || cred.out.contains(" 0 credentials"));

    // T12: other processes.
    x.check("T12", "open the host process (Medium) for write/inject", &base, &["openproc", &std::process::id().to_string()], "DENIED");

    // T13: auto-run files are writable (reported, not blocked).
    std::fs::create_dir_all(ws.join(".git").join("hooks"))?;
    x.check("T13", "write .git/hooks/pre-commit", &base, &["write", &ws.join(".git").join("hooks").join("pre-commit").display().to_string()], "OK");
    let _ = std::fs::remove_dir_all(ws.join(".git"));

    // P3: git in the workspace.
    // The marker "HEPR_GIT_DONE" only prints when every git step succeeded.
    let git_line = "git init -q && git -c user.name=poc -c user.email=poc@example.invalid commit -q --allow-empty -m first && git log --oneline && git status --short --branch && echo HEPR_GIT_DONE";
    let git = x.probe(true, &base, &["run", &cmd, "/c", git_line]);
    x.row("P3", "git in a workspace under the user profile", "works", &git.out, git.out.contains("HEPR_GIT_DONE"));

    // (a) A workspace whose only parent is C:\ .
    let root_ws = PathBuf::from(r"C:\hepr-poc-ws");
    std::fs::create_dir_all(&root_ws)?;
    host::set_access(&root_ws, x.c.sid, MODIFY, false)?;
    let at_root = Opts { cwd: root_ws.clone(), ..base.clone() };
    let git = x.probe(true, &at_root, &["run", &cmd, "/c", git_line]);
    x.row("P3", r"git in a workspace at C:\hepr-poc-ws", "(recorded)", &git.out, true);
    let _ = host::set_access(&root_ws, x.c.sid, 0, true);
    let _ = std::fs::remove_dir_all(&root_ws);

    // (c) The profile case rebuilt in scratch: C:\hepr-poc-ws\a\b\ws, whose
    // parents the container can't see. First as is, then with each parent
    // granted only its attributes and passage (no listing, no inheritance).
    let deep_root = PathBuf::from(r"C:\hepr-poc-ws");
    let parents = [deep_root.clone(), deep_root.join("a"), deep_root.join("a").join("b")];
    let deep = deep_root.join("a").join("b").join("ws");
    std::fs::create_dir_all(&deep)?;
    host::set_access(&deep, x.c.sid, MODIFY, false)?;
    let in_deep = Opts { cwd: deep.clone(), ..base.clone() };
    let git = x.probe(true, &in_deep, &["run", &cmd, "/c", git_line]);
    x.row("P3", r"git in C:\hepr-poc-ws\a\b\ws, parents unseen", "fails like the profile case", &git.out, !git.out.contains("HEPR_GIT_DONE"));
    let _ = std::fs::remove_dir_all(deep.join(".git"));
    for p in &parents {
        host::set_access_here(p, x.c.sid, host::SEE_PARENT, false)?;
    }
    let git = x.probe(true, &in_deep, &["run", &cmd, "/c", git_line]);
    x.row("P3", "the same with each parent granted attributes + traverse only", "works", &git.out, git.out.contains("HEPR_GIT_DONE"));
    x.check("P3", "list a parent folder (still not granted)", &in_deep, &["opendir", &parents[1].display().to_string()], "DENIED");
    std::fs::write(parents[1].join("sibling-secret.txt"), b"x")?;
    x.check("P3", "read a file beside the workspace in a parent", &in_deep, &["read", &parents[1].join("sibling-secret.txt").display().to_string()], "DENIED");
    // As C:\Users would be: the top parent left ungranted (it needs admin).
    let _ = std::fs::remove_dir_all(deep.join(".git"));
    let _ = host::set_access_here(&parents[0], x.c.sid, 0, true);
    let git = x.probe(true, &in_deep, &["run", &cmd, "/c", git_line]);
    x.row("P3", r"the same with the top parent left ungranted (as C:\Users would be)", "(recorded)", &git.out, true);
    for p in &parents {
        let _ = host::set_access_here(p, x.c.sid, 0, true);
    }
    let _ = host::set_access(&deep, x.c.sid, 0, true);
    let _ = std::fs::remove_dir_all(&deep_root);

    // (b) The workspace mapped to a drive of its own: nothing above it.
    let letter = ["W:", "V:", "U:", "T:"].into_iter().find(|l| !Path::new(&format!(r"{l}\")).exists());
    if let Some(letter) = letter {
        let ws_b = ws.join("mapped");
        std::fs::create_dir_all(&ws_b)?;
        let mapped = std::process::Command::new(&cmd).args(["/c", "subst", letter]).arg(&ws_b).output();
        let ok = mapped.as_ref().is_ok_and(|o| o.status.success());
        if ok {
            let on_drive = Opts { cwd: PathBuf::from(format!(r"{letter}\")), ..base.clone() };
            let git = x.probe(true, &on_drive, &["run", &cmd, "/c", git_line]);
            x.row("P3", &format!(r"git in the workspace mapped to {letter}\ (subst)"), "works", &git.out, git.out.contains("HEPR_GIT_DONE"));
            x.check("P3", &format!(r"the container sees {letter}\ at all"), &on_drive, &["opendir", &format!(r"{letter}\")], "OK");
            let _ = std::process::Command::new(&cmd).args(["/c", "subst", letter, "/D"]).output();
        } else {
            x.row("P3", "map the workspace to a drive", "subst works", &format!("{mapped:?}"), false);
        }
    }

    // P2: a real agent CLI, network off (nothing can leave).
    let npm = PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("npm");
    let gemini = npm.join("node_modules").join("@google").join("gemini-cli");
    if gemini.exists() {
        let to = tools.join("npm");
        copy_tree(&gemini, &to.join("node_modules").join("@google").join("gemini-cli"))?;
        std::fs::copy(npm.join("gemini.cmd"), to.join("gemini.cmd"))?;
        let gcmd = to.join("gemini.cmd").display().to_string();
        let o = Opts { timeout: Duration::from_secs(90), ..base.clone() };
        let g = x.probe(true, &o, &["run", &cmd, "/c", &gcmd, "--version"]);
        x.row("P2", "gemini --version, node.exe from Program Files (tools granted, network off)", "(recorded)", &g.out, true);
        // Node's own install folder grants no AppContainer access, so the
        // same again with a user-owned copy of node.exe beside gemini.cmd
        // (gemini.cmd prefers %dp0%\node.exe).
        std::fs::copy(r"C:\Program Files\nodejs\node.exe", to.join("node.exe"))?;
        let node = to.join("node.exe").display().to_string();
        let js = to.join(r"node_modules\@google\gemini-cli\bundle\gemini.js").display().to_string();
        x.check("P2", "diagnose: read the node.exe copy", &o, &["read", &node], "OK");
        x.check("P2", "diagnose: read gemini.cmd", &o, &["read", &gcmd], "OK");
        let n = x.probe(true, &o, &["run", &node, "--version"]);
        x.row("P2", "diagnose: node.exe copy --version", "prints a version", &n.out, n.out.contains("exit Some(0)"));
        let n = x.probe(true, &o, &["run", &node, &js, "--version"]);
        x.row("P2", "diagnose: node gemini.js --version directly", "prints a version", &n.out, n.out.contains("exit Some(0)"));
        let hello = to.join("hello.js");
        std::fs::write(&hello, "const fs = require('fs'); console.log('HELLO_FROM_NODE', fs.readdirSync('.').length)")?;
        let h = hello.display().to_string();
        let n = x.probe(true, &o, &["run", &node, "--preserve-symlinks", "--preserve-symlinks-main", &h]);
        x.row("P2", "node --preserve-symlinks(-main) hello.js (reads the workspace)", "runs", &n.out, n.out.contains("HELLO_FROM_NODE"));
        let o = Opts { timeout: Duration::from_secs(30), ..o };
        let n = x.probe(true, &o, &["run", &node, "--preserve-symlinks", "--preserve-symlinks-main", &js, "--version"]);
        x.row("P2", "node --preserve-symlinks(-main) gemini.js --version", "prints a version", &n.out, n.out.contains("exit Some(0)"));
        let g = x.probe(true, &o, &["run", &cmd, "/c", &gcmd, "--version"]);
        x.row("P2", "gemini --version with node.exe copied into the tools folder", "prints a version", &g.out, verdict(&g.out) == "OK" && g.out.contains("exit Some(0)"));
        let lp = Opts { lpac: true, ..o.clone() };
        let g = x.probe(true, &lp, &["run", &cmd, "/c", &gcmd, "--version"]);
        x.row("P2", "the same under LPAC", "(measuring: expected to break)", &g.out, true);
    } else {
        x.row("P2", "gemini --version", "prints a version", "gemini-cli not installed", false);
    }

    // T14: launch cost, contained vs the same job without the container.
    let mut a = Vec::new();
    let mut b = Vec::new();
    for _ in 0..15 {
        a.push(x.probe(true, &base, &["sleep", "0"]).ms);
        b.push(x.probe(false, &base, &["sleep", "0"]).ms);
    }
    let (ma, mb) = (median(&mut a), median(&mut b));
    x.row("T14", "start-to-exit of a trivial probe, median of 15", "measured", &format!("contained {ma:.1} ms, uncontained {mb:.1} ms"), true);

    // P5: ACL grant cost on trees of 10k and 50k files.
    let p5 = scratch.join("p5");
    for files in [10_000usize, 50_000] {
        let tree = p5.join(format!("t{files}"));
        make_tree(&tree, files)?;
        let t = Instant::now();
        host::set_access(&tree, x.c.sid, MODIFY, false)?;
        let grant = t.elapsed().as_secs_f64();
        let t = Instant::now();
        host::set_access(&tree, x.c.sid, MODIFY, true)?;
        let revoke = t.elapsed().as_secs_f64();
        x.row("P5", &format!("grant and revoke an inheritable ACE on {files} files"), "measured", &format!("grant {grant:.2} s, revoke {revoke:.2} s"), true);
    }

    // Clean up: every ACE added, then the profile.
    let mut clean = Vec::new();
    for d in [&bin, &ws, &tools] {
        if let Err(e) = host::set_access(d, x.c.sid, 0, true) {
            clean.push(format!("{}: {e}", d.display()));
        }
    }
    let _ = std::fs::remove_dir(&made_inside);
    let _ = std::fs::remove_dir(&host_made);
    let _ = std::fs::remove_dir_all(&p5);
    if let Err(e) = x.c.delete() {
        clean.push(format!("profile: {e}"));
    }
    eprintln!("cleanup: {}", if clean.is_empty() { "all grants revoked, profile deleted".into() } else { clean.join("; ") });

    let failed = x.rows.iter().filter(|r| r[4] == "FAIL").count();
    eprintln!("{} checks, {failed} failed", x.rows.len());
    let _ = x.base;
    Ok(failed)
}

/// The probe's own line out of a pseudo console transcript (which also
/// carries the title and cursor sequences).
fn said(transcript: &str) -> String {
    let at = ["OK ", "DENIED ", "ERR "].iter().filter_map(|w| transcript.find(w)).min();
    let Some(at) = at else { return String::new() };
    transcript[at..].split(['\r', '\n', '\u{1b}']).next().unwrap_or("").to_string()
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
}

fn count_probes() -> usize {
    let out = std::process::Command::new("tasklist").args(["/FI", "IMAGENAME eq hepr-poc.exe", "/NH"]).output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).matches("hepr-poc.exe").count()).unwrap_or(0)
}

fn make_tree(root: &Path, files: usize) -> std::io::Result<()> {
    let per_dir = 100;
    for d in 0..files.div_ceil(per_dir) {
        let dir = root.join(format!("d{}", d / 10)).join(format!("d{d}"));
        std::fs::create_dir_all(&dir)?;
        for f in 0..per_dir.min(files - d * per_dir) {
            std::fs::write(dir.join(format!("f{f}.txt")), b"x")?;
        }
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type()?.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}
