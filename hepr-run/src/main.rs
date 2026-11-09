//! hepr-run: run a coding agent in a Windows AppContainer sandbox scoped to
//! one project folder. Inside the folder it works normally; outside it,
//! Windows says Access is denied.

mod ledger;
mod sandbox;

use ledger::{Grant, Ledger};
use sandbox::{Container, MODIFY, READ_EXEC, SEE_PARENT};
use std::io;
use std::path::{Path, PathBuf};

/// The capability every hepr-run sandbox carries (see `sandbox::capability_sid`).
const CAPABILITY: &str = "heprRun";
/// hepr-run's own failures, kept apart from the agent's exit codes.
const FAILED: i32 = 125;

const HELP: &str = "\
hepr-run: run a coding agent sandboxed to one project folder (Windows).

  hepr-run [options] [--] <program> [args...]

Runs <program> in a Windows AppContainer that can read and write the
project folder (the current folder, or --dir) and nothing else of yours.
The first run in a folder sets up its sandbox; later runs reuse it.

Options:
  --dir <folder>        the project folder (default: the current folder)
  --offline             no network (default: network on, agents need their API)
  --read <folder>       also let it read and run files in <folder>
  --write <folder>      also let it change files in <folder>
  --env <NAME>          pass the variable NAME through (e.g. an API token)
  --max-memory <MB>     memory limit for the whole sandbox
  --max-processes <N>   process limit for the whole sandbox
  --quiet               no start-up line

Commands:
  --setup [--undo]      one time, as administrator: lets sandboxes reach
                        projects under C:\\Users (your Documents, repos...)
  --status              this folder's sandbox and what it was granted
  --list                every folder with a sandbox
  --forget              remove this folder's sandbox, its grants and the
                        agent's saved state (logins, history) for it
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hepr-run: {e}");
            FAILED
        }
    };
    std::process::exit(code);
}

#[derive(Default)]
struct Opts {
    dir: Option<PathBuf>,
    offline: bool,
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    env: Vec<String>,
    max_memory_mb: Option<usize>,
    max_processes: Option<u32>,
    quiet: bool,
    undo: bool,
}

fn fail(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

fn run(args: &[String]) -> io::Result<i32> {
    let mut o = Opts::default();
    let mut command: Option<&str> = None;
    let mut setup_target: Option<PathBuf> = None;
    let mut i = 0;
    let value = |i: usize, name: &str| args.get(i + 1).cloned().ok_or_else(|| fail(format!("{name} needs a value")));
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--" => {
                i += 1;
                break;
            }
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(0);
            }
            "--version" => {
                println!("hepr-run {}", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            "--dir" => (o.dir, i) = (Some(PathBuf::from(value(i, a)?)), i + 1),
            "--offline" => o.offline = true,
            "--read" => (i, _) = (i + 1, o.read.push(PathBuf::from(value(i, a)?))),
            "--write" => (i, _) = (i + 1, o.write.push(PathBuf::from(value(i, a)?))),
            "--env" => (i, _) = (i + 1, o.env.push(value(i, a)?)),
            "--max-memory" => (o.max_memory_mb, i) = (Some(value(i, a)?.parse().map_err(|_| fail("--max-memory takes megabytes"))?), i + 1),
            "--max-processes" => (o.max_processes, i) = (Some(value(i, a)?.parse().map_err(|_| fail("--max-processes takes a number"))?), i + 1),
            "--quiet" => o.quiet = true,
            "--undo" => o.undo = true,
            "--setup" | "--status" | "--forget" | "--list" => {
                command = Some(a);
                if a == "--setup" && args.get(i + 1).is_some_and(|n| !n.starts_with("--")) {
                    i += 1;
                    setup_target = Some(PathBuf::from(&args[i]));
                }
            }
            _ if a.starts_with("--") => return Err(fail(format!("unknown option {a} (see hepr-run --help)"))),
            _ => break,
        }
        i += 1;
    }
    let program = &args[i.min(args.len())..];
    // `--setup --undo <folder>`: the folder may follow the other flags.
    if command == Some("--setup") && setup_target.is_none() {
        setup_target = program.first().map(PathBuf::from);
    }

    let cap = sandbox::capability_sid(CAPABILITY)?;
    match command {
        Some("--setup") => return setup(setup_target, o.undo, cap),
        Some("--list") => return list(),
        _ => {}
    }
    let dir = project_dir(o.dir.as_deref())?;
    match command {
        Some("--status") => status(&dir, cap),
        Some("--forget") => forget(&dir),
        _ if program.is_empty() => {
            print!("{HELP}");
            Ok(FAILED)
        }
        _ => launch(&dir, program, &o, cap),
    }
}

/// `\\?\C:\x` → `C:\x`: what people and other programs expect to see.
fn plain(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => p,
    }
}

fn canonical(p: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(p).map(plain).map_err(|e| fail(format!("{}: {e}", p.display())))
}

/// `a` is `b` or inside it (case-insensitive, whole components).
fn within(a: &Path, b: &Path) -> bool {
    let (a, b) = (a.to_string_lossy().to_lowercase(), b.to_string_lossy().to_lowercase());
    let b = b.trim_end_matches('\\');
    a == b || a.starts_with(&format!("{b}\\"))
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from).and_then(|p| canonical(&p).ok())
}

fn profile_dir() -> io::Result<PathBuf> {
    env_path("USERPROFILE").ok_or_else(|| fail("USERPROFILE is not set"))
}

/// The project folder, refused where a sandbox would hold too much.
fn project_dir(given: Option<&Path>) -> io::Result<PathBuf> {
    let dir = canonical(given.unwrap_or(Path::new(".")))?;
    if !dir.is_dir() {
        return Err(fail(format!("{} is not a folder", dir.display())));
    }
    let refuse = |why: &str| fail(format!("won't sandbox {}: {why}. Run it from a project folder.", dir.display()));
    if dir.parent().is_none() {
        return Err(refuse("it's a whole drive"));
    }
    let profile = profile_dir()?;
    if within(&profile, &dir) {
        return Err(refuse("it holds your whole user folder"));
    }
    let off_limits = [
        ("APPDATA", "it's app data"),
        ("LOCALAPPDATA", "it's app data"),
        ("SystemRoot", "it's Windows"),
        ("ProgramFiles", "it's installed programs"),
        ("ProgramFiles(x86)", "it's installed programs"),
        ("ProgramData", "it's shared app data"),
    ];
    for (var, why) in off_limits {
        if env_path(var).is_some_and(|p| within(&dir, &p)) {
            return Err(refuse(why));
        }
    }
    if within(&dir, &profile.join(".ssh")) {
        return Err(refuse("it's your SSH keys"));
    }
    Ok(dir)
}

fn denied(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
}

/// Grants (once) what the project's sandbox needs: the folder itself, and a
/// way through each folder above it.
fn grant_project(c: &Container, l: &mut Ledger, dir: &Path, cap: windows_sys::Win32::Security::PSID, quiet: bool) -> io::Result<()> {
    // Every parent except the drive root: git and other tools stat each one.
    // Attributes and traverse only; listing it or reading its files stays denied.
    for parent in dir.ancestors().skip(1).filter(|p| p.parent().is_some()) {
        if sandbox::has_grant(parent, cap, SEE_PARENT) || sandbox::has_grant(parent, c.sid, SEE_PARENT) {
            continue;
        }
        l.record(Grant { mask: SEE_PARENT, tree: false, path: parent.to_path_buf() })?;
        if let Err(e) = sandbox::grant_here(parent, c.sid, SEE_PARENT, false) {
            return Err(if denied(&e) {
                fail(format!(
                    "the sandbox can't pass through {} and only an administrator can allow it.\n\
                     Once, from an administrator terminal, run:  hepr-run --setup\n\
                     (It lets hepr-run sandboxes pass through that one folder: no listing, no reading.)",
                    parent.display()
                ))
            } else {
                fail(format!("{}: {e}", parent.display()))
            });
        }
    }
    if !sandbox::has_grant(dir, c.sid, MODIFY) {
        if !quiet {
            eprintln!("hepr-run: first run in this folder: giving its sandbox access (big repos take a few seconds, once)...");
        }
        l.record(Grant { mask: MODIFY, tree: true, path: dir.to_path_buf() })?;
        sandbox::grant_tree(dir, c.sid, MODIFY, false).map_err(|e| fail(format!("{}: {e}", dir.display())))?;
    }
    Ok(())
}

fn grant_extra(c: &Container, l: &mut Ledger, path: &Path, mask: u32) -> io::Result<PathBuf> {
    let path = canonical(path)?;
    if path.parent().is_none() || within(&profile_dir()?, &path) {
        return Err(fail(format!("won't grant {}: it's too much (a drive or your whole user folder)", path.display())));
    }
    if !sandbox::has_grant(&path, c.sid, mask) {
        l.record(Grant { mask, tree: true, path: path.clone() })?;
        sandbox::grant_tree(&path, c.sid, mask, false).map_err(|e| fail(format!("{}: {e}", path.display())))?;
    }
    Ok(path)
}

fn pathext() -> Vec<String> {
    std::env::var("PATHEXT").unwrap_or(".COM;.EXE;.BAT;.CMD".into()).split(';').filter(|e| !e.is_empty()).map(|e| e.to_lowercase()).collect()
}

/// Finds the program the way a shell would: as given, else on PATH, trying
/// each PATHEXT extension when it has none.
fn resolve(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);
    let candidates = |base: &Path| -> Vec<PathBuf> {
        if base.extension().is_some() { vec![base.to_path_buf()] } else { pathext().iter().map(|e| base.with_extension(e.trim_start_matches('.'))).collect() }
    };
    if p.components().count() > 1 || p.is_absolute() {
        return candidates(p).into_iter().find(|c| c.is_file()).and_then(|c| canonical(&c).ok());
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).flat_map(|d| candidates(&d.join(program))).find(|c| c.is_file()).and_then(|c| canonical(&c).ok())
}

/// A program under the user folder can't be read by a sandbox. A single
/// executable is copied to hepr-run's tools folder (again only when the
/// original changes), which every sandbox may read and run.
fn reachable(exe: PathBuf, cap: windows_sys::Win32::Security::PSID) -> io::Result<PathBuf> {
    if !within(&exe, &profile_dir()?) {
        return Ok(exe);
    }
    let ext = exe.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if ext != "exe" {
        return Err(fail(format!(
            "{} is a script in your user folder (npm installs Node-based tools this way). \
             hepr-run can run single-file programs from there, like Claude Code, but not Node-based tools yet.",
            exe.display()
        )));
    }
    let tools = ledger::home().join("tools");
    std::fs::create_dir_all(&tools)?;
    if !sandbox::has_grant(&tools, cap, READ_EXEC) {
        sandbox::grant_tree(&tools, cap, READ_EXEC, false)?;
    }
    let copy = tools.join(exe.file_name().unwrap());
    let (src, dst) = (std::fs::metadata(&exe)?, std::fs::metadata(&copy).ok());
    let stale = dst.is_none_or(|d| d.len() != src.len() || d.modified().ok() != src.modified().ok());
    if stale {
        eprintln!("hepr-run: copying {} where the sandbox can run it (again only when it changes)...", exe.display());
        let part = copy.with_extension("partial");
        std::fs::copy(&exe, &part)?;
        std::fs::rename(&part, &copy)?;
    }
    Ok(copy)
}

fn launch(dir: &Path, program: &[String], o: &Opts, cap: windows_sys::Win32::Security::PSID) -> io::Result<i32> {
    let found = resolve(&program[0]).ok_or_else(|| fail(format!("can't find {} on PATH", program[0])))?;
    let exe = reachable(found, cap)?;

    let mut l = Ledger::open(dir)?;
    let c = Container::open(&l.profile, &format!("hepr-run: {}", dir.display()))?;
    grant_project(&c, &mut l, dir, cap, o.quiet)?;
    let mut extra_dirs = Vec::new();
    for p in &o.read {
        extra_dirs.push(grant_extra(&c, &mut l, p, READ_EXEC)?);
    }
    for p in &o.write {
        extra_dirs.push(grant_extra(&c, &mut l, p, MODIFY)?);
    }

    // The agent's home is the sandbox's own folder: its logins, settings and
    // history live there, one set per project, apart from yours.
    let home = c.folder()?;
    let temp = home.join("Temp");
    std::fs::create_dir_all(&temp)?;
    let profile = profile_dir()?;
    let host_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path: Vec<PathBuf> = vec![exe.parent().unwrap().to_path_buf()];
    path.extend(extra_dirs.iter().cloned());
    path.extend(std::env::split_paths(&host_path).filter(|d| !d.as_os_str().is_empty() && !within(d, &profile)));
    let path = std::env::join_paths(path).map_err(|e| fail(e.to_string()))?.to_string_lossy().into_owned();

    let h = home.display().to_string();
    let t = temp.display().to_string();
    let mut env: Vec<(String, String)> = vec![
        ("PATH".into(), path),
        ("USERPROFILE".into(), h.clone()),
        ("HOME".into(), h.clone()),
        ("APPDATA".into(), home.join("Roaming").display().to_string()),
        ("LOCALAPPDATA".into(), h),
        ("TEMP".into(), t.clone()),
        ("TMP".into(), t),
        ("HEPR_RUN".into(), "1".into()),
        ("HEPR_RUN_DIR".into(), dir.display().to_string()),
    ];
    std::fs::create_dir_all(home.join("Roaming"))?;
    let passed = [
        "SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
        "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "ProgramData",
        "TERM", "COLORTERM", "TERM_PROGRAM", "LANG", "LC_ALL", "NO_COLOR", "FORCE_COLOR",
    ];
    for name in passed.iter().map(|s| s.to_string()).chain(o.env.iter().cloned()) {
        match std::env::var(&name) {
            Ok(v) => env.push((name, v)),
            Err(_) if o.env.contains(&name) => eprintln!("hepr-run: --env {name}: not set here, so not passed"),
            Err(_) => {}
        }
    }

    let mut argv = program.to_vec();
    argv[0] = exe.display().to_string();
    let ext = exe.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if ext == "cmd" || ext == "bat" {
        let comspec = std::env::var("ComSpec").unwrap_or(r"C:\Windows\System32\cmd.exe".into());
        argv.splice(0..0, [comspec, "/d".into(), "/c".into()]);
    }

    if !o.quiet {
        let net = if o.offline { "network off" } else { "network on" };
        eprintln!("hepr-run: {} sandboxed to {} ({net})", program[0], dir.display());
    }
    let code = sandbox::run(
        &c,
        &sandbox::Launch {
            argv: &argv,
            env: &env,
            cwd: dir,
            net: !o.offline,
            capability: cap,
            max_memory_mb: o.max_memory_mb,
            max_processes: o.max_processes,
            quiet: o.quiet,
        },
    )?;
    Ok(code as i32)
}

fn setup(target: Option<PathBuf>, undo: bool, cap: windows_sys::Win32::Security::PSID) -> io::Result<i32> {
    let target = match target {
        Some(t) => canonical(&t)?,
        None => profile_dir()?.parent().map(Path::to_path_buf).ok_or_else(|| fail("your user folder has no parent"))?,
    };
    match sandbox::grant_here(&target, cap, SEE_PARENT, undo) {
        Ok(()) if undo => println!("hepr-run: sandboxes can no longer pass through {}.", target.display()),
        Ok(()) => println!(
            "hepr-run: done. Sandboxes can pass through {} (not list it or read anything in it).\n\
             Undo with: hepr-run --setup --undo",
            target.display()
        ),
        Err(e) if denied(&e) => {
            return Err(fail(format!(
                "changing {} needs an administrator terminal. Open one (right-click Terminal, Run as administrator) and run hepr-run --setup{} there.",
                target.display(),
                if undo { " --undo" } else { "" }
            )));
        }
        Err(e) => return Err(fail(format!("{}: {e}", target.display()))),
    }
    Ok(0)
}

fn status(dir: &Path, cap: windows_sys::Win32::Security::PSID) -> io::Result<i32> {
    let l = Ledger::open(dir)?;
    let users = profile_dir()?.parent().map(Path::to_path_buf);
    let setup = users.as_deref().is_some_and(|u| sandbox::has_grant(u, cap, SEE_PARENT));
    println!("folder   {}", dir.display());
    println!("setup    {}", if setup { "done (sandboxes can reach projects under your user folder)" } else { "not done (needed only for projects under your user folder)" });
    if !l.exists() {
        println!("sandbox  none yet: the first hepr-run here makes one");
        return Ok(0);
    }
    let c = Container::existing(&l.profile)?;
    println!("sandbox  {} ({})", l.profile, sandbox::sid_string(c.sid));
    if let Ok(home) = c.folder() {
        println!("home     {}", home.display());
    }
    for g in &l.grants {
        let what = match g.mask {
            MODIFY => "read + write",
            READ_EXEC => "read + run",
            SEE_PARENT => "pass through",
            _ => "custom",
        };
        let live = if sandbox::has_grant(&g.path, c.sid, g.mask) { "" } else { "  (not in place)" };
        println!("grant    {what:<13}{}{live}", g.path.display());
    }
    Ok(0)
}

fn forget(dir: &Path) -> io::Result<i32> {
    let l = Ledger::open(dir)?;
    if !l.exists() {
        println!("hepr-run: no sandbox for {}", dir.display());
        return Ok(0);
    }
    let c = Container::existing(&l.profile)?;
    let mut problems = Vec::new();
    for g in l.grants.iter().rev() {
        let r = if g.tree { sandbox::grant_tree(&g.path, c.sid, 0, true) } else { sandbox::grant_here(&g.path, c.sid, 0, true) };
        if let Err(e) = r
            && e.kind() != io::ErrorKind::NotFound
        {
            problems.push(format!("{}: {e}", g.path.display()));
        }
    }
    if let Err(e) = c.delete() {
        problems.push(format!("sandbox profile: {e}"));
    }
    if problems.is_empty() {
        l.remove()?;
        println!("hepr-run: forgot {}: grants removed, sandbox and its saved state deleted.", dir.display());
        Ok(0)
    } else {
        Err(fail(format!("some of {} could not be removed (run --forget again):\n  {}", dir.display(), problems.join("\n  "))))
    }
}

fn list() -> io::Result<i32> {
    let dir = ledger::home().join("projects");
    let mut found = 0;
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        if let Ok(text) = std::fs::read_to_string(e.path())
            && let Some(d) = text.lines().find_map(|l| l.strip_prefix("dir\t"))
        {
            println!("{d}");
            found += 1;
        }
    }
    if found == 0 {
        println!("hepr-run: no sandboxes yet");
    }
    Ok(0)
}
