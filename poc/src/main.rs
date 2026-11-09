//! HEPR Stage 2 proof of concept. Not product code: a probe that tries the
//! Windows mechanisms the Stage 2 design relies on and reports what held.
//!
//! `hepr-poc suite <scratch dir>`  runs every probe from the host side.
//! `hepr-poc agent <scratch dir> [net]`  runs Claude Code in the container (P2).
//! `hepr-poc probe <op> [args]`    runs inside the container; exit 0 = done,
//!                                 5 = access denied, 1 = other error.

mod agent;
mod host;
mod probe;
mod suite;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("probe") => probe::main(&args[1..]),
        Some("pty") => pty(&args[1..]),
        Some("agent") if args.len() >= 2 => agent::main(std::path::Path::new(&args[1]), args.get(2).is_some_and(|a| a == "net")),
        Some("suite") if args.len() >= 2 => suite::main(std::path::Path::new(&args[1])),
        _ => {
            eprintln!("usage: hepr-poc suite <scratch dir> | probe <op> [args]");
            2
        }
    };
    std::process::exit(code);
}

/// `hepr-poc pty <send> <expect> ... -- <argv>`: runs argv (not contained)
/// behind a ConPTY, as a Herdr pane would, sends each `send` once the last
/// `expect` showed, and prints the screen text. `\r`, `\n` and `\x03` in a
/// `send` are control characters. A test harness for hepr-run.
fn pty(args: &[String]) -> i32 {
    let Some(split) = args.iter().position(|a| a == "--") else {
        eprintln!("usage: hepr-poc pty <send> <expect> ... -- <argv>");
        return 2;
    };
    let unescape = |s: &str| s.replace(r"\r", "\r").replace(r"\n", "\n").replace(r"\x03", "\u{3}");
    let pairs: Vec<(String, String)> = args[..split].chunks(2).map(|c| (unescape(&c[0]), c.get(1).cloned().unwrap_or_default())).collect();
    let steps: Vec<(&str, &str)> = pairs.iter().map(|(s, e)| (s.as_str(), e.as_str())).collect();
    let argv: Vec<String> = args[split + 1..].to_vec();
    let o = host::Opts {
        env: std::env::vars().collect(),
        cwd: std::env::current_dir().unwrap_or_default(),
        timeout: std::time::Duration::from_secs(20),
        herdr_job: std::env::var("HEPR_POC_JOB").is_ok_and(|v| v == "herdr"),
        ..Default::default()
    };
    match host::run_pty(None, |_| argv, &o, &steps) {
        Ok(r) => {
            println!("steps seen: {}/{}  exit: {}", r.steps_seen, steps.len(), r.code);
            println!("{}", agent::screen(&r.transcript));
            if r.steps_seen == steps.len() { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("pty: {e}");
            1
        }
    }
}
