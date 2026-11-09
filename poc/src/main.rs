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
        Some("agent") if args.len() >= 2 => agent::main(std::path::Path::new(&args[1]), args.get(2).is_some_and(|a| a == "net")),
        Some("suite") if args.len() >= 2 => suite::main(std::path::Path::new(&args[1])),
        _ => {
            eprintln!("usage: hepr-poc suite <scratch dir> | probe <op> [args]");
            2
        }
    };
    std::process::exit(code);
}
