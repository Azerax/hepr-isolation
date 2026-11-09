//! Container side: each op makes one raw OS call and says what happened.
//! Prints `OK …`, `DENIED …` or `ERR …`; exits 0, 5 or 1 to match.

use crate::host::wide;
use std::io;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::ptr::null_mut;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Credentials::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_USER};

fn report(r: io::Result<String>) -> i32 {
    match r {
        Ok(s) => {
            println!("OK {s}");
            0
        }
        Err(e) if e.raw_os_error() == Some(5) || e.kind() == io::ErrorKind::PermissionDenied => {
            println!("DENIED {e}");
            5
        }
        Err(e) => {
            println!("ERR {e}");
            1
        }
    }
}

fn last() -> io::Error {
    io::Error::last_os_error()
}

pub fn main(args: &[String]) -> i32 {
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    match args.first().map(String::as_str).unwrap_or("") {
        "read" => report(std::fs::read(arg(1)).map(|b| format!("read {} bytes", b.len()))),
        "opendir" => report(open_dir(&arg(1))),
        "write" => report(std::fs::write(arg(1), b"probe").map(|_| "written".into())),
        "connect" => report(connect(&arg(1))),
        "env" => report(std::env::var(arg(1)).map(|_| "present".into()).map_err(|_| io::Error::other("absent"))),
        "breakaway" => report(
            Command::new(std::env::current_exe().unwrap())
                .args(["probe", "sleep", "10"])
                .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
                .spawn()
                .map(|c| format!("started pid {} outside the job", c.id())),
        ),
        "spawnmany" => report(spawn_many(arg(1).parse().unwrap_or(10))),
        "sleep" => {
            std::thread::sleep(Duration::from_millis(arg(1).parse().unwrap_or(1000)));
            0
        }
        "alloc" => report(alloc(arg(1).parse().unwrap_or(64))),
        "openproc" => report(open_process(arg(1).parse().unwrap_or(0))),
        "pipe" => report(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!(r"\\.\pipe\{}", arg(1)))
                .map(|_| "connected".into()),
        ),
        "cred" => report(credentials()),
        "conwin" => report(console_window()),
        "run" => report(
            Command::new(arg(1))
                .args(&args[2..])
                .output()
                .map(|o| {
                    let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
                    format!("exit {:?}: {} {}", o.status.code(), out.trim(), err.trim())
                }),
        ),
        other => {
            println!("ERR unknown op {other:?}");
            1
        }
    }
}

fn open_dir(path: &str) -> io::Result<String> {
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last());
    }
    unsafe { CloseHandle(h) };
    Ok("opened for listing".into())
}

fn connect(addr: &str) -> io::Result<String> {
    let addr: std::net::SocketAddr = addr.parse().map_err(io::Error::other)?;
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(4)).map(|_| format!("connected to {addr}"))
}

fn spawn_many(n: usize) -> io::Result<String> {
    let me = std::env::current_exe()?;
    let mut started = Vec::new();
    let mut failed = None;
    for _ in 0..n {
        match Command::new(&me).args(["probe", "sleep", "5000"]).spawn() {
            Ok(c) => started.push(c),
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    let count = started.len();
    for mut c in started {
        let _ = c.kill();
    }
    match failed {
        Some(e) => Ok(format!("{count} of {n} started; then: {e}")),
        None => Ok(format!("{count} of {n} started")),
    }
}

fn alloc(mb: usize) -> io::Result<String> {
    let mut v: Vec<u8> = Vec::new();
    v.try_reserve_exact(mb << 20).map_err(|e| io::Error::other(format!("could not reserve {mb} MB: {e}")))?;
    // Write every byte, so it's in use, not just reserved.
    v.resize(mb << 20, 1);
    Ok(format!("{mb} MB committed"))
}

fn open_process(pid: u32) -> io::Result<String> {
    let rights = PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
    let h = unsafe { OpenProcess(rights, 0, pid) };
    if h.is_null() {
        let e = last();
        // What a weaker ask gets, for the report.
        let q = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        let query = if q.is_null() { "denied" } else { "allowed" };
        if !q.is_null() {
            unsafe { CloseHandle(q) };
        }
        return Err(io::Error::new(e.kind(), format!("{e} (write/inject); query-limited: {query}")));
    }
    unsafe { CloseHandle(h) };
    Ok(format!("opened pid {pid} for write and thread creation"))
}

fn credentials() -> io::Result<String> {
    let mut count = 0u32;
    let mut creds = null_mut();
    if unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut creds) } == 0 {
        return Err(last());
    }
    // Only how many: never what they are.
    unsafe { CredFree(creds.cast()) };
    Ok(format!("{count} credentials visible"))
}

fn console_window() -> io::Result<String> {
    let hwnd = unsafe { GetConsoleWindow() };
    if hwnd.is_null() {
        return Ok("no console window".into());
    }
    if unsafe { PostMessageW(hwnd, WM_USER + 1, 0, 0) } == 0 {
        return Err(last());
    }
    Ok(format!("posted WM_USER+1 to the console window {hwnd:?}"))
}
