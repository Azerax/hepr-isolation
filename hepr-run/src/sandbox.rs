//! The Windows side: AppContainer profiles, ACL grants, and launching a
//! program in a container inside a job object on the caller's console.

use std::ffi::{OsStr, c_void};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::core::BOOL;

const SE_GROUP_ENABLED: u32 = 0x4;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ALREADY_EXISTS: i32 = 0x800700B7u32 as i32;

/// Read and run: what tools and extra read-only folders get.
pub const READ_EXEC: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
/// Read, write, run and delete, but not change permissions: the project folder.
pub const MODIFY: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
/// A parent folder of the project: its attributes and passing through it,
/// never its listing or its other files.
pub const SEE_PARENT: u32 = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;

pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

unsafe fn from_wide(p: *const u16) -> String {
    unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(p, (0..).take_while(|&i| *p.add(i) != 0).count())) }
}

fn hr(what: &str, hr: i32) -> io::Error {
    io::Error::other(format!("{what} failed: {:#x}", hr as u32))
}

fn check(ok: BOOL, what: &str) -> io::Result<()> {
    if ok == 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(())
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle()
}

pub fn sid_string(sid: PSID) -> String {
    unsafe {
        let mut p = null_mut();
        if ConvertSidToStringSidW(sid, &mut p) == 0 {
            return "?".into();
        }
        let s = from_wide(p);
        LocalFree(p.cast());
        s
    }
}

fn sid_from(text: &str) -> io::Result<PSID> {
    let mut sid = null_mut();
    check(unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) }, "ConvertStringSidToSid")?;
    Ok(sid) // kept for the life of the process
}

/// The SID of a named capability. Every hepr-run sandbox carries the
/// `heprRun` capability, so one admin-made grant (C:\Users) or one tools-folder
/// grant serves them all.
pub fn capability_sid(name: &str) -> io::Result<PSID> {
    unsafe {
        let (mut groups, mut ng, mut caps, mut nc) = (null_mut(), 0u32, null_mut(), 0u32);
        check(DeriveCapabilitySidsFromName(wide(name).as_ptr(), &mut groups, &mut ng, &mut caps, &mut nc), "DeriveCapabilitySidsFromName")?;
        if nc == 0 {
            return Err(io::Error::other("no capability SID"));
        }
        Ok(*caps) // kept for the life of the process
    }
}

pub struct Container {
    pub name: String,
    pub sid: PSID,
}

impl Container {
    /// Creates the profile, or finds the one an earlier run made.
    pub fn open(name: &str, display: &str) -> io::Result<Container> {
        let (n, d) = (wide(name), wide(display));
        let mut sid = null_mut();
        let r = unsafe { CreateAppContainerProfile(n.as_ptr(), d.as_ptr(), d.as_ptr(), null(), 0, &mut sid) };
        if r == ALREADY_EXISTS {
            return Container::existing(name);
        }
        if r != 0 {
            return Err(hr("CreateAppContainerProfile", r));
        }
        Ok(Container { name: name.into(), sid })
    }

    /// The SID of a profile by name, whether or not the profile still exists.
    pub fn existing(name: &str) -> io::Result<Container> {
        let mut sid = null_mut();
        let r = unsafe { DeriveAppContainerSidFromAppContainerName(wide(name).as_ptr(), &mut sid) };
        if r != 0 {
            return Err(hr("DeriveAppContainerSidFromAppContainerName", r));
        }
        Ok(Container { name: name.into(), sid })
    }

    pub fn delete(&self) -> io::Result<()> {
        let r = unsafe { DeleteAppContainerProfile(wide(&self.name).as_ptr()) };
        if r != 0 { Err(hr("DeleteAppContainerProfile", r)) } else { Ok(()) }
    }

    /// `%LOCALAPPDATA%\Packages\<name>\AC`: the agent's home.
    pub fn folder(&self) -> io::Result<PathBuf> {
        let mut p = null_mut();
        let r = unsafe { GetAppContainerFolderPath(wide(sid_string(self.sid)).as_ptr(), &mut p) };
        if r != 0 {
            return Err(hr("GetAppContainerFolderPath", r));
        }
        Ok(PathBuf::from(unsafe { from_wide(p) }))
    }
}

fn read_dacl(path: &Path) -> io::Result<(*mut ACL, PSECURITY_DESCRIPTOR)> {
    let (mut dacl, mut sd) = (null_mut(), null_mut());
    let e = unsafe {
        GetNamedSecurityInfoW(wide(path).as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), &mut dacl, null_mut(), &mut sd)
    };
    if e != 0 {
        return Err(io::Error::from_raw_os_error(e as i32));
    }
    Ok((dacl, sd))
}

fn entry(sid: PSID, mask: u32, revoke: bool, inherit: bool) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: if revoke { REVOKE_ACCESS } else { GRANT_ACCESS },
        grfInheritance: if inherit { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { NO_INHERITANCE },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.cast(),
        },
    }
}

/// Adds (or, with `revoke`, removes every) inheritable ACE for `sid` on
/// `path`. Windows propagates it through the tree, which is why it is done
/// once per project, not per run.
pub fn grant_tree(path: &Path, sid: PSID, mask: u32, revoke: bool) -> io::Result<()> {
    unsafe {
        let (dacl, sd) = read_dacl(path)?;
        let mut new = null_mut();
        let e = SetEntriesInAclW(1, &entry(sid, mask, revoke, true), dacl, &mut new);
        LocalFree(sd);
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let e = SetNamedSecurityInfoW(wide(path).as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), new, null());
        LocalFree(new.cast());
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        Ok(())
    }
}

/// Adds (or removes every) ACE for `sid` on this one folder only: no
/// inheritance, no propagation (SetFileSecurity sets just the object).
pub fn grant_here(path: &Path, sid: PSID, mask: u32, revoke: bool) -> io::Result<()> {
    unsafe {
        let (dacl, sd) = read_dacl(path)?;
        let mut new = null_mut();
        let e = SetEntriesInAclW(1, &entry(sid, mask, revoke, false), dacl, &mut new);
        LocalFree(sd);
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let mut abs: SECURITY_DESCRIPTOR = zeroed();
        let set = InitializeSecurityDescriptor((&raw mut abs).cast(), 1) != 0
            && SetSecurityDescriptorDacl((&raw mut abs).cast(), 1, new, 0) != 0
            && SetFileSecurityW(wide(path).as_ptr(), DACL_SECURITY_INFORMATION, (&raw const abs).cast_mut().cast()) != 0;
        let err = io::Error::last_os_error();
        LocalFree(new.cast());
        if !set {
            return Err(err);
        }
        Ok(())
    }
}

/// Whether `path` already has an allow ACE for `sid` covering `mask`.
pub fn has_grant(path: &Path, sid: PSID, mask: u32) -> bool {
    unsafe {
        let Ok((dacl, sd)) = read_dacl(path) else { return false };
        let mut found = false;
        if !dacl.is_null() {
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace = null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    continue;
                }
                let header = &*ace.cast::<ACE_HEADER>();
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                    continue;
                }
                let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                if allowed.Mask & mask == mask && EqualSid((&raw const allowed.SidStart).cast_mut().cast(), sid) != 0 {
                    found = true;
                    break;
                }
            }
        }
        LocalFree(sd);
        found
    }
}

pub struct Launch<'a> {
    pub argv: &'a [String],
    pub env: &'a [(String, String)],
    pub cwd: &'a Path,
    pub net: bool,
    pub capability: PSID,
    pub max_memory_mb: Option<usize>,
    pub max_processes: Option<u32>,
    pub quiet: bool,
}

fn command_line(argv: &[String]) -> Vec<u16> {
    let line = argv
        .iter()
        .map(|a| {
            if !a.is_empty() && !a.contains([' ', '\t', '"']) {
                return a.clone();
            }
            // CommandLineToArgvW rules: backslashes double only before a quote.
            let mut out = String::from("\"");
            let mut slashes = 0;
            for c in a.chars() {
                match c {
                    '\\' => slashes += 1,
                    '"' => {
                        out.push_str(&"\\".repeat(slashes * 2 + 1));
                        out.push('"');
                        slashes = 0;
                    }
                    _ => {
                        out.push_str(&"\\".repeat(slashes));
                        out.push(c);
                        slashes = 0;
                    }
                }
            }
            out.push_str(&"\\".repeat(slashes * 2));
            out.push('"');
            out
        })
        .collect::<Vec<_>>()
        .join(" ");
    wide(line)
}

fn env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut env = env.to_vec();
    env.sort_by_key(|(k, _)| k.to_uppercase());
    let mut block = Vec::new();
    for (k, v) in env {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// Kill-on-close, no breakaway, and the limits asked for. The UI limits keep
/// the agent off other windows, the clipboard's contents and system settings;
/// `ui: false` leaves them out (see `run`).
fn job(l: &Launch, ui: bool) -> io::Result<OwnedHandle> {
    unsafe {
        let job = CreateJobObjectW(null(), null());
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = OwnedHandle::from_raw_handle(job);
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if let Some(n) = l.max_processes {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = n;
        }
        if let Some(mb) = l.max_memory_mb {
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = mb << 20;
        }
        info.BasicLimitInformation.LimitFlags = flags;
        let size = size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
        check(SetInformationJobObject(raw(&job), JobObjectExtendedLimitInformation, (&raw const info).cast(), size), "job limits")?;
        if !ui {
            return Ok(job);
        }
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        };
        let size = size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32;
        check(SetInformationJobObject(raw(&job), JobObjectBasicUIRestrictions, (&raw const ui).cast(), size), "job UI limits")?;
        Ok(job)
    }
}

struct Attrs(Vec<u8>);

impl Attrs {
    fn new(count: u32) -> io::Result<Attrs> {
        let mut n = 0usize;
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut n) };
        let mut buf = vec![0u8; n];
        check(unsafe { InitializeProcThreadAttributeList(buf.as_mut_ptr().cast(), count, 0, &mut n) }, "attribute list")?;
        Ok(Attrs(buf))
    }
    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
    unsafe fn set(&mut self, attr: u32, value: *const c_void, size: usize) -> io::Result<()> {
        check(unsafe { UpdateProcThreadAttribute(self.list(), 0, attr as usize, value, size, null_mut(), null()) }, "UpdateProcThreadAttribute")
    }
}

impl Drop for Attrs {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}

fn is_console(h: HANDLE) -> bool {
    let mut mode = 0;
    unsafe { GetConsoleMode(h, &mut mode) != 0 }
}

/// Ctrl+C and Ctrl+Break reach every process on the console. The agent
/// handles them; hepr-run just keeps waiting. (A handler is not inherited,
/// unlike `SetConsoleCtrlHandler(None, TRUE)`, which would stop Ctrl+C in the
/// agent too.)
unsafe extern "system" fn keep_waiting(_: u32) -> BOOL {
    1
}

/// Runs the program in the container and waits for it. When it exits, or
/// hepr-run itself ends, the job takes anything it left running.
pub fn run(c: &Container, l: &Launch) -> io::Result<u32> {
    unsafe {
        let mut caps = vec![SID_AND_ATTRIBUTES { Sid: l.capability, Attributes: SE_GROUP_ENABLED }];
        if l.net {
            // internetClient, privateNetworkClientServer
            caps.push(SID_AND_ATTRIBUTES { Sid: sid_from("S-1-15-3-1")?, Attributes: SE_GROUP_ENABLED });
            caps.push(SID_AND_ATTRIBUTES { Sid: sid_from("S-1-15-3-3")?, Attributes: SE_GROUP_ENABLED });
        }
        let sc = SECURITY_CAPABILITIES { AppContainerSid: c.sid, Capabilities: caps.as_mut_ptr(), CapabilityCount: caps.len() as u32, Reserved: 0 };

        // On a console (a Herdr pane, any terminal) the agent shares it, so
        // the terminal sees it exactly as if it ran unsandboxed. Redirected
        // (pipes, files), it gets the three handles and nothing else.
        let std: [HANDLE; 3] = [GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE)];
        let console = std.iter().all(|&h| is_console(h));
        let mut inheritable: Vec<HANDLE> = Vec::new();
        if !console {
            for &h in &std {
                if !h.is_null() && h != INVALID_HANDLE_VALUE && !inheritable.contains(&h) {
                    SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
                    inheritable.push(h);
                }
            }
        }
        let mut attrs = Attrs::new(2)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, (&raw const sc).cast(), size_of::<SECURITY_CAPABILITIES>())?;
        if !inheritable.is_empty() {
            attrs.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritable.as_ptr().cast(), size_of::<HANDLE>() * inheritable.len())?;
        }
        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attrs.list();
        if !console {
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = std[0];
            si.StartupInfo.hStdOutput = std[1];
            si.StartupInfo.hStdError = std[2];
        }

        let mut cmd = command_line(l.argv);
        let mut env = env_block(l.env);
        let cwd = wide(l.cwd);
        let mut pi: PROCESS_INFORMATION = zeroed();
        check(
            CreateProcessW(
                null(),
                cmd.as_mut_ptr(),
                null(),
                null(),
                (!inheritable.is_empty()) as BOOL,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                env.as_mut_ptr().cast(),
                cwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ),
            "CreateProcess",
        )?;
        let process = OwnedHandle::from_raw_handle(pi.hProcess);
        let thread = OwnedHandle::from_raw_handle(pi.hThread);
        // The terminal may already run hepr-run in a job of its own. Windows
        // nests jobs, but refuses a nested job with UI limits under some
        // parents (ERROR_NOT_SUPPORTED); then the job goes without them. The
        // sandbox, the process tree and kill-on-close are the same either way.
        let mut job = job(l, true)?;
        if AssignProcessToJobObject(raw(&job), raw(&process)) == 0 && GetLastError() == ERROR_NOT_SUPPORTED {
            job = self::job(l, false)?;
            if !l.quiet {
                eprintln!("hepr-run: this terminal's own job rules out window limits; running without them (the sandbox is unchanged)");
            }
        }
        let mut list: BOOL = 0;
        if IsProcessInJob(raw(&process), raw(&job), &mut list) == 0 || list == 0 {
            let e = if AssignProcessToJobObject(raw(&job), raw(&process)) == 0 { Some(io::Error::last_os_error()) } else { None };
            if let Some(e) = e {
                TerminateProcess(raw(&process), 1);
                return Err(io::Error::new(e.kind(), format!("could not put the agent in its job, so it was not started: {e}")));
            }
        }
        SetConsoleCtrlHandler(Some(keep_waiting), 1);
        ResumeThread(raw(&thread));
        WaitForSingleObject(raw(&process), INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(raw(&process), &mut code);
        drop(job); // kill-on-close: anything still running in the sandbox ends here
        Ok(code)
    }
}
