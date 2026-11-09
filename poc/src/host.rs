//! Host side: AppContainer profiles, ACL grants, and launching a process in a
//! container inside a job object (plain pipes or a ConPTY).

use std::ffi::{OsStr, c_void};
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
use windows_sys::core::BOOL;

const SE_GROUP_ENABLED: u32 = 0x4;

pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

pub unsafe fn from_wide(p: *const u16) -> String {
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

pub fn sid_from(text: &str) -> io::Result<PSID> {
    let mut sid = null_mut();
    check(unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) }, "ConvertStringSidToSid")?;
    Ok(sid) // kept for the life of the probe
}

/// This process's user SID, as text.
pub fn user_sid() -> io::Result<String> {
    unsafe {
        let mut token = null_mut();
        check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token), "OpenProcessToken")?;
        let token = OwnedHandle::from_raw_handle(token);
        let mut n = 0u32;
        GetTokenInformation(raw(&token), TokenUser, null_mut(), 0, &mut n);
        let mut buf = vec![0usize; (n as usize).div_ceil(size_of::<usize>())];
        check(GetTokenInformation(raw(&token), TokenUser, buf.as_mut_ptr().cast(), n, &mut n), "TokenUser")?;
        Ok(sid_string((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid))
    }
}

pub fn raw(h: &OwnedHandle) -> HANDLE {
    use std::os::windows::io::AsRawHandle;
    h.as_raw_handle()
}

pub struct Container {
    pub name: String,
    pub sid: PSID,
}

impl Container {
    pub fn create(name: &str) -> io::Result<Container> {
        let n = wide(name);
        let mut sid = null_mut();
        let r = unsafe { CreateAppContainerProfile(n.as_ptr(), n.as_ptr(), n.as_ptr(), null(), 0, &mut sid) };
        if r == 0x800700B7u32 as i32 {
            // Already there (an earlier run): derive its SID.
            let r = unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) };
            if r != 0 {
                return Err(hr("DeriveAppContainerSidFromAppContainerName", r));
            }
        } else if r != 0 {
            return Err(hr("CreateAppContainerProfile", r));
        }
        Ok(Container { name: name.into(), sid })
    }

    pub fn delete(&self) -> io::Result<()> {
        let r = unsafe { DeleteAppContainerProfile(wide(&self.name).as_ptr()) };
        if r != 0 { Err(hr("DeleteAppContainerProfile", r)) } else { Ok(()) }
    }

    /// `%LOCALAPPDATA%\Packages\<name>\AC`: the one folder it may write by default.
    pub fn folder(&self) -> io::Result<PathBuf> {
        let mut p = null_mut();
        let r = unsafe { GetAppContainerFolderPath(wide(sid_string(self.sid)).as_ptr(), &mut p) };
        if r != 0 {
            return Err(hr("GetAppContainerFolderPath", r));
        }
        Ok(PathBuf::from(unsafe { from_wide(p) }))
    }
}

pub const READ_EXEC: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
pub const MODIFY: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;

/// Adds (or, with `revoke`, removes every) inheritable ACE for `sid` on `path`.
/// Windows propagates it through the tree: that is the cost P5 measures.
pub fn set_access(path: &Path, sid: PSID, mask: u32, revoke: bool) -> io::Result<()> {
    unsafe {
        let p = wide(path);
        let (mut dacl, mut sd) = (null_mut(), null_mut());
        let e = GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        );
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: if revoke { REVOKE_ACCESS } else { GRANT_ACCESS },
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.cast(),
            },
        };
        let mut new = null_mut();
        let e = SetEntriesInAclW(1, &ea, dacl, &mut new);
        LocalFree(sd);
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let e = SetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new,
            null(),
        );
        LocalFree(new.cast());
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        Ok(())
    }
}

/// What a parent folder of the workspace gets: its attributes, and passing
/// through it. Not its listing, not its files.
pub const SEE_PARENT: u32 = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;

/// Adds (or removes every) ACE for `sid` on this one folder, with no
/// inheritance and no propagation: SetFileSecurity sets only the object
/// itself, unlike SetNamedSecurityInfo, which rewalks the whole tree.
pub fn set_access_here(path: &Path, sid: PSID, mask: u32, revoke: bool) -> io::Result<()> {
    unsafe {
        let p = wide(path);
        let (mut dacl, mut sd) = (null_mut(), null_mut());
        let e = GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        );
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: if revoke { REVOKE_ACCESS } else { GRANT_ACCESS },
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: sid.cast(),
            },
        };
        let mut new = null_mut();
        let e = SetEntriesInAclW(1, &ea, dacl, &mut new);
        LocalFree(sd);
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let mut abs: SECURITY_DESCRIPTOR = zeroed();
        let set = InitializeSecurityDescriptor((&raw mut abs).cast(), 1) != 0
            && SetSecurityDescriptorDacl((&raw mut abs).cast(), 1, new, 0) != 0
            && SetFileSecurityW(p.as_ptr(), DACL_SECURITY_INFORMATION, (&raw const abs).cast_mut().cast()) != 0;
        let err = io::Error::last_os_error();
        LocalFree(new.cast());
        if !set {
            return Err(err);
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Opts {
    pub net: bool,
    pub lpac: bool,
    pub mem_mb: Option<usize>,
    pub procs: Option<u32>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub timeout: Duration,
    pub herdr_job: bool,
}

pub struct Output {
    pub code: u32,
    pub out: String,
    pub ms: f64,
}

fn command_line(argv: &[String]) -> Vec<u16> {
    let line = argv
        .iter()
        .map(|a| if a.is_empty() || a.contains([' ', '\t', '"']) { format!("\"{}\"", a.replace('"', "\\\"")) } else { a.clone() })
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

/// Capability SIDs for "network on": internetClient, privateNetworkClientServer.
fn capabilities(net: bool) -> io::Result<Vec<SID_AND_ATTRIBUTES>> {
    if !net {
        return Ok(vec![]);
    }
    Ok(vec![
        SID_AND_ATTRIBUTES { Sid: sid_from("S-1-15-3-1")?, Attributes: SE_GROUP_ENABLED },
        SID_AND_ATTRIBUTES { Sid: sid_from("S-1-15-3-3")?, Attributes: SE_GROUP_ENABLED },
    ])
}

/// A job with no breakaway, plus the limits asked for. Assignment is checked.
fn job(o: &Opts) -> io::Result<OwnedHandle> {
    unsafe {
        let job = CreateJobObjectW(null(), null());
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = OwnedHandle::from_raw_handle(job);
        let mut l: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if let Some(n) = o.procs {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            l.BasicLimitInformation.ActiveProcessLimit = n;
        }
        if let Some(mb) = o.mem_mb {
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            l.JobMemoryLimit = mb << 20;
        }
        // As herdr-core's pane job (platform/windows.rs): kill-on-close,
        // breakaway allowed, no UI limits.
        if o.herdr_job {
            flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        }
        l.BasicLimitInformation.LimitFlags = flags;
        check(
            SetInformationJobObject(
                raw(&job),
                JobObjectExtendedLimitInformation,
                (&raw const l).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ),
            "job limits",
        )?;
        if o.herdr_job {
            return Ok(job);
        }
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        check(
            SetInformationJobObject(
                raw(&job),
                JobObjectBasicUIRestrictions,
                (&raw const ui).cast(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            ),
            "job UI limits",
        )?;
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
        check(
            unsafe { UpdateProcThreadAttribute(self.list(), 0, attr as usize, value, size, null_mut(), null()) },
            "UpdateProcThreadAttribute",
        )
    }
}

impl Drop for Attrs {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list()) };
    }
}

/// Creates suspended, assigns to the job (checked), resumes.
unsafe fn start(
    argv: &[String],
    o: &Opts,
    si: &STARTUPINFOEXW,
    inherit: bool,
) -> io::Result<(OwnedHandle, OwnedHandle, u32, Instant)> {
    unsafe {
        let mut cmd = command_line(argv);
        let mut env = env_block(&o.env);
        let cwd = wide(&o.cwd);
        let job = job(o)?;
        let mut pi: PROCESS_INFORMATION = zeroed();
        let t = Instant::now();
        check(
            CreateProcessW(
                null(),
                cmd.as_mut_ptr(),
                null(),
                null(),
                inherit as BOOL,
                // A pseudo console child must not get CREATE_NO_WINDOW: it would get
                // a hidden console of its own instead of the pseudo console.
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_SUSPENDED
                    | if inherit { CREATE_NO_WINDOW } else { 0 },
                env.as_mut_ptr().cast(),
                cwd.as_ptr(),
                &si.StartupInfo,
                &mut pi,
            ),
            "CreateProcess",
        )?;
        let process = OwnedHandle::from_raw_handle(pi.hProcess);
        let thread = OwnedHandle::from_raw_handle(pi.hThread);
        if AssignProcessToJobObject(raw(&job), raw(&process)) == 0 {
            let e = io::Error::last_os_error();
            TerminateProcess(raw(&process), 1);
            return Err(io::Error::new(e.kind(), format!("AssignProcessToJobObject: {e} (launch stopped)")));
        }
        ResumeThread(raw(&thread));
        Ok((process, job, pi.dwProcessId, t))
    }
}

fn security_caps(c: &Container, caps: &mut [SID_AND_ATTRIBUTES]) -> SECURITY_CAPABILITIES {
    SECURITY_CAPABILITIES {
        AppContainerSid: c.sid,
        Capabilities: if caps.is_empty() { null_mut() } else { caps.as_mut_ptr() },
        CapabilityCount: caps.len() as u32,
        Reserved: 0,
    }
}

/// Runs `argv` (in the container when `c` is given) with pipes for stdio.
pub fn run(c: Option<&Container>, argv: &[String], o: &Opts) -> io::Result<Output> {
    unsafe {
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: null_mut(), bInheritHandle: 1 };
        let (mut out_r, mut out_w, mut in_r, mut in_w) = (null_mut(), null_mut(), null_mut(), null_mut());
        check(CreatePipe(&mut out_r, &mut out_w, &sa, 0), "CreatePipe")?;
        check(CreatePipe(&mut in_r, &mut in_w, &sa, 0), "CreatePipe")?;
        SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
        let (out_r, out_w, in_r, in_w) = (
            std::fs::File::from_raw_handle(out_r),
            OwnedHandle::from_raw_handle(out_w),
            OwnedHandle::from_raw_handle(in_r),
            OwnedHandle::from_raw_handle(in_w),
        );
        drop(in_w); // stdin at EOF

        let mut caps = capabilities(o.net)?;
        let lpac: u32 = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let handles = [raw(&in_r), raw(&out_w)];
        let mut attrs = Attrs::new(3)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.as_ptr().cast(), size_of_val(&handles))?;
        let sc;
        if let Some(c) = c {
            sc = security_caps(c, &mut caps);
            attrs.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, (&raw const sc).cast(), size_of::<SECURITY_CAPABILITIES>())?;
            if o.lpac {
                attrs.set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, (&raw const lpac).cast(), size_of::<u32>())?;
            }
        }
        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attrs.list();
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = raw(&in_r);
        si.StartupInfo.hStdOutput = raw(&out_w);
        si.StartupInfo.hStdError = raw(&out_w);
        let (process, job, _pid, t) = start(argv, o, &si, true)?;
        drop((in_r, out_w));
        let reader = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = (&out_r).take(1 << 20).read_to_end(&mut s);
            String::from_utf8_lossy(&s).into_owned()
        });
        let waited = WaitForSingleObject(raw(&process), o.timeout.as_millis() as u32);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        let mut code = 0u32;
        GetExitCodeProcess(raw(&process), &mut code);
        // The whole tree goes with the job, finished or not.
        TerminateJobObject(raw(&job), 1);
        drop(job);
        let mut out = reader.join().unwrap_or_default();
        if waited != WAIT_OBJECT_0 {
            out.push_str("\n[timed out]");
            code = 258;
        }
        Ok(Output { code, out, ms })
    }
}

fn conhosts() -> Vec<u32> {
    let me = std::process::id();
    let mut found = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return found;
        }
        let snap = OwnedHandle::from_raw_handle(snap);
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(raw(&snap), &mut e);
        while more != 0 {
            let name = from_wide(e.szExeFile.as_ptr()).to_lowercase();
            if e.th32ParentProcessID == me && (name == "conhost.exe" || name == "openconsole.exe") {
                found.push(e.th32ProcessID);
            }
            more = Process32NextW(raw(&snap), &mut e);
        }
    }
    found
}

pub struct PtyRun {
    pub transcript: String,
    pub steps_seen: usize,
    pub code: u32,
    pub conhost: Option<u32>,
}

/// Runs in the container behind a ConPTY, as herdr's holder would: sends each
/// `send`, waits until `expect` shows in the output, resizes once midway.
pub fn run_pty(
    c: Option<&Container>,
    argv: impl FnOnce(Option<u32>) -> Vec<String>,
    o: &Opts,
    steps: &[(&str, &str)],
) -> io::Result<PtyRun> {
    unsafe {
        let (mut in_r, mut in_w, mut out_r, mut out_w) = (null_mut(), null_mut(), null_mut(), null_mut());
        check(CreatePipe(&mut in_r, &mut in_w, null(), 0), "CreatePipe")?;
        check(CreatePipe(&mut out_r, &mut out_w, null(), 0), "CreatePipe")?;
        let (in_r, mut input, output, out_w) = (
            OwnedHandle::from_raw_handle(in_r),
            std::fs::File::from_raw_handle(in_w),
            std::fs::File::from_raw_handle(out_r),
            OwnedHandle::from_raw_handle(out_w),
        );
        let before = conhosts();
        let mut hpc: HPCON = 0;
        let r = CreatePseudoConsole(COORD { X: 120, Y: 30 }, raw(&in_r), raw(&out_w), 0, &mut hpc);
        if r != 0 {
            return Err(hr("CreatePseudoConsole", r));
        }
        let conhost = conhosts().into_iter().find(|p| !before.contains(p));
        let argv = argv(conhost);

        let mut caps = capabilities(o.net)?;
        let mut attrs = Attrs::new(2)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpc as *const c_void, size_of::<HPCON>())?;
        let sc;
        if let Some(c) = c {
            sc = security_caps(c, &mut caps);
            attrs.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, (&raw const sc).cast(), size_of::<SECURITY_CAPABILITIES>())?;
        }
        let mut si: STARTUPINFOEXW = zeroed();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attrs.list();
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
        si.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
        si.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
        let started = start(&argv, o, &si, false);
        drop((in_r, out_w));
        let (process, job, _pid, _t) = match started {
            Ok(s) => s,
            Err(e) => {
                ClosePseudoConsole(hpc);
                return Err(e);
            }
        };

        let seen = Arc::new(Mutex::new(String::new()));
        let reader = {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = (&output).read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    seen.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            })
        };
        let mut steps_seen = 0;
        for (i, (send, expect)) in steps.iter().enumerate() {
            if i == steps.len() / 2 {
                ResizePseudoConsole(hpc, COORD { X: 100, Y: 40 });
            }
            let _ = input.write_all(send.as_bytes());
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline && !seen.lock().unwrap().contains(expect) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if seen.lock().unwrap().contains(expect) {
                steps_seen += 1;
            }
        }
        let waited = WaitForSingleObject(raw(&process), o.timeout.as_millis() as u32);
        let mut code = 0u32;
        GetExitCodeProcess(raw(&process), &mut code);
        if waited != WAIT_OBJECT_0 {
            code = 258;
        }
        TerminateJobObject(raw(&job), 1);
        ClosePseudoConsole(hpc);
        let _ = reader.join();
        let transcript = seen.lock().unwrap().clone();
        Ok(PtyRun { transcript, steps_seen, code, conhost })
    }
}

/// A named pipe server with the given SDDL. Accepts one client and reports
/// whether its token carries `expect_sid` as its AppContainer SID.
pub fn pipe_server(name: &str, sddl: &str, expect_sid: Option<String>) -> io::Result<std::thread::JoinHandle<String>> {
    unsafe {
        let mut sd = null_mut();
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()), "SDDL")?;
        let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let path = wide(format!(r"\\.\pipe\{name}"));
        let pipe = CreateNamedPipeW(
            path.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            &sa,
        );
        if pipe == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let pipe = pipe as usize;
        Ok(std::thread::spawn(move || {
            let pipe = pipe as HANDLE;
            let pipe = OwnedHandle::from_raw_handle(pipe);
            if ConnectNamedPipe(raw(&pipe), null_mut()) == 0 && GetLastError() != ERROR_PIPE_CONNECTED {
                return "no client".into();
            }
            let mut pid = 0u32;
            GetNamedPipeClientProcessId(raw(&pipe), &mut pid);
            let ac = client_container_sid(pid).unwrap_or_else(|e| format!("? ({e})"));
            match &expect_sid {
                Some(want) if *want == ac => format!("client pid {pid}, AppContainer SID matches"),
                Some(_) => format!("client pid {pid}, AppContainer SID {ac} (MISMATCH)"),
                None => format!("client pid {pid}, AppContainer SID {ac}"),
            }
        }))
    }
}

fn client_container_sid(pid: u32) -> io::Result<String> {
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return Err(io::Error::last_os_error());
        }
        let p = OwnedHandle::from_raw_handle(p);
        let mut token = null_mut();
        check(OpenProcessToken(raw(&p), TOKEN_QUERY, &mut token), "OpenProcessToken")?;
        let token = OwnedHandle::from_raw_handle(token);
        let mut buf = vec![0usize; 64];
        let mut n = 0u32;
        check(
            GetTokenInformation(raw(&token), TokenAppContainerSid, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut n),
            "TokenAppContainerSid",
        )?;
        let sid = (*buf.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer;
        Ok(if sid.is_null() { "none".into() } else { sid_string(sid) })
    }
}

/// Pokes a pipe so a server still waiting in ConnectNamedPipe returns.
pub fn unblock(name: &str) {
    let _ = std::fs::OpenOptions::new().read(true).write(true).open(format!(r"\\.\pipe\{name}"));
}
