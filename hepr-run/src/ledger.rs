//! What hepr-run has granted for each project, so `--forget` can take it all
//! back. Each entry is written before the change it records, so a crash
//! mid-grant leaves a line to revoke, never an ACE nobody knows about.
//!
//! One file per project in `%LOCALAPPDATA%\hepr-run\projects\`, tab-separated:
//! `dir`, `profile`, then one `grant <mask> <tree|here> <path>` per ACE.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, PartialEq)]
pub struct Grant {
    pub mask: u32,
    /// Inheritable through the folder's tree, or on that one folder only.
    pub tree: bool,
    pub path: PathBuf,
}

pub struct Ledger {
    file: PathBuf,
    pub dir: PathBuf,
    pub profile: String,
    pub grants: Vec<Grant>,
}

pub fn home() -> PathBuf {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    local.join("hepr-run")
}

/// FNV-1a over the lower-cased path: a stable, short name for a project.
pub fn project_id(dir: &Path) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in dir.to_string_lossy().to_lowercase().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

impl Ledger {
    pub fn open(dir: &Path) -> io::Result<Ledger> {
        let id = project_id(dir);
        let file = home().join("projects").join(format!("{id}.txt"));
        let mut l = Ledger { file, dir: dir.to_path_buf(), profile: format!("HeprRun.{id}"), grants: Vec::new() };
        if let Ok(text) = std::fs::read_to_string(&l.file) {
            for line in text.lines() {
                let f: Vec<&str> = line.split('\t').collect();
                match f.as_slice() {
                    ["profile", p] => l.profile = p.to_string(),
                    ["grant", mask, kind, path] => {
                        if let Ok(mask) = u32::from_str_radix(mask, 16) {
                            l.grants.push(Grant { mask, tree: *kind == "tree", path: PathBuf::from(path) });
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(l)
    }

    pub fn exists(&self) -> bool {
        self.file.exists()
    }

    pub fn has(&self, g: &Grant) -> bool {
        self.grants.contains(g)
    }

    /// Records a grant before it is made.
    pub fn record(&mut self, g: Grant) -> io::Result<()> {
        if self.has(&g) {
            return Ok(());
        }
        std::fs::create_dir_all(self.file.parent().unwrap())?;
        let new = !self.file.exists();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.file)?;
        if new {
            writeln!(f, "dir\t{}", self.dir.display())?;
            writeln!(f, "profile\t{}", self.profile)?;
        }
        writeln!(f, "grant\t{:x}\t{}\t{}", g.mask, if g.tree { "tree" } else { "here" }, g.path.display())?;
        self.grants.push(g);
        Ok(())
    }

    pub fn remove(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.file) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}
