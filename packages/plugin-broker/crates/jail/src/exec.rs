use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use crate::frame::{Frame, PinnedProgram, Target};
use crate::{landlock, roots, seccomp, sys, Level, RunKind};

pub const EXIT_SANDBOX_SETUP: i32 = 76;
pub const EXIT_EXEC_FAILED: i32 = 127;
pub const READY_FD: RawFd = 5;

#[derive(Debug)]
pub struct StartedSignal {
    fd: RawFd,
}

impl StartedSignal {
    pub fn confine(self, kept_fds: &[RawFd]) -> Result<(), String> {
        let mut kept = kept_fds.to_vec();
        kept.push(self.fd);
        let result = confine_host_threads(&kept);
        let line: &[u8] = match &result {
            Ok(()) => b"started\n",
            Err(_) => b"error host-filter\n",
        };
        let _ = sys::write_all(self.fd, line);
        unsafe { libc::close(self.fd) };
        result
    }
}

#[derive(Debug)]
pub struct HostHandoff {
    pub level: Level,
    pub landlock_abi: u32,
    pub args: Vec<String>,
    pub started: StartedSignal,
    pub entry: Option<(String, OwnedFd)>,
}

#[derive(Debug)]
pub enum ExecOutcome {
    Host(HostHandoff),
    Exit(i32),
}

struct Failure {
    code: &'static str,
    error: io::Error,
}

fn fail(code: &'static str) -> impl FnOnce(io::Error) -> Failure {
    move |error| Failure { code, error }
}

fn parse_fd(args: &[String], name: &str) -> Option<RawFd> {
    let at = args.iter().position(|arg| arg == name)?;
    args.get(at + 1)?.parse().ok().filter(|fd: &RawFd| *fd > 2)
}

pub fn exec_main(args: &[String]) -> ExecOutcome {
    if args.first().map(String::as_str) == Some("--probe") {
        return match make_mounts_private_and_drop_capabilities() {
            Ok(()) => ExecOutcome::Exit(0),
            Err(error) => {
                let _ = sys::write_all(
                    2,
                    format!("[ardia] the launcher can't make its mounts private: {error}\n")
                        .as_bytes(),
                );
                ExecOutcome::Exit(EXIT_SANDBOX_SETUP)
            }
        };
    }
    let (Some(policy), Some(ready)) = (parse_fd(args, "--policy-fd"), parse_fd(args, "--ready-fd"))
    else {
        let _ = sys::write_all(2, b"[ardia] usage: exec --policy-fd N --ready-fd N\n");
        return ExecOutcome::Exit(64);
    };
    if ready != READY_FD {
        let _ = sys::write_all(2, b"[ardia] the readiness pipe must be fd 5\n");
        return ExecOutcome::Exit(64);
    }
    match enter(sys::owned(policy)) {
        Ok(handoff) => ExecOutcome::Host(handoff),
        Err(failure) => {
            let _ = sys::write_all(
                2,
                format!(
                    "[ardia] the sandbox couldn't be set up ({}): {}\n",
                    failure.code, failure.error
                )
                .as_bytes(),
            );
            let _ = sys::write_all(READY_FD, format!("error {}\n", failure.code).as_bytes());
            ExecOutcome::Exit(EXIT_SANDBOX_SETUP)
        }
    }
}

fn open_target(target: &Target) -> io::Result<Option<OwnedFd>> {
    match target {
        Target::Path(path) => sys::open_path(path).map(Some),
        Target::Fd(_) => Ok(None),
    }
}

pub fn unexpected_mounts(
    mount_points: &[PathBuf],
    trees: &[PathBuf],
    expected: &[PathBuf],
) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = mount_points
        .iter()
        .filter(|point| {
            trees
                .iter()
                .any(|tree| point.as_path() != tree.as_path() && point.starts_with(tree))
        })
        .filter(|point| !expected.contains(point))
        .cloned()
        .collect();
    found.sort();
    found.dedup();
    found
}

fn check_mount_view(frame: &Frame) -> io::Result<()> {
    if frame.mount_checks.is_empty() {
        return Ok(());
    }
    let entries = roots::read_mountinfo()?;
    let points: Vec<PathBuf> = entries.iter().map(|entry| entry.point.clone()).collect();
    let trees: Vec<PathBuf> = frame
        .mount_checks
        .iter()
        .map(|check| check.path.clone())
        .collect();
    let unexpected = unexpected_mounts(&points, &trees, &frame.expected_mounts);
    if let Some(point) = unexpected.first() {
        return Err(sys::invalid(format!(
            "an unexpected filesystem is mounted at {} inside a granted folder",
            point.display()
        )));
    }
    if !frame.private_mounts {
        return Ok(());
    }
    if let Some(entry) = entries.iter().find(|entry| entry.propagates()) {
        return Err(sys::invalid(format!(
            "{} still takes part in mount propagation",
            entry.point.display()
        )));
    }
    let expected = frame.expected_mounts.iter().map(|path| (path, false));
    let checks = frame
        .mount_checks
        .iter()
        .map(|check| (&check.path, check.writable))
        .chain(expected);
    for (path, writable) in checks {
        let entry = mount_root(&entries, path)?;
        if entry.point != Path::new("/") && !entries.iter().any(|other| other.id == entry.parent) {
            return Err(sys::invalid(format!(
                "{} hangs off a mount the sandbox can't see",
                path.display()
            )));
        }
        if entry.read_only() == writable {
            return Err(sys::invalid(format!(
                "{} is mounted {} but the policy wants it {}",
                path.display(),
                if entry.read_only() {
                    "read-only"
                } else {
                    "writable"
                },
                if writable { "writable" } else { "read-only" }
            )));
        }
    }
    Ok(())
}

fn mount_root<'a>(
    entries: &'a [roots::MountEntry],
    path: &Path,
) -> io::Result<&'a roots::MountEntry> {
    let fd = sys::openat(libc::AT_FDCWD, path, libc::O_PATH | libc::O_NOFOLLOW, 0)?;
    let id = sys::mount_id(fd.as_raw_fd())?;
    let entry = entries.iter().find(|entry| entry.id == id).ok_or_else(|| {
        sys::invalid(format!(
            "{} sits on a mount missing from mountinfo",
            path.display()
        ))
    })?;
    if entry.point != path {
        return Err(sys::invalid(format!(
            "{} isn't the root of its own mount (it sits on {})",
            path.display(),
            entry.point.display()
        )));
    }
    Ok(entry)
}

fn make_mounts_private_and_drop_capabilities() -> io::Result<()> {
    make_mounts_private()?;
    drop_capabilities()
}

fn make_mounts_private() -> io::Result<()> {
    sys::check(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    let root = c"/";
    sys::check(unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    })?;
    Ok(())
}

fn mount_call(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&std::ffi::CStr>,
    flags: libc::c_ulong,
    data: Option<&std::ffi::CStr>,
) -> io::Result<()> {
    let source = source.map(sys::cstring).transpose()?;
    let target = sys::cstring(target)?;
    sys::check(unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            fstype.map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    })?;
    Ok(())
}

pub const SCRIPT_COPY_LIMIT: u64 = 16 << 20;

fn read_verified(fd: &OwnedFd, limit: u64) -> io::Result<(Vec<u8>, u32)> {
    let info = sys::fstat(fd.as_raw_fd())?;
    if info.st_size as u64 > limit {
        return Err(sys::invalid("the script is over 16 MB"));
    }
    let mut bytes = vec![0u8; info.st_size as usize];
    let mut done = 0;
    while done < bytes.len() {
        let count = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                bytes[done..].as_mut_ptr().cast(),
                bytes.len() - done,
                done as libc::off_t,
            )
        };
        if count < 0 {
            let error = sys::last_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(sys::invalid("the script shrank while it was copied"));
        }
        done += count as usize;
    }
    Ok((bytes, info.st_mode & 0o755))
}

fn pin_script(program: &PinnedProgram, verified: &OwnedFd) -> io::Result<()> {
    let Some((root, relative)) = overlay_root(program) else {
        return Ok(());
    };
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(sys::invalid("the script's path isn't plain"));
    }
    let (bytes, mode) = read_verified(verified, SCRIPT_COPY_LIMIT)?;
    let layer = Path::new(crate::EXEC_STAGE_IN_JAIL);
    let nosuid_nodev = libc::MS_NOSUID | libc::MS_NODEV;
    let size = std::ffi::CString::new(format!("size={},mode=0755", bytes.len() + (1 << 20)))
        .map_err(|_| sys::invalid("the layer options hold a NUL byte"))?;
    mount_call(None, layer, Some(c"tmpfs"), nosuid_nodev, Some(&size))?;
    let copy = layer.join(relative);
    if let Some(parent) = copy.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&copy, &bytes)?;
    std::fs::set_permissions(&copy, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    mount_call(
        None,
        layer,
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | nosuid_nodev,
        None,
    )?;
    let options =
        std::ffi::CString::new(format!("lowerdir={}:{}", layer.display(), root.display()))
            .map_err(|_| sys::invalid("the overlay options hold a NUL byte"))?;
    mount_call(
        Some(Path::new("ardia-pinned")),
        root,
        Some(c"overlay"),
        libc::MS_RDONLY | nosuid_nodev,
        Some(&options),
    )?;
    let again = sys::openat(
        libc::AT_FDCWD,
        &program.path,
        libc::O_RDONLY | libc::O_NOFOLLOW,
        0,
    )?;
    if read_verified(&again, SCRIPT_COPY_LIMIT)?.0 != bytes {
        return Err(sys::invalid(
            "the pinned script doesn't read back as the verified bytes",
        ));
    }
    let entries = roots::read_mountinfo()?;
    let mount = mount_root(&entries, root)?;
    if sys::mount_id(again.as_raw_fd())? != mount.id || !mount.read_only() || mount.propagates() {
        return Err(sys::invalid(
            "the pinned script isn't on its own read-only, private overlay",
        ));
    }
    Ok(())
}

fn drop_capabilities() -> io::Result<()> {
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    for capability in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            let error = sys::last_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    sys::check_long(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) })?;
    let status = std::fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .map(str::trim)
            .unwrap_or("missing");
        if value.trim_start_matches('0').is_empty() {
            continue;
        }
        return Err(sys::invalid(format!(
            "{field} is still {value} after dropping"
        )));
    }
    Ok(())
}

pub fn open_beneath(dir: RawFd, relative: &str) -> io::Result<OwnedFd> {
    let fd = sys::openat2(
        dir,
        Path::new(relative),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        sys::RESOLVE_BENEATH
            | sys::RESOLVE_NO_XDEV
            | sys::RESOLVE_NO_MAGICLINKS
            | sys::RESOLVE_NO_SYMLINKS,
    )?;
    if sys::fstat(fd.as_raw_fd())?.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(sys::invalid("the entry isn't a regular file"));
    }
    Ok(fd)
}

fn check_entry(frame: &Frame) -> io::Result<Option<(String, OwnedFd)>> {
    let Some(entry) = &frame.entry else {
        return Ok(None);
    };
    let dir = match &frame.cwd {
        Target::Path(path) => sys::open_dir(path)?,
        Target::Fd(fd) => sys::dup_above(*fd, 3)?,
    };
    let file = open_beneath(dir.as_raw_fd(), entry).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("the entry {entry} can't be opened inside the plugin folder on its own filesystem: {error}"),
        )
    })?;
    let flags = sys::check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) })?;
    sys::check(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) })?;
    Ok(Some((entry.clone(), file)))
}

fn open_program(program: &PinnedProgram, private_mounts: bool) -> io::Result<OwnedFd> {
    let fd = sys::openat(
        libc::AT_FDCWD,
        &program.path,
        libc::O_RDONLY | libc::O_NOFOLLOW,
        0,
    )?;
    if sys::identity(fd.as_raw_fd())? != (program.device, program.inode) {
        return Err(sys::invalid(
            "the program inside the sandbox isn't the one the broker verified",
        ));
    }
    if private_mounts {
        let entries = roots::read_mountinfo()?;
        let expected = match overlay_root(program) {
            Some((root, _)) => root.to_path_buf(),
            None => program.path.clone(),
        };
        let mount = mount_root(&entries, &expected)?;
        if sys::mount_id(fd.as_raw_fd())? != mount.id || !mount.read_only() || mount.propagates() {
            return Err(sys::invalid(
                "the program didn't come from its expected read-only, private mount",
            ));
        }
    }
    Ok(fd)
}

fn overlay_root(program: &PinnedProgram) -> Option<(&'static Path, &Path)> {
    if !program.pin_with_overlay {
        return None;
    }
    match (
        program.path.strip_prefix(crate::PROGRAM_IN_JAIL),
        program.path.strip_prefix(crate::PLUGIN_IN_JAIL),
    ) {
        (Ok(relative), _) => Some((Path::new(crate::PROGRAM_IN_JAIL), relative)),
        (_, Ok(relative)) => Some((Path::new(crate::PLUGIN_IN_JAIL), relative)),
        _ => None,
    }
}

fn enter(policy: OwnedFd) -> Result<HostHandoff, Failure> {
    let bytes = sys::read_to_end_capped(policy.as_raw_fd(), crate::frame::MAX_FRAME)
        .map_err(fail("policy-read"))?;
    drop(policy);
    let frame = Frame::decode(&bytes).map_err(fail("policy-invalid"))?;
    if frame.expected_parent > 0 {
        sys::die_with_parent(frame.expected_parent).map_err(fail("parent-gone"))?;
    }
    sys::set_no_new_privs().map_err(fail("no-new-privs"))?;
    let mut script_path = None;
    let mut verified_early = None;
    if frame.private_mounts {
        make_mounts_private().map_err(fail("private-mounts"))?;
        check_mount_view(&frame).map_err(fail("unexpected-mount"))?;
        if let Some(program) = frame.program.as_ref().filter(|program| program.script) {
            let fd = open_program(program, true).map_err(fail("program-identity"))?;
            pin_script(program, &fd).map_err(fail("script-pin"))?;
            script_path = Some(program.path.clone());
            verified_early = Some(fd);
        }
        drop_capabilities().map_err(fail("private-mounts"))?;
        let program = seccomp::compile(&seccomp::baseline()).map_err(fail("baseline"))?;
        seccomp::install(&program, false).map_err(fail("baseline"))?;
    }
    if !frame.baseline.is_empty() {
        let program = seccomp::from_bytes(&frame.baseline).map_err(fail("baseline-invalid"))?;
        seccomp::install(&program, false).map_err(fail("baseline"))?;
    }
    let kernel = landlock::kernel_abi().map_err(|why| Failure {
        code: "landlock-unavailable",
        error: io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{}: {why}", crate::LANDLOCK_MISSING),
        ),
    })?;
    let minimum = match frame.kind {
        RunKind::Host => landlock::HOST_MIN_ABI,
        RunKind::Sidecar => landlock::SIDECAR_MIN_ABI,
    };
    if frame.landlock_abi < minimum || kernel < frame.landlock_abi {
        return Err(Failure {
            code: "landlock-abi",
            error: sys::invalid(format!(
                "the policy wants Landlock ABI {} and the kernel has {kernel}",
                frame.landlock_abi
            )),
        });
    }
    if !frame.private_mounts {
        check_mount_view(&frame).map_err(fail("unexpected-mount"))?;
    }
    let entry = check_entry(&frame).map_err(fail("entry-check"))?;
    let program_fd = match (&frame.program, verified_early) {
        (Some(_), Some(fd)) => Some(fd),
        (Some(program), None) => {
            Some(open_program(program, frame.private_mounts).map_err(fail("program-identity"))?)
        }
        (None, _) => None,
    };
    let mut opened = Vec::new();
    let mut rules = Vec::new();
    for rule in &frame.rules {
        match open_target(&rule.target).map_err(fail("rule-target"))? {
            Some(fd) => {
                rules.push((fd.as_raw_fd(), rule.rights));
                opened.push(fd);
            }
            None => {
                if let Target::Fd(fd) = rule.target {
                    rules.push((fd, rule.rights));
                }
            }
        }
    }
    if let Some(fd) = &program_fd {
        rules.push((fd.as_raw_fd(), landlock::READ_FILE | landlock::EXECUTE));
    }
    landlock::restrict_self(frame.landlock_abi, &rules).map_err(fail("landlock"))?;
    drop(opened);
    if frame.kind == RunKind::Sidecar {
        let program = seccomp::from_bytes(&frame.final_filter).map_err(fail("final-invalid"))?;
        seccomp::install(&program, false).map_err(fail("final"))?;
    }
    match &frame.cwd {
        Target::Path(path) => {
            let path = sys::cstring(path).map_err(fail("cwd"))?;
            sys::check(unsafe { libc::chdir(path.as_ptr()) }).map_err(fail("cwd"))?;
        }
        Target::Fd(fd) => {
            sys::check(unsafe { libc::fchdir(*fd) }).map_err(fail("cwd"))?;
        }
    }
    let accepted = format!("accepted {} {}\n", frame.level.name(), frame.landlock_abi);
    match (frame.kind, frame.program, program_fd) {
        (RunKind::Sidecar, Some(_), Some(fd)) => {
            keep_only(&[fd.as_raw_fd()]).map_err(fail("close-fds"))?;
            sys::check(unsafe { libc::fcntl(READY_FD, libc::F_SETFD, libc::FD_CLOEXEC) })
                .map_err(fail("ready-fd"))?;
            sys::check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })
                .map_err(fail("program-fd"))?;
            let launch = Launch::prepare(&fd, script_path.as_deref(), &frame.argv, &frame.env)
                .map_err(fail("argv"))?;
            sys::write_all(READY_FD, accepted.as_bytes()).map_err(fail("accepted"))?;
            launch.exec_past_point_of_no_return(&frame.argv)
        }
        (RunKind::Sidecar, _, _) => Err(Failure {
            code: "program-missing",
            error: sys::invalid("a sidecar frame came without its program"),
        }),
        (RunKind::Host, _, _) => {
            let kept: Vec<RawFd> = entry.iter().map(|(_, fd)| fd.as_raw_fd()).collect();
            keep_only(&kept).map_err(fail("close-fds"))?;
            sys::write_all(READY_FD, accepted.as_bytes()).map_err(fail("accepted"))?;
            Ok(HostHandoff {
                level: frame.level,
                landlock_abi: frame.landlock_abi,
                args: frame.host_args,
                started: StartedSignal { fd: READY_FD },
                entry,
            })
        }
    }
}

struct Launch {
    fd: RawFd,
    path: Option<CString>,
    _args: Vec<CString>,
    _vars: Vec<CString>,
    arg_pointers: Vec<*const libc::c_char>,
    var_pointers: Vec<*const libc::c_char>,
}

impl Launch {
    fn prepare(
        fd: &OwnedFd,
        path: Option<&Path>,
        argv: &[String],
        env: &[String],
    ) -> io::Result<Launch> {
        let args = cstrings(argv).ok_or_else(|| sys::invalid("an argument holds a NUL byte"))?;
        let vars = cstrings(env).ok_or_else(|| sys::invalid("a variable holds a NUL byte"))?;
        let path = path.map(sys::cstring).transpose()?;
        let (arg_pointers, var_pointers) = (pointers(&args), pointers(&vars));
        Ok(Launch {
            fd: fd.as_raw_fd(),
            path,
            _args: args,
            _vars: vars,
            arg_pointers,
            var_pointers,
        })
    }

    fn exec_past_point_of_no_return(self, argv: &[String]) -> ! {
        match &self.path {
            Some(path) => unsafe {
                libc::execve(
                    path.as_ptr(),
                    self.arg_pointers.as_ptr(),
                    self.var_pointers.as_ptr(),
                );
            },
            None => unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    self.fd,
                    c"".as_ptr(),
                    self.arg_pointers.as_ptr(),
                    self.var_pointers.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
            },
        }
        exec_failed(argv)
    }
}

fn keep_only(extra: &[RawFd]) -> io::Result<()> {
    let mut kept = vec![0, 1, 2, 3, READY_FD];
    kept.extend_from_slice(extra);
    sys::close_all_except(&kept)
}

fn cstrings(items: &[String]) -> Option<Vec<CString>> {
    items
        .iter()
        .map(|item| CString::new(item.as_bytes()).ok())
        .collect()
}

fn pointers(items: &[CString]) -> Vec<*const libc::c_char> {
    let mut list: Vec<*const libc::c_char> = items.iter().map(|item| item.as_ptr()).collect();
    list.push(std::ptr::null());
    list
}

fn exec_failed(argv: &[String]) -> ! {
    let error = sys::last_error();
    let name = argv.first().map(String::as_str).unwrap_or("the program");
    let _ = sys::write_all(
        2,
        format!("[ardia] {name} couldn't start: {error}\n").as_bytes(),
    );
    let _ = sys::write_all(READY_FD, b"error exec\n");
    unsafe { libc::_exit(EXIT_EXEC_FAILED) }
}

fn confine_host_threads(kept_fds: &[RawFd]) -> Result<(), String> {
    sys::close_all_except(kept_fds)
        .map_err(|error| format!("the extra fds couldn't be closed: {error}"))?;
    let program = seccomp::compile(&seccomp::host_final(std::process::id() as i32))
        .map_err(|error| format!("the host filter didn't compile: {error}"))?;
    seccomp::install(&program, true)
        .map_err(|error| format!("the host filter couldn't be installed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(items: &[&str]) -> Vec<PathBuf> {
        items.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn only_expected_mounts_may_sit_inside_granted_trees() {
        let points = paths(&[
            "/",
            "/usr",
            "/usr/local",
            "/proc",
            "/proc/sys",
            "/run/ardia/plugin",
            "/run/ardia/program",
            "/run/ardia/program/bin/tool",
            "/run/ardia/plugin/nested",
        ]);
        let trees = paths(&["/usr", "/run/ardia/plugin", "/run/ardia/program"]);
        let expected = paths(&["/run/ardia/program/bin/tool"]);
        assert_eq!(
            unexpected_mounts(&points, &trees, &expected),
            paths(&["/run/ardia/plugin/nested", "/usr/local"])
        );
        assert!(unexpected_mounts(&paths(&["/usr", "/proc/sys"]), &trees, &expected).is_empty());
    }

    #[test]
    fn the_entry_must_stay_beneath_its_folder_and_filesystem() {
        let dir = std::env::temp_dir().join(format!("jail-entry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("dist")).unwrap();
        std::fs::write(dir.join("dist/index.js"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("dist/link.js")).unwrap();
        let root = sys::open_dir(&dir).unwrap();
        assert!(open_beneath(root.as_raw_fd(), "dist/index.js").is_ok());
        assert!(open_beneath(root.as_raw_fd(), "dist/link.js").is_err());
        assert!(open_beneath(root.as_raw_fd(), "../etc/passwd").is_err());
        assert!(open_beneath(root.as_raw_fd(), "dist").is_err());
        let fifo = dir.join("dist/pipe.js");
        let fifo_name = sys::cstring(&fifo).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(open_beneath(root.as_raw_fd(), "dist/pipe.js").is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let proc_root = sys::open_dir(Path::new("/")).unwrap();
        assert!(open_beneath(proc_root.as_raw_fd(), "proc/self/status").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
