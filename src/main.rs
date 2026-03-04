use std::os::unix::io::{AsFd, AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use nix::libc;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyEvent, InitFlags, MarkFlags, MaskFlags,
    FANOTIFY_METADATA_VERSION,
};

// ── CLI ──────────────────────────────────────────────────────────

/// fanotify audit experimentation tool
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Watch filesystem events on a path
    Watch {
        /// Path to watch (file, directory, or mount point)
        #[arg(short, long)]
        path: PathBuf,

        /// What kind of object to mark
        #[arg(short = 't', long, default_value = "inode")]
        mark_type: MarkType,

        /// Events to watch for (ignored if --all is set)
        #[arg(
            short,
            long,
            value_delimiter = ',',
            default_value = "access,modify,open,close"
        )]
        events: Vec<EventType>,

        /// Watch all possible events
        #[arg(short, long, default_value_t = false)]
        all: bool,

        /// Use FID mode: report file handles + directory + filenames instead of fds.
        /// nix 0.29 doesn't wrap this, so we use raw libc for init and event parsing.
        #[arg(long, default_value_t = false)]
        fid: bool,

        /// Init flags for the fanotify group
        #[arg(short, long, value_delimiter = ',')]
        init_flags: Vec<FanInitFlag>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum MarkType {
    /// Mark a specific inode
    Inode,
    /// Mark an entire mount point
    Mount,
    /// Mark an entire filesystem
    Filesystem,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum EventType {
    Access,
    Modify,
    Attrib,
    CloseWrite,
    CloseNowrite,
    Close,
    Open,
    MovedFrom,
    MovedTo,
    Move,
    Create,
    Delete,
    DeleteSelf,
    MoveSelf,
    OpenExec,
    Rename,
    Ondir,
    EventOnChild,
}

#[derive(ValueEnum, Clone, Debug)]
enum FanInitFlag {
    /// Close-on-exec
    Cloexec,
    /// Non-blocking reads
    Nonblock,
    /// Notification class (default)
    ClassNotif,
    /// Content class (permission events, final data)
    ClassContent,
    /// Pre-content class (permission events, before final data)
    ClassPreContent,
    /// Unlimited event queue
    UnlimitedQueue,
    /// Unlimited marks
    UnlimitedMarks,
    /// Report pidfd instead of pid
    ReportPidfd,
    /// Report thread id instead of process id
    ReportTid,
}

// ── Flag conversion helpers ──────────────────────────────────────

impl EventType {
    fn to_mask_flag(&self) -> MaskFlags {
        match self {
            EventType::Access => MaskFlags::FAN_ACCESS,
            EventType::Modify => MaskFlags::FAN_MODIFY,
            EventType::Attrib => MaskFlags::FAN_ATTRIB,
            EventType::CloseWrite => MaskFlags::FAN_CLOSE_WRITE,
            EventType::CloseNowrite => MaskFlags::FAN_CLOSE_NOWRITE,
            EventType::Close => MaskFlags::FAN_CLOSE,
            EventType::Open => MaskFlags::FAN_OPEN,
            EventType::MovedFrom => MaskFlags::FAN_MOVED_FROM,
            EventType::MovedTo => MaskFlags::FAN_MOVED_TO,
            EventType::Move => MaskFlags::FAN_MOVE,
            EventType::Create => MaskFlags::FAN_CREATE,
            EventType::Delete => MaskFlags::FAN_DELETE,
            EventType::DeleteSelf => MaskFlags::FAN_DELETE_SELF,
            EventType::MoveSelf => MaskFlags::FAN_MOVE_SELF,
            EventType::OpenExec => MaskFlags::FAN_OPEN_EXEC,
            EventType::Rename => MaskFlags::FAN_RENAME,
            EventType::Ondir => MaskFlags::FAN_ONDIR,
            EventType::EventOnChild => MaskFlags::FAN_EVENT_ON_CHILD,
        }
    }
}

fn all_events_mask() -> MaskFlags {
    MaskFlags::FAN_ACCESS
        | MaskFlags::FAN_MODIFY
        | MaskFlags::FAN_ATTRIB
        | MaskFlags::FAN_CLOSE_WRITE
        | MaskFlags::FAN_CLOSE_NOWRITE
        | MaskFlags::FAN_OPEN
        | MaskFlags::FAN_MOVED_FROM
        | MaskFlags::FAN_MOVED_TO
        | MaskFlags::FAN_CREATE
        | MaskFlags::FAN_DELETE
        | MaskFlags::FAN_DELETE_SELF
        | MaskFlags::FAN_MOVE_SELF
        | MaskFlags::FAN_OPEN_EXEC
        | MaskFlags::FAN_RENAME
        | MaskFlags::FAN_ONDIR
        | MaskFlags::FAN_EVENT_ON_CHILD
}

fn events_to_mask(events: &[EventType]) -> MaskFlags {
    events
        .iter()
        .fold(MaskFlags::empty(), |acc, e| acc | e.to_mask_flag())
}

fn mark_type_to_flags(mark_type: &MarkType) -> MarkFlags {
    match mark_type {
        MarkType::Inode => MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_INODE,
        MarkType::Mount => MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
        MarkType::Filesystem => MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
    }
}

fn build_init_flags(flags: &[FanInitFlag]) -> InitFlags {
    let mut result = InitFlags::empty();
    for flag in flags {
        result |= match flag {
            FanInitFlag::Cloexec => InitFlags::FAN_CLOEXEC,
            FanInitFlag::Nonblock => InitFlags::FAN_NONBLOCK,
            FanInitFlag::ClassNotif => InitFlags::FAN_CLASS_NOTIF,
            FanInitFlag::ClassContent => InitFlags::FAN_CLASS_CONTENT,
            FanInitFlag::ClassPreContent => InitFlags::FAN_CLASS_PRE_CONTENT,
            FanInitFlag::UnlimitedQueue => InitFlags::FAN_UNLIMITED_QUEUE,
            FanInitFlag::UnlimitedMarks => InitFlags::FAN_UNLIMITED_MARKS,
            FanInitFlag::ReportPidfd => InitFlags::FAN_REPORT_PIDFD,
            FanInitFlag::ReportTid => InitFlags::FAN_REPORT_TID,
        };
    }
    result
}

fn build_mask(events: &[EventType], all: bool) -> MaskFlags {
    if all {
        all_events_mask()
    } else {
        events_to_mask(events)
    }
}

// ── Shared display helpers ───────────────────────────────────────

fn describe_mask(mask: MaskFlags) -> Vec<&'static str> {
    let mut descriptions = Vec::new();
    let checks: &[(MaskFlags, &str)] = &[
        (MaskFlags::FAN_ACCESS, "ACCESS"),
        (MaskFlags::FAN_MODIFY, "MODIFY"),
        (MaskFlags::FAN_ATTRIB, "ATTRIB"),
        (MaskFlags::FAN_CLOSE_WRITE, "CLOSE_WRITE"),
        (MaskFlags::FAN_CLOSE_NOWRITE, "CLOSE_NOWRITE"),
        (MaskFlags::FAN_OPEN, "OPEN"),
        (MaskFlags::FAN_MOVED_FROM, "MOVED_FROM"),
        (MaskFlags::FAN_MOVED_TO, "MOVED_TO"),
        (MaskFlags::FAN_CREATE, "CREATE"),
        (MaskFlags::FAN_DELETE, "DELETE"),
        (MaskFlags::FAN_DELETE_SELF, "DELETE_SELF"),
        (MaskFlags::FAN_MOVE_SELF, "MOVE_SELF"),
        (MaskFlags::FAN_OPEN_EXEC, "OPEN_EXEC"),
        (MaskFlags::FAN_Q_OVERFLOW, "Q_OVERFLOW"),
        (MaskFlags::FAN_FS_ERROR, "FS_ERROR"),
        (MaskFlags::FAN_OPEN_PERM, "OPEN_PERM"),
        (MaskFlags::FAN_ACCESS_PERM, "ACCESS_PERM"),
        (MaskFlags::FAN_OPEN_EXEC_PERM, "OPEN_EXEC_PERM"),
        (MaskFlags::FAN_RENAME, "RENAME"),
        (MaskFlags::FAN_ONDIR, "ONDIR"),
    ];
    for &(flag, name) in checks {
        if mask.contains(flag) {
            descriptions.push(name);
        }
    }
    descriptions
}

fn describe_mask_raw(mask: u64) -> Vec<&'static str> {
    describe_mask(MaskFlags::from_bits_truncate(mask))
}

fn process_name(pid: i32) -> String {
    if pid <= 0 {
        return String::from("<kernel>");
    }
    let comm_path = format!("/proc/{}/comm", pid);
    std::fs::read_to_string(&comm_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| String::from("<exited>"))
}

fn process_cmdline(pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    let path = format!("/proc/{}/cmdline", pid);
    std::fs::read(&path)
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

// ── FD mode ──────────────────────────────────────────────────────

fn resolve_fd_path(event: &FanotifyEvent) -> Option<PathBuf> {
    event.fd().map(|fd| {
        let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
        std::fs::read_link(&link).unwrap_or_else(|_| PathBuf::from("<unknown>"))
    })
}

fn get_fd_metadata(event: &FanotifyEvent) -> Option<std::fs::Metadata> {
    event.fd().and_then(|fd| {
        let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
        std::fs::metadata(&link).ok()
    })
}

fn file_type_str(meta: &std::fs::Metadata) -> &'static str {
    let ft = meta.file_type();
    if ft.is_dir() {
        "dir"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "file"
    }
}

fn print_fd_event(event: &FanotifyEvent) {
    let mask = event.mask();
    let event_names = describe_mask(mask);
    let pid = event.pid();
    let pname = process_name(pid);

    let path = resolve_fd_path(event);
    let meta = get_fd_metadata(event);

    let path_str = path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<no-fd>".to_string());

    let ftype = meta.as_ref().map(file_type_str).unwrap_or("?");

    println!(
        "  pid={:<8} proc={:<20} events={:<40} type={:<7} path={}",
        pid,
        pname,
        event_names.join("|"),
        ftype,
        path_str,
    );

    if mask.contains(MaskFlags::FAN_Q_OVERFLOW) {
        println!("    [Q_OVERFLOW] event queue overflowed, events were lost");
    }
    if mask.contains(MaskFlags::FAN_MODIFY) || mask.contains(MaskFlags::FAN_ATTRIB) {
        if let Some(ref m) = meta {
            println!("    [file_info] size={} bytes", m.len());
        }
    }
    if mask.contains(MaskFlags::FAN_MOVED_FROM) {
        println!(
            "    [MOVED_FROM] file is being moved away from: {}",
            path_str
        );
        println!("    (note: MOVED_FROM/MOVED_TO are separate events, no built-in correlation)");
    }
    if mask.contains(MaskFlags::FAN_MOVED_TO) {
        println!("    [MOVED_TO] file arrived at: {}", path_str);
    }
    if mask.contains(MaskFlags::FAN_RENAME) {
        println!("    [RENAME] file was renamed (fd points to the file after rename)");
    }
    if mask.contains(MaskFlags::FAN_DELETE) {
        println!("    [DELETE] entry removed from directory: {}", path_str);
    }
    if mask.contains(MaskFlags::FAN_DELETE_SELF) {
        println!("    [DELETE_SELF] watched object itself was deleted");
    }
    if mask.contains(MaskFlags::FAN_CREATE) {
        println!("    [CREATE] new entry created in directory: {}", path_str);
    }
    if mask.contains(MaskFlags::FAN_OPEN_EXEC) {
        println!("    [OPEN_EXEC] file opened with intent to execute");
    }
    if mask.contains(MaskFlags::FAN_ONDIR) {
        println!("    [ONDIR] event target is a directory");
    }

    if pid > 0 {
        let cmdline = process_cmdline(pid);
        if !cmdline.is_empty() {
            println!("    [process] {}", cmdline);
        }
    }
}

fn run_watch_fd(
    path: PathBuf,
    mark_type: MarkType,
    events: Vec<EventType>,
    all: bool,
    init_flags: Vec<FanInitFlag>,
) -> Result<()> {
    let init = build_init_flags(&init_flags) | InitFlags::FAN_CLOEXEC;
    let mask = build_mask(&events, all);
    let mark = mark_type_to_flags(&mark_type);

    println!("Initializing fanotify group (fd mode)...");
    println!("  init flags: {:?}", init);
    println!("  mark flags: {:?}", mark);
    println!("  event mask: {:?}", mask);
    println!("  path:       {}", path.display());
    if all {
        println!("  (watching ALL events)");
    }
    println!();

    let fan = Fanotify::init(init, EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC)
        .context("fanotify_init failed (are you root / CAP_SYS_ADMIN?)")?;

    fan.mark(mark, mask, None, Some(&path))
        .context("fanotify_mark failed")?;

    println!("Listening for events... (Ctrl+C to stop)\n");

    loop {
        let events = fan.read_events().context("read_events failed")?;
        for event in &events {
            if !event.check_version() {
                bail!(
                    "fanotify metadata version mismatch: got {}, expected {}",
                    event.version(),
                    FANOTIFY_METADATA_VERSION,
                );
            }
            print_fd_event(event);
        }
    }
}

// ── FID mode ─────────────────────────────────────────────────────
//
// nix 0.29 doesn't expose FAN_REPORT_FID / FAN_REPORT_DIR_FID / FAN_REPORT_NAME
// or the info-record parsing needed for FID mode. We use raw libc where nix falls
// short, and nix's Fanotify wrapper for marking (which works fine once we have
// the fd).
//
// In FID mode, events arrive with fd == FAN_NOFD (-1). Instead of a per-event
// file descriptor, each event carries variable-length info records after the
// fixed metadata header. These records contain:
//   - fsid (filesystem identifier)
//   - file_handle (kernel file handle, same as from name_to_handle_at)
//   - optionally a null-terminated filename (for DFID_NAME records)
//
// To resolve a file_handle back to a path, we use open_by_handle_at(2).

/// Parsed content from one info record within an FID-mode event.
struct FidRecord {
    info_type: u8,
    fsid: [i32; 2],
    handle_type: i32,
    handle_bytes: Vec<u8>,
    /// Filename, present only in DFID_NAME / OLD_DFID_NAME / NEW_DFID_NAME records.
    name: Option<String>,
}

/// A fully parsed FID-mode event (metadata + info records).
struct FidEvent {
    mask: u64,
    pid: i32,
    records: Vec<FidRecord>,
}

/// Decode handle_type from the file_handle struct.
/// These correspond to the FILEID_* enum in linux/exportfs.h.
fn handle_type_name(t: i32) -> &'static str {
    // Upper 16 bits are user flags (FILEID_IS_CONNECTABLE, FILEID_IS_DIR);
    // match on lower 16 bits for the filesystem type.
    match t & 0xffff {
        0x00 => "ROOT",
        0x01 => "INO32_GEN",
        0x02 => "INO32_GEN_PARENT",
        0x4d => "BTRFS_WITHOUT_PARENT",
        0x4e => "BTRFS_WITH_PARENT",
        0x4f => "BTRFS_WITH_PARENT_ROOT",
        0x51 => "UDF_WITHOUT_PARENT",
        0x52 => "UDF_WITH_PARENT",
        0x61 => "NILFS_WITHOUT_PARENT",
        0x62 => "NILFS_WITH_PARENT",
        0x71 => "FAT_WITHOUT_PARENT",
        0x72 => "FAT_WITH_PARENT",
        0x81 => "INO64_GEN",
        0x82 => "INO64_GEN_PARENT",
        0x97 => "LUSTRE",
        0xb1 => "BCACHEFS_WITHOUT_PARENT",
        0xb2 => "BCACHEFS_WITH_PARENT",
        0xfe => "KERNFS",
        0xff => "INVALID",
        _ => "UNKNOWN",
    }
}

fn handle_type_flags(t: i32) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if t & 0x10000 != 0 {
        flags.push("CONNECTABLE");
    }
    if t & 0x20000 != 0 {
        flags.push("DIR");
    }
    flags
}

fn info_type_name(t: u8) -> &'static str {
    match t {
        libc::FAN_EVENT_INFO_TYPE_FID => "FID",
        libc::FAN_EVENT_INFO_TYPE_DFID => "DFID",
        libc::FAN_EVENT_INFO_TYPE_DFID_NAME => "DFID_NAME",
        libc::FAN_EVENT_INFO_TYPE_PIDFD => "PIDFD",
        5 => "ERROR",
        10 => "OLD_DFID_NAME",
        12 => "NEW_DFID_NAME",
        _ => "UNKNOWN",
    }
}

/// Parse FID-mode events from a raw read buffer.
///
/// Layout per event:
///   [fanotify_event_metadata]           (24 bytes, event_len tells total size)
///   [info_record_1]                     (variable, hdr.len tells size)
///   [info_record_2]                     (variable)
///   ...
///
/// Each FID/DFID/DFID_NAME info record layout:
///   [fanotify_event_info_header]        (4 bytes: info_type, pad, len)
///   [__kernel_fsid_t]                   (8 bytes: val[0], val[1])
///   [file_handle header]               (8 bytes: handle_bytes, handle_type)
///   [file_handle data]                 (handle_bytes bytes)
///   [null-terminated name]             (only for DFID_NAME, padded to alignment)
fn parse_fid_events(buf: &[u8]) -> Vec<FidEvent> {
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let info_hdr_size = 4usize; // fanotify_event_info_header is 4 bytes
    let fsid_size = 8usize;
    let fh_hdr_size = 8usize; // handle_bytes(u32) + handle_type(i32)

    let mut events = Vec::new();
    let mut offset = 0;

    while offset + meta_size <= buf.len() {
        let meta = unsafe {
            std::ptr::read_unaligned(
                buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata
            )
        };

        let event_end = offset + meta.event_len as usize;
        if event_end > buf.len() {
            break;
        }

        let mut records = Vec::new();
        let mut info_offset = offset + meta.metadata_len as usize;

        while info_offset + info_hdr_size <= event_end {
            let hdr = unsafe {
                std::ptr::read_unaligned(
                    buf.as_ptr().add(info_offset) as *const libc::fanotify_event_info_header
                )
            };

            if hdr.len < info_hdr_size as u16 {
                break;
            }
            let record_end = info_offset + hdr.len as usize;
            if record_end > event_end {
                break;
            }

            let data_start = info_offset + info_hdr_size;

            match hdr.info_type {
                libc::FAN_EVENT_INFO_TYPE_FID
                | libc::FAN_EVENT_INFO_TYPE_DFID
                | libc::FAN_EVENT_INFO_TYPE_DFID_NAME
                | 10  // FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
                | 12  // FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
                => {
                    if data_start + fsid_size + fh_hdr_size > record_end {
                        info_offset = record_end;
                        continue;
                    }

                    // fsid
                    let fsid_val0 = i32::from_ne_bytes(
                        buf[data_start..data_start + 4].try_into().unwrap(),
                    );
                    let fsid_val1 = i32::from_ne_bytes(
                        buf[data_start + 4..data_start + 8].try_into().unwrap(),
                    );

                    // file_handle header
                    let fh_offset = data_start + fsid_size;
                    let handle_bytes_count = u32::from_ne_bytes(
                        buf[fh_offset..fh_offset + 4].try_into().unwrap(),
                    ) as usize;
                    let handle_type = i32::from_ne_bytes(
                        buf[fh_offset + 4..fh_offset + 8].try_into().unwrap(),
                    );

                    // file_handle data
                    let fh_data_start = fh_offset + fh_hdr_size;
                    let fh_data_end = fh_data_start + handle_bytes_count;

                    let handle_data = if fh_data_end <= record_end {
                        buf[fh_data_start..fh_data_end].to_vec()
                    } else {
                        Vec::new()
                    };

                    // For DFID_NAME variants, a null-terminated filename follows the handle
                    let name = if (hdr.info_type == libc::FAN_EVENT_INFO_TYPE_DFID_NAME
                        || hdr.info_type == 10
                        || hdr.info_type == 12)
                        && fh_data_end < record_end
                    {
                        let name_bytes = &buf[fh_data_end..record_end];
                        let name_str = name_bytes.split(|&b| b == 0).next().unwrap_or(&[]);
                        if name_str.is_empty() {
                            None
                        } else {
                            Some(String::from_utf8_lossy(name_str).into_owned())
                        }
                    } else {
                        None
                    };

                    records.push(FidRecord {
                        info_type: hdr.info_type,
                        fsid: [fsid_val0, fsid_val1],
                        handle_type,
                        handle_bytes: handle_data,
                        name,
                    });
                }
                _ => {
                    // PIDFD, ERROR, or unknown — skip
                }
            }

            info_offset = record_end;
        }

        events.push(FidEvent {
            mask: meta.mask,
            pid: meta.pid,
            records,
        });

        offset = event_end;
    }

    events
}

/// Resolve a file handle back to a path using open_by_handle_at(2).
///
/// mount_fd must be an open fd to any object on the same filesystem.
/// We open with O_PATH to avoid actually reading the file.
fn resolve_handle(mount_fd: RawFd, record: &FidRecord) -> Option<PathBuf> {
    if record.handle_bytes.is_empty() {
        return None;
    }

    // Build a buffer matching struct file_handle layout:
    //   u32 handle_bytes
    //   i32 handle_type
    //   u8  f_handle[handle_bytes]
    let total = 8 + record.handle_bytes.len();
    let mut buf = vec![0u8; total];
    let hb = record.handle_bytes.len() as u32;
    buf[0..4].copy_from_slice(&hb.to_ne_bytes());
    buf[4..8].copy_from_slice(&record.handle_type.to_ne_bytes());
    buf[8..].copy_from_slice(&record.handle_bytes);

    // open_by_handle_at is not wrapped by libc as a function, use syscall
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mount_fd,
            buf.as_mut_ptr(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    } as RawFd;

    if fd < 0 {
        return None;
    }

    let link = format!("/proc/self/fd/{}", fd);
    let path = std::fs::read_link(&link).ok();
    unsafe {
        libc::close(fd);
    }
    path
}

fn print_fid_event(event: &FidEvent, mount_fd: RawFd) {
    let event_names = describe_mask_raw(event.mask);
    let mask = MaskFlags::from_bits_truncate(event.mask);
    let pid = event.pid;
    let pname = process_name(pid);

    // Collect resolved paths and names from records for the header line
    let mut dir_path: Option<String> = None;
    let mut file_name: Option<String> = None;
    let mut file_path: Option<String> = None;

    for record in &event.records {
        let resolved = resolve_handle(mount_fd, record);

        match record.info_type {
            libc::FAN_EVENT_INFO_TYPE_DFID_NAME | 10 | 12 => {
                if let Some(ref p) = resolved {
                    dir_path = Some(p.display().to_string());
                }
                if record.name.is_some() {
                    file_name = record.name.clone();
                }
            }
            libc::FAN_EVENT_INFO_TYPE_DFID => {
                if dir_path.is_none() {
                    if let Some(ref p) = resolved {
                        dir_path = Some(p.display().to_string());
                    }
                }
            }
            libc::FAN_EVENT_INFO_TYPE_FID => {
                if let Some(ref p) = resolved {
                    file_path = Some(p.display().to_string());
                }
            }
            _ => {}
        }
    }

    // Build a display path: prefer dir+name, fall back to file handle path
    let display_path = match (&dir_path, &file_name) {
        (Some(dir), Some(name)) => format!("'{}'/'{}'", dir, name),
        (Some(dir), None) => format!("'{}'", dir.clone()),
        (None, Some(name)) => format!("<dir-unknown>/'{}'", name),
        (None, None) => file_path
            .clone()
            .unwrap_or_else(|| "<unresolved>".to_string()),
    };

    println!(
        "  pid={:<8} proc={:<20} events={:<40} path={}",
        pid,
        pname,
        event_names.join("|"),
        display_path,
    );

    // Detail lines for each info record
    for record in &event.records {
        let type_name = info_type_name(record.info_type);
        let resolved = resolve_handle(mount_fd, record);
        let resolved_str = resolved
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unresolved>".to_string());

        let ht_name = handle_type_name(record.handle_type);
        let ht_flags = handle_type_flags(record.handle_type);
        let ht_display = if ht_flags.is_empty() {
            ht_name.to_string()
        } else {
            format!("{}|{}", ht_name, ht_flags.join("|"))
        };

        print!(
            "    [{}] fsid={:08x}:{:08x} handle_type={}({}) ( => {})",
            type_name,
            record.fsid[0] as u32,
            record.fsid[1] as u32,
            record.handle_type,
            ht_display,
            resolved_str,
        );

        if let Some(ref name) = record.name {
            println!(" name = '{}'", name);
        } else {
            println!("");
        }
    }

    // Per-event contextual annotations
    if mask.contains(MaskFlags::FAN_Q_OVERFLOW) {
        println!("    ** event queue overflowed, events were lost **");
    }
    if mask.contains(MaskFlags::FAN_MOVED_FROM) {
        println!("    [MOVED_FROM] file is leaving this directory");
    }
    if mask.contains(MaskFlags::FAN_MOVED_TO) {
        println!("    [MOVED_TO] file is arriving in this directory");
    }
    if mask.contains(MaskFlags::FAN_RENAME) {
        println!("    [RENAME] file was renamed");
    }
    if mask.contains(MaskFlags::FAN_DELETE) {
        println!("    [DELETE] entry removed from directory");
    }
    if mask.contains(MaskFlags::FAN_DELETE_SELF) {
        println!("    [DELETE_SELF] watched object itself was deleted");
    }
    if mask.contains(MaskFlags::FAN_CREATE) {
        println!("    [CREATE] new entry created");
    }
    if mask.contains(MaskFlags::FAN_OPEN_EXEC) {
        println!("    [OPEN_EXEC] opened with intent to execute");
    }
    if mask.contains(MaskFlags::FAN_ONDIR) {
        println!("    [ONDIR] target is a directory");
    }

    if pid > 0 {
        let cmdline = process_cmdline(pid);
        if !cmdline.is_empty() {
            println!("    [process] {}", cmdline);
        }
    }
}

fn run_watch_fid(
    path: PathBuf,
    mark_type: MarkType,
    events: Vec<EventType>,
    all: bool,
    init_flags: Vec<FanInitFlag>,
) -> Result<()> {
    // Build init flags: start with user flags, add CLOEXEC, add FID reporting
    let init_bits: libc::c_uint = build_init_flags(&init_flags).bits()
        | InitFlags::FAN_CLOEXEC.bits()
        | libc::FAN_REPORT_FID
        | libc::FAN_REPORT_DFID_NAME;

    // In FID mode, child events are always reported to the parent, so
    // FAN_EVENT_ON_CHILD is implicit.  The kernel returns EINVAL if it
    // appears in the mask for mount/filesystem marks on a FID group.
    let mask = build_mask(&events, all) - MaskFlags::FAN_EVENT_ON_CHILD;
    let mark = mark_type_to_flags(&mark_type);

    println!("Initializing fanotify group (FID mode)...");
    println!(
        "  init flags: {:#010x} (includes FAN_REPORT_FID | FAN_REPORT_DFID_NAME)",
        init_bits
    );
    println!("  mark flags: {:?}", mark);
    println!("  event mask: {:?}", mask);
    println!("  path:       {}", path.display());
    if all {
        println!("  (watching ALL events)");
    }
    println!();

    // raw libc init — nix 0.29 doesn't expose FAN_REPORT_FID flags
    let raw_fd = unsafe {
        libc::fanotify_init(
            init_bits,
            (libc::O_RDONLY | libc::O_CLOEXEC) as libc::c_uint,
        )
    };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("fanotify_init failed (are you root / CAP_SYS_ADMIN?)");
    }

    // Wrap in nix's Fanotify for safe marking
    let fan = unsafe { Fanotify::from_raw_fd(raw_fd) };

    fan.mark(mark, mask, None, Some(&path))
        .context("fanotify_mark failed")?;

    // We need an fd to the watched path's filesystem for open_by_handle_at
    let mount_file = std::fs::File::open(&path)
        .with_context(|| format!("Cannot open path for handle resolution: {}", path.display()))?;
    let mount_fd = mount_file.as_raw_fd();

    println!("Listening for events (FID mode)... (Ctrl+C to stop)\n");

    let fan_fd = fan.as_fd().as_raw_fd();
    let mut buf = [0u8; 4096];

    loop {
        let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err).context("read failed");
        }

        let fid_events = parse_fid_events(&buf[..n as usize]);
        for event in &fid_events {
            print_fid_event(event, mount_fd);
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────

fn run_watch(
    path: PathBuf,
    mark_type: MarkType,
    events: Vec<EventType>,
    all: bool,
    fid: bool,
    init_flags: Vec<FanInitFlag>,
) -> Result<()> {
    if fid {
        run_watch_fid(path, mark_type, events, all, init_flags)
    } else {
        run_watch_fd(path, mark_type, events, all, init_flags)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Watch {
            path,
            mark_type,
            events,
            all,
            fid,
            init_flags,
        } => run_watch(path, mark_type, events, all, fid, init_flags),
    }
}
