# fanotify_audit

A CLI tool for experimenting with Linux's [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) API. Watches filesystem events on files, directories, mount points, or entire filesystems, with support for both traditional FD-based and modern FID-based event reporting.

## Building

```
cargo build --release
```

Requires Linux with fanotify support. Must be run as root (or with `CAP_SYS_ADMIN`).

## Usage

```
sudo target/release/fanotify_audit watch [OPTIONS] -p <PATH>
```

### Options

| Option | Description |
|--------|-------------|
| `-p, --path <PATH>` | Path to watch (file, directory, or mount point) |
| `-t, --mark-type <TYPE>` | What to mark: `inode` (default), `mount`, or `filesystem` |
| `-e, --events <LIST>` | Comma-separated events (default: `access,modify,open,close`) |
| `-a, --all` | Watch all supported events |
| `--fid` | Use FID mode: report file handles, directory, and filenames instead of file descriptors |
| `-i, --init-flags <FLAGS>` | Comma-separated init flags (e.g. `nonblock,unlimited-queue,report-tid`) |

### Event types

`access`, `modify`, `attrib`, `close-write`, `close-nowrite`, `close`, `open`, `moved-from`, `moved-to`, `move`, `create`, `delete`, `delete-self`, `move-self`, `open-exec`, `rename`, `ondir`, `event-on-child`

### Init flags

`cloexec`, `nonblock`, `class-notif`, `class-content`, `class-pre-content`, `unlimited-queue`, `unlimited-marks`, `report-pidfd`, `report-tid`

## Examples

Watch all events on a mount point (FD mode):

```
sudo fanotify_audit watch -p /home -t mount --all
```

Watch all events with FID reporting (includes filenames and directory info):

```
sudo fanotify_audit watch -p /home -t mount --all --fid
```

Watch only file creation and deletion on a specific directory:

```
sudo fanotify_audit watch -p /tmp -e create,delete,ondir
```

## FD vs FID mode

**FD mode** (default) returns an open file descriptor for each event, which can be used to read `/proc/self/fd/<fd>` to resolve the path. Simple but limited — no filename info for directory events like create/delete.

**FID mode** (`--fid`) uses `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` to report events with filesystem IDs and file handles. Events carry info records containing the directory file handle and the filename of the affected entry. Paths are resolved via `open_by_handle_at(2)`. This is the modern approach and provides richer information.

## License

MIT
