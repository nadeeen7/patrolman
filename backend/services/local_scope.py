"""Exact local-directory authorization and bounded, link-free scan snapshots."""
import os
import stat
import time
from pathlib import Path, PurePosixPath
from .target_validation import ScopeError, TargetError

MAX_FILES = 10000
MAX_BYTES = 100_000_000
MAX_FILE_BYTES = 10_000_000


def _plain(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ScopeError('Links and Windows reparse points are prohibited in local scope.')
    return info


def validate_local(value, allowed):
    if not isinstance(value, str) or not value or len(value) > 253 or '\0' in value:
        raise TargetError('Supply an absolute local directory path (maximum 253 characters).')
    if value.startswith(('\\\\', '//')):
        raise ScopeError('Network shares and device paths are not local assessment targets.')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise TargetError('An absolute directory without parent traversal is required.')
    # Compare before accessing any user-selected path.
    approved = {os.path.normcase(os.path.abspath(p)) for p in allowed}
    if os.path.normcase(str(path)) not in approved:
        raise ScopeError('Directory is not in AVA_ALLOWED_LOCAL_ROOTS (exact match required).')
    try:
        for part in [*reversed(path.parents), path]:
            _plain(part)
        if not path.is_dir():
            raise TargetError('Local target must be a directory.')
    except OSError as exc:
        raise TargetError('Authorized directory is unavailable.') from exc
    return str(path)


def snapshot(source, destination, cancel=None):
    """Never hand the original source tree to a scanner. Exclude Git history.

    Use only on an administrator-controlled, quiescent directory. Reject links,
    special files, hardlinks and changing files rather than silently widen scope.
    """
    root, dest = Path(source), Path(destination)
    dest.mkdir()
    count = total = 0
    deadline = time.monotonic() + 30
    def check():
        if cancel and cancel.is_set(): raise ValueError('Local snapshot cancelled.')
        if time.monotonic() > deadline: raise ValueError('Local snapshot timed out.')
    for directory, dirs, files in os.walk(root, followlinks=False):
        check()
        _plain(Path(directory))
        dirs[:] = [d for d in dirs if d != '.git']
        for name in dirs: _plain(Path(directory) / name)
        for name in files:
            check()
            if name == '.git': continue
            src = Path(directory) / name
            before = _plain(src)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ScopeError('Special files and hardlinks are prohibited.')
            count += 1; total += before.st_size
            if count > MAX_FILES or total > MAX_BYTES or before.st_size > MAX_FILE_BYTES:
                raise ValueError('Local snapshot exceeds file/size limits; select a smaller authorized directory.')
            relative = src.relative_to(root)
            out = dest / relative
            out.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(src, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
            with os.fdopen(fd, 'rb') as handle:
                opened = os.fstat(handle.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise ScopeError('Source changed while snapshotting.')
                content = handle.read(MAX_FILE_BYTES + 1)
                after = os.fstat(handle.fileno())
            if len(content) != before.st_size or after.st_mtime_ns != before.st_mtime_ns or src.resolve() != src:
                raise ScopeError('Source changed while snapshotting.')
            out.write_bytes(content)
    return {'files': count, 'bytes': total, 'git_history': False}


def relative_file(value, root):
    """Reject output paths escaping the snapshot; never retain raw scanner text."""
    if not isinstance(value, str) or not value or '\0' in value:
        raise ValueError('Missing result file path.')
    path = Path(value)
    if path.is_absolute():
        try: value = path.relative_to(Path(root)).as_posix()
        except ValueError: raise ValueError('Out-of-scope result file.')
    p = PurePosixPath(value.replace('\\', '/'))
    if p.is_absolute() or '..' in p.parts or ':' in str(p):
        raise ValueError('Out-of-scope result file.')
    return str(p)
