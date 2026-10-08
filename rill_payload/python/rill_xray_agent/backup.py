"""Bounded, privacy-filtered state backup archive operations."""
import hashlib
import json
import os
import platform
import secrets
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .canonical import canonical_bytes, read_json
from .errors import BackupError, UnsafePathError
from .safe_fs import reject_ancestor_symlinks, safe_relative, write_beneath

MAX_ENTRIES = 4096
MAX_MEMBER = 16 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_RATIO = 200
SECRET_KEYS = {'privatekey', 'private_key', 'token', 'accesstoken', 'refreshtoken',
               'password', 'authorization', 'credential', 'secret', 'clientsecret',
               'api_key', 'apikey'}
SECRET_MARKERS = ('vless://', 'vmess://', 'trojan://', 'ss://', 'privatekey',
                  'private_key', 'private key', 'authorization:', 'bearer ',
                  'github_pat_', 'ghp_', '-----begin')
DENY_NAMES = ('private', 'secret', 'token', 'password', 'credential', 'xray.key',
              'id_rsa', 'id_ed25519')


def _has_secret(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).replace('-', '').replace('_', '').lower()
            if normalized in SECRET_KEYS or _has_secret(child):
                return True
        return False
    if isinstance(value, list):
        return any(_has_secret(child) for child in value)
    if isinstance(value, str):
        lowered = value.lower()
        return any(marker.lower() in lowered for marker in SECRET_MARKERS)
    return False


def safe_content(path, data):
    """Include only bounded JSON state without secret fields or markers."""
    if any(part.lower() in DENY_NAMES for part in (path.name, *path.parts)):
        return False
    try:
        parsed = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return False
    return not _has_secret(parsed)


def _read_bounded(stream, limit):
    chunks = []
    total = 0
    while True:
        block = stream.read(min(65536, limit + 1 - total))
        if not block:
            break
        total += len(block)
        if total > limit:
            raise BackupError('member exceeds size limit')
        chunks.append(block)
    return b''.join(chunks)


def _validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise BackupError('manifest must be an object')
    if manifest.get('schemaVersion') != 2 or manifest.get('kind') != 'state':
        raise BackupError('unsupported manifest schema')
    if not isinstance(manifest.get('platform'), str) or not manifest['platform']:
        raise BackupError('manifest platform invalid')
    timestamp = manifest.get('createdAtEpochSeconds')
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise BackupError('manifest timestamp invalid')
    if not isinstance(manifest.get('candidateVersion'), str):
        raise BackupError('manifest candidateVersion invalid')
    entries = manifest.get('entries')
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise BackupError('manifest entries invalid')
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise BackupError('manifest entry invalid')
        name = entry.get('path')
        if not isinstance(name, str) or name in seen:
            raise BackupError('duplicate or invalid entry path')
        seen.add(name)
        try:
            rel = safe_relative(name)
        except UnsafePathError as exc:
            raise BackupError('manifest entry path invalid') from exc
        if len(rel.parts) < 3 or rel.parts[0] != 'data':
            raise BackupError('entry path prefix invalid')
        size = entry.get('size')
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= MAX_MEMBER:
            raise BackupError('entry size invalid')
        digest = entry.get('sha256')
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in '0123456789abcdef' for c in digest.lower())):
            raise BackupError('entry digest invalid')
        mode = entry.get('mode')
        if not isinstance(mode, int) or isinstance(mode, bool) or mode & ~0o777:
            raise BackupError('entry mode invalid')
    return entries


def _member_mode(info):
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG) or mode & 0o7000:
        raise BackupError('non-regular or privileged member')
    return stat.S_IMODE(mode)


def create_backup(out, sources, meta=None, now=0):
    entries = []
    selected = []
    total = 0
    for label, root in sources:
        if not isinstance(label, str) or not label or '/' in label or label in ('.', '..'):
            raise BackupError('source label invalid')
        root = Path(root)
        reject_ancestor_symlinks(root)
        if not root.exists():
            continue
        for path in sorted(root.rglob('*')):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MEMBER:
                continue
            with path.open('rb') as stream:
                data = _read_bounded(stream, MAX_MEMBER)
            if not safe_content(path, data):
                continue
            name = f'data/{label}/{path.relative_to(root).as_posix()}'
            try:
                safe_relative(name)
            except UnsafePathError as exc:
                raise BackupError('source path invalid') from exc
            mode = stat.S_IMODE(path.stat().st_mode) & 0o777
            digest = hashlib.sha256(data).hexdigest()
            entries.append({'path': name, 'sha256': digest, 'size': len(data), 'mode': mode})
            selected.append((path, name, mode, len(data), digest))
            total += len(data)
            if len(entries) > MAX_ENTRIES or total > MAX_TOTAL:
                raise BackupError('backup limits exceeded')
    manifest = {'schemaVersion': 2, 'kind': 'state',
                'createdAtEpochSeconds': now, 'candidateVersion': '1.0.0',
                'platform': platform.system().lower(), 'entries': entries}
    if meta:
        if not isinstance(meta, dict) or set(meta) & set(manifest) or _has_secret(meta):
            raise BackupError('backup metadata invalid or contains secrets')
        manifest.update(meta)
    _validate_manifest(manifest)
    if _has_secret(manifest):
        raise BackupError('manifest contains secret material')
    manifest_data = canonical_bytes(manifest) + b'\n'
    if len(manifest_data) > MAX_MANIFEST or total + len(manifest_data) > MAX_TOTAL:
        raise BackupError('backup limits exceeded')

    output = Path(out)
    output.parent.mkdir(parents=True, exist_ok=True)
    reject_ancestor_symlinks(output.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f'.{output.name}.backup.', dir=output.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    previous = output.with_name(f'.{output.name}.previous.{secrets.token_hex(8)}')
    had_previous = published = False
    epoch = (2026, 8, 4, 0, 0, 0)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo('MANIFEST.json', epoch)
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, manifest_data)
            for source_path, name, mode, expected_size, expected_hash in selected:
                info = zipfile.ZipInfo(name, epoch)
                info.external_attr = (stat.S_IFREG | mode) << 16
                digest = hashlib.sha256()
                size = 0
                with archive.open(info, 'w') as dest, source_path.open('rb') as source:
                    while True:
                        block = source.read(65536)
                        if not block:
                            break
                        size += len(block)
                        digest.update(block)
                        dest.write(block)
                if size != expected_size or digest.hexdigest() != expected_hash:
                    raise BackupError('source changed while backup was created')
        with temporary.open('rb') as stream:
            os.fsync(stream.fileno())
        if output.is_symlink() or (output.exists() and not output.is_file()):
            raise BackupError('backup target is not a regular file')
        if output.exists():
            os.link(output, previous, follow_symlinks=False)
            had_previous = True
        os.replace(temporary, output)
        published = True
        dir_fd = os.open(output.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        if published:
            if had_previous:
                os.replace(previous, output)
            else:
                output.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)
        previous.unlink(missing_ok=True)
    return manifest


def verify_backup(path):
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if (len(infos) > MAX_ENTRIES + 1 or len(names) != len(set(names))
                    or 'MANIFEST.json' not in names):
                raise BackupError('members invalid')
            total = 0
            for info in infos:
                try:
                    safe_relative(info.filename)
                except UnsafePathError as exc:
                    raise BackupError('member path invalid') from exc
                if info.flag_bits & 1:
                    raise BackupError('encrypted members unsupported')
                _member_mode(info)
                limit = MAX_MANIFEST if info.filename == 'MANIFEST.json' else MAX_MEMBER
                if (info.file_size > limit or
                        (info.compress_size and info.file_size / info.compress_size > MAX_RATIO)):
                    raise BackupError('member limits exceeded')
                total += info.file_size
                if total > MAX_TOTAL:
                    raise BackupError('archive total limit exceeded')
            manifest_info = archive.getinfo('MANIFEST.json')
            with archive.open(manifest_info) as stream:
                manifest_data = _read_bounded(stream, MAX_MANIFEST)
            if len(manifest_data) != manifest_info.file_size:
                raise BackupError('manifest size mismatch')
            manifest = json.loads(manifest_data.decode('utf-8'))
            entries = _validate_manifest(manifest)
            if _has_secret(manifest):
                raise BackupError('manifest contains secret material')
            expected = {entry['path']: entry for entry in entries}
            if set(names) - {'MANIFEST.json'} != set(expected):
                raise BackupError('archive coverage mismatch')
            for name, entry in expected.items():
                info = archive.getinfo(name)
                if info.file_size != entry['size'] or _member_mode(info) != entry['mode']:
                    raise BackupError('member metadata mismatch')
                digest = hashlib.sha256()
                count = 0
                chunks = []
                with archive.open(info) as stream:
                    while True:
                        block = stream.read(min(65536, MAX_MEMBER + 1 - count))
                        if not block:
                            break
                        count += len(block)
                        if count > MAX_MEMBER:
                            raise BackupError('member exceeds size limit')
                        digest.update(block)
                        chunks.append(block)
                if count != entry['size'] or digest.hexdigest() != entry['sha256']:
                    raise BackupError('member digest mismatch')
                if not safe_content(Path(name), b''.join(chunks)):
                    raise BackupError('member contains unsafe or unknown content')
            return manifest
    except BackupError:
        raise
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            RuntimeError, UnicodeDecodeError) as exc:
        raise BackupError(f'invalid backup: {exc}') from exc


def _create_restore_journal(path, record):
    data = canonical_bytes(record) + b'\n'
    temporary = path.with_name(f'.{path.name}.{secrets.token_hex(8)}.tmp')
    try:
        with temporary.open('xb') as stream:
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                try:
                    written = stream.write(view[offset:])
                except InterruptedError:
                    continue
                if written is None or written <= 0:
                    raise BackupError('restore journal write made no progress')
                offset += written
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _recover_restore_transaction(target):
    journal = target.parent / f'.{target.name}.restore-journal.json'
    if not journal.exists():
        return
    if journal.is_symlink() or not journal.is_file():
        raise BackupError('unsafe restore journal')
    try:
        record = read_json(journal)
    except Exception as exc:
        raise BackupError('restore journal unreadable; recovery material retained') from exc
    prefix = f'.{target.name}.'
    if not isinstance(record, dict):
        raise BackupError('restore journal invalid')
    stage_name, old_name = record.get('staging'), record.get('previous')
    if (record.get('schemaVersion') != 1 or record.get('target') != target.name
            or not isinstance(stage_name, str) or not stage_name.startswith(prefix + 'restore.')
            or PurePosixPath(stage_name).name != stage_name
            or not isinstance(old_name, str) or not old_name.startswith(prefix + 'previous.')
            or PurePosixPath(old_name).name != old_name):
        raise BackupError('restore journal invalid')
    stage, old = target.parent / stage_name, target.parent / old_name
    if stage.is_symlink() or old.is_symlink():
        raise BackupError('restore transaction path is a symlink')
    if target.exists():
        if old.exists():
            shutil.rmtree(old)
    elif record.get('hadTarget') and old.exists():
        os.replace(old, target)
    elif not record.get('hadTarget') and stage.exists():
        os.replace(stage, target)
    for leftover in (stage, old):
        if leftover.exists():
            shutil.rmtree(leftover)
    journal.unlink(missing_ok=True)


def restore_backup(path, target, force=False):
    manifest = verify_backup(path)
    target = Path(target)
    reject_ancestor_symlinks(target.parent)
    _recover_restore_transaction(target)
    if target.is_symlink() or (target.exists() and
                               (not target.is_dir() or (any(target.iterdir()) and not force))):
        raise BackupError('target is non-empty, unsafe, or not a directory')
    suffix = secrets.token_hex(12)
    staging = target.parent / f'.{target.name}.restore.{suffix}'
    old = target.parent / f'.{target.name}.previous.{suffix}'
    journal = target.parent / f'.{target.name}.restore-journal.json'
    staging.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(path) as archive:
            for entry in manifest['entries']:
                with archive.open(entry['path']) as source:
                    data = _read_bounded(source, entry['size'])
                if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                    raise BackupError('restore staging digest mismatch')
                write_beneath(staging, '/'.join(PurePosixPath(entry['path']).parts[1:]),
                              data, entry['mode'])
        record = {'schemaVersion': 1, 'target': target.name,
                  'staging': staging.name, 'previous': old.name,
                  'hadTarget': target.exists()}
        if journal.exists() or journal.is_symlink():
            raise BackupError('restore transaction already requires recovery')
        _create_restore_journal(journal, record)
        if target.exists():
            os.replace(target, old)
        try:
            os.replace(staging, target)
        except OSError:
            if old.exists() and not target.exists():
                os.replace(old, target)
            raise
        if old.exists():
            shutil.rmtree(old)
        journal.unlink(missing_ok=True)
        return manifest
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        if not target.exists() and old.exists():
            os.replace(old, target)
        elif target.exists() and old.exists():
            shutil.rmtree(old, ignore_errors=True)
        journal.unlink(missing_ok=True)
        raise
