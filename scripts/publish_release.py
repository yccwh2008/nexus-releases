from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Iterator

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_TEMP_GLOB = ".publish-*.tmp"
_MOVEFILE_REPLACE_EXISTING = 0x1
_MOVEFILE_WRITE_THROUGH = 0x8


class PublishError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _require_external_directories(build_output: Path, publish_root: Path, repo: Path) -> None:
    if _is_within(build_output, repo) or _is_within(publish_root, repo):
        raise PublishError("outside_repo")
    if _is_within(build_output, publish_root) or _is_within(publish_root, build_output):
        raise PublishError("separate_directories")


def _safe_basename(value: object) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise PublishError("unsafe_filename")
    if "/" in value or "\\" in value or ":" in value or Path(value).name != value:
        raise PublishError("unsafe_filename")
    return value


def _regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except OSError:
        return False


def _decode_json(data: bytes, error: str) -> dict[str, object]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublishError(error) from exc
    if not isinstance(value, dict):
        raise PublishError(error)
    return value


def _read_source_catalog_once(build_output: Path) -> dict[str, object]:
    catalog_path = build_output / "latest.json"
    if not _regular_file(catalog_path):
        raise PublishError("catalog_missing")
    try:
        data = catalog_path.read_bytes()
    except OSError as exc:
        raise PublishError("catalog_invalid") from exc
    return _decode_json(data, "catalog_invalid")


def _canonical_names(version: object) -> tuple[str, str, str]:
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise PublishError("catalog_invalid")
    return version, f"Nexus-{version}.zip", f"Nexus-{version}.manifest.json"


def _validated_catalog_identity(catalog: dict[str, object]) -> tuple[str, str, str]:
    version, archive_name, manifest_name = _canonical_names(catalog.get("version"))
    supplied_archive = _safe_basename(catalog.get("archive"))
    supplied_manifest = _safe_basename(catalog.get("manifest"))
    if supplied_archive != archive_name or supplied_manifest != manifest_name:
        raise PublishError("version_filename")
    return version, archive_name, manifest_name


def _lock_path(publish_root: Path) -> Path:
    return publish_root.parent / f".{publish_root.name}.publish.lock"


@contextlib.contextmanager
def _publish_lock(publish_root: Path) -> Iterator[None]:
    publish_root.parent.mkdir(parents=True, exist_ok=True)
    path = _lock_path(publish_root)
    stream = path.open("a+b")
    if path.stat().st_size == 0:
        stream.write(b"\0")
        stream.flush()
    stream.seek(0)
    locked = False
    try:
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise PublishError("publish_locked") from exc
        yield
    finally:
        if locked:
            try:
                stream.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()
        else:
            stream.close()


def _cleanup_stale_temps(publish_root: Path) -> None:
    for path in publish_root.glob(_TEMP_GLOB):
        if path.is_file() or path.is_symlink():
            path.unlink(missing_ok=True)


def _new_temp(publish_root: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".publish-", suffix=".tmp", dir=publish_root)
    os.close(descriptor)
    return Path(name)


def _snapshot_file(source: Path, temporary: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        code = "manifest_missing" if source.name.endswith(".manifest.json") else "archive_missing"
        raise PublishError(code) from exc
    try:
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            code = "manifest_missing" if source.name.endswith(".manifest.json") else "archive_missing"
            raise PublishError(code)
        with os.fdopen(descriptor, "rb", closefd=False) as source_stream, temporary.open("wb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            target_stream.flush()
            os.fsync(target_stream.fileno())
    finally:
        os.close(descriptor)


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _validate_snapshots(
    catalog: dict[str, object],
    version: str,
    archive_name: str,
    archive_snapshot: Path,
    manifest_snapshot: Path,
) -> dict[str, object]:
    expected_hash = catalog.get("archive_sha256")
    expected_size = catalog.get("archive_size")
    if not isinstance(expected_hash, str) or not isinstance(expected_size, int) or isinstance(expected_size, bool):
        raise PublishError("catalog_invalid")

    actual_hash, actual_size = _sha256_and_size(archive_snapshot)
    if actual_hash != expected_hash:
        raise PublishError("archive_hash")
    if actual_size != expected_size:
        raise PublishError("archive_size")

    try:
        manifest_data = manifest_snapshot.read_bytes()
    except OSError as exc:
        raise PublishError("manifest_missing") from exc
    manifest = _decode_json(manifest_data, "manifest_invalid")
    archive_entry = manifest.get("archive")
    if (
        manifest.get("version") != version
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("file_hashes"), dict)
        or not isinstance(archive_entry, dict)
        or archive_entry.get("name") != archive_name
    ):
        raise PublishError("manifest_invalid")
    if archive_entry.get("sha256") != actual_hash:
        raise PublishError("archive_hash")
    manifest_size = archive_entry.get("size")
    if not isinstance(manifest_size, int) or isinstance(manifest_size, bool) or manifest_size != actual_size:
        raise PublishError("archive_size")

    return {
        "version": version,
        "archive": archive_name,
        "manifest": f"Nexus-{version}.manifest.json",
        "archive_sha256": actual_hash,
        "archive_size": actual_size,
    }


def _write_catalog_snapshot(temporary: Path, catalog: dict[str, object]) -> None:
    data = json.dumps(catalog, ensure_ascii=False, indent=2).encode("utf-8")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _platform_name() -> str:
    return os.name


def _persist_directory(directory: Path) -> None:
    if _platform_name() == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _move_file_windows(source: Path, destination: Path, flags: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file = kernel32.MoveFileExW
    move_file.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    move_file.restype = ctypes.c_int
    if not move_file(str(source), str(destination), flags):
        error = ctypes.get_last_error()
        if not flags & _MOVEFILE_REPLACE_EXISTING and error in {80, 183}:
            raise PublishError("asset_exists")
        raise ctypes.WinError(error)


def _windows_move(source: Path, destination: Path, *, replace_existing: bool) -> None:
    flags = _MOVEFILE_WRITE_THROUGH
    if replace_existing:
        flags |= _MOVEFILE_REPLACE_EXISTING
    _move_file_windows(source, destination, flags)


def _durable_move(source: Path, destination: Path, *, replace_existing: bool) -> None:
    if _platform_name() == "nt":
        _windows_move(source, destination, replace_existing=replace_existing)
        return
    if replace_existing:
        os.replace(source, destination)
    else:
        try:
            os.link(source, destination)
        except FileExistsError as exc:
            raise PublishError("asset_exists") from exc
        os.unlink(source)
    _persist_directory(destination.parent)


def _published_version(publish_root: Path) -> str | None:
    catalog = publish_root / "latest.json"
    if not catalog.exists():
        return None
    if not _regular_file(catalog):
        raise PublishError("published_catalog_invalid")
    try:
        value = _decode_json(catalog.read_bytes(), "published_catalog_invalid")
    except OSError as exc:
        raise PublishError("published_catalog_invalid") from exc
    version = value.get("version")
    if not isinstance(version, str):
        raise PublishError("published_catalog_invalid")
    return version


def publish_release(
    build_output: str | Path,
    publish_root: str | Path,
    *,
    repo: str | Path | None = None,
) -> dict[str, str]:
    build_path = _resolved(build_output)
    publish_path = _resolved(publish_root)
    repo_path = _resolved(repo or Path(__file__).parents[1])
    _require_external_directories(build_path, publish_path, repo_path)
    if not build_path.is_dir():
        raise PublishError("build_output_missing")

    with _publish_lock(publish_path):
        publish_path.mkdir(parents=True, exist_ok=True)
        _cleanup_stale_temps(publish_path)
        catalog = _read_source_catalog_once(build_path)
        version, archive_name, manifest_name = _validated_catalog_identity(catalog)
        if _published_version(publish_path) == version:
            raise PublishError("version_exists")

        archive_source = build_path / archive_name
        manifest_source = build_path / manifest_name
        if not _regular_file(archive_source):
            raise PublishError("archive_missing")
        if not _regular_file(manifest_source):
            raise PublishError("manifest_missing")

        archive_target = publish_path / archive_name
        manifest_target = publish_path / manifest_name
        latest_target = publish_path / "latest.json"
        if archive_target.exists() or manifest_target.exists():
            raise PublishError("asset_exists")

        owned_temps: list[Path] = []
        try:
            archive_temp = _new_temp(publish_path)
            owned_temps.append(archive_temp)
            manifest_temp = _new_temp(publish_path)
            owned_temps.append(manifest_temp)
            catalog_temp = _new_temp(publish_path)
            owned_temps.append(catalog_temp)
            _snapshot_file(archive_source, archive_temp)
            _snapshot_file(manifest_source, manifest_temp)
            canonical_catalog = _validate_snapshots(
                catalog,
                version,
                archive_name,
                archive_temp,
                manifest_temp,
            )
            _write_catalog_snapshot(catalog_temp, canonical_catalog)
            _durable_move(archive_temp, archive_target, replace_existing=False)
            _durable_move(manifest_temp, manifest_target, replace_existing=False)
            _durable_move(catalog_temp, latest_target, replace_existing=True)
        finally:
            for path in owned_temps:
                path.unlink(missing_ok=True)

        return {
            "archive": str(archive_target),
            "manifest": str(manifest_target),
            "catalog": str(latest_target),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-output", required=True)
    parser.add_argument("--publish-root", required=True)
    parser.add_argument("--repo")
    args = parser.parse_args(argv)
    try:
        result = publish_release(args.build_output, args.publish_root, repo=args.repo)
    except PublishError as exc:
        print(exc.code, file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
