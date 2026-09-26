"""打包已验证的静态发布目录；CI 只解包、复验，不构建客户端。"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import publish_release as publisher

PublishError = publisher.PublishError
PAGES_LIMIT = 1_000_000_000
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
ASSET_RE = re.compile(rf"Nexus-({VERSION})\.(zip|manifest\.json)")
STATIC = {"index.html", "app.js", "style.css", "install.ps1", ".nojekyll", "releases.json"}
TEMPLATE = Path(__file__).parent


def version_key(value):
    if not isinstance(value, str) or not re.fullmatch(VERSION, value):
        raise PublishError("release_version")
    return tuple(int(part) for part in value.split("."))


def version_from_tag(tag):
    if not isinstance(tag, str) or not re.fullmatch("v" + VERSION, tag):
        raise PublishError("release_tag")
    return tag[1:]


def _json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PublishError("site_json") from exc


def _regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise PublishError("site_file_type")


def _directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise PublishError("site_file_type")


def _allowed_name(name, *, complete):
    allowed = {"latest.json"} | (STATIC if complete else set())
    if name not in allowed and ASSET_RE.fullmatch(name) is None:
        raise PublishError("site_filename")


def _catalogs(root, version, limit, *, complete):
    version_key(version)
    _directory(root)
    files = list(root.iterdir())
    for path in files:
        _allowed_name(path.name, complete=complete)
        _regular(path)
    if sum(path.stat().st_size for path in files) > limit:
        raise PublishError("pages_size_limit")
    names = {path.name for path in files}
    latest = _json(root / "latest.json")
    if not isinstance(latest, dict):
        raise PublishError("catalog_invalid")
    selected, archive_name, _ = publisher._validated_catalog_identity(latest)
    version_key(selected)
    if selected != version:
        raise PublishError("release_version_mismatch")
    canonical_latest = publisher._validate_snapshots(
        latest, selected, archive_name, root / archive_name, root / latest["manifest"]
    )
    if latest != canonical_latest:
        raise PublishError("catalog_invalid")
    versions = {ASSET_RE.fullmatch(name).group(1) for name in names if ASSET_RE.fullmatch(name)}
    if not versions or max(versions, key=version_key) != version:
        raise PublishError("release_version_mismatch")
    expected = {"latest.json"} | (STATIC if complete else set())
    catalogs = []
    for current in sorted(versions, key=version_key):
        archive = f"Nexus-{current}.zip"
        manifest_name = f"Nexus-{current}.manifest.json"
        expected.update((archive, manifest_name))
        if not {archive, manifest_name} <= names:
            raise PublishError("release_pair_missing")
        manifest = _json(root / manifest_name)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("archive"), dict):
            raise PublishError("manifest_invalid")
        entry = manifest["archive"]
        catalog = {
            "version": current, "archive": archive, "manifest": manifest_name,
            "archive_sha256": entry.get("sha256"), "archive_size": entry.get("size"),
        }
        catalogs.append(publisher._validate_snapshots(
            catalog, current, archive, root / archive, root / manifest_name
        ))
    if names != expected:
        raise PublishError("site_files_missing")
    return catalogs


def validate_site(root, version, *, limit=PAGES_LIMIT):
    root = Path(root)
    catalogs = _catalogs(root, version, limit, complete=True)
    if _json(root / "releases.json") != catalogs:
        raise PublishError("release_inventory")
    return catalogs


def pack_site(publish_root, install_script, output_dir, version, *, limit=PAGES_LIMIT):
    """仅接受安全发布器产生的完整目录，快照后复用其三件套校验。"""
    version_key(version)
    source, installer, output = map(Path, (publish_root, install_script, output_dir))
    _directory(source)
    _regular(installer)
    publisher._require_external_directories(source.resolve(), output.resolve(), TEMPLATE.parents[1].resolve())
    output.mkdir(parents=True, exist_ok=True)
    bundle = output / f"Nexus-site-{version}.zip"
    digest_path = bundle.with_name(bundle.name + ".sha256")
    if bundle.exists() or digest_path.exists():
        raise PublishError("asset_exists")
    owned = []
    try:
        with tempfile.TemporaryDirectory(prefix=".release-site-", dir=output) as temporary:
            stage = Path(temporary)
            for path in source.iterdir():
                _allowed_name(path.name, complete=False)
                _regular(path)
                publisher._snapshot_file(path, stage / path.name)
            catalogs = _catalogs(stage, version, limit, complete=False)
            latest_bytes = (stage / "latest.json").read_bytes()
            (stage / "latest.json").unlink()
            for name in ("index.html", "style.css", "app.js"):
                publisher._snapshot_file(TEMPLATE / name, stage / name)
            publisher._snapshot_file(installer, stage / "install.ps1")
            (stage / ".nojekyll").write_bytes(b"")
            (stage / "releases.json").write_text(json.dumps(catalogs, indent=2), encoding="utf-8")
            (stage / "latest.json").write_bytes(latest_bytes)
            validate_site(stage, version, limit=limit)
            # ZIP_STORED 避免再次压缩客户端 ZIP；latest 保持最后一个成员。
            with bundle.open("xb") as stream:
                owned.append(bundle)
                with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as archive:
                    paths = sorted(stage.iterdir(), key=lambda p: (p.name == "latest.json", p.name))
                    for path in paths:
                        archive.write(path, path.name)
            digest, _ = publisher._sha256_and_size(bundle)
            with digest_path.open("x", encoding="ascii") as stream:
                owned.append(digest_path)
                stream.write(f"{digest}  {bundle.name}\n")
        return bundle
    except Exception:
        for path in owned:
            path.unlink(missing_ok=True)
        raise


def _check_release_assets(release, version, site_root=None):
    assets = release.get("assets")
    if not isinstance(assets, list) or not all(isinstance(asset, dict) for asset in assets):
        raise PublishError("release_asset_invalid")
    for name in (f"Nexus-{version}.zip", f"Nexus-{version}.manifest.json"):
        matches = [asset for asset in assets if asset.get("name") == name]
        if not matches:
            raise PublishError("release_asset_missing")
        if len(matches) != 1:
            raise PublishError("release_asset_invalid")
        asset = matches[0]
        digest, size = asset.get("digest"), asset.get("size")
        if (asset.get("state") != "uploaded" or type(size) is not int or size <= 0
                or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)):
            raise PublishError("release_asset_invalid")
        if site_root is not None:
            path = Path(site_root) / name
            _regular(path)
            actual_hash, actual_size = publisher._sha256_and_size(path)
            if digest != f"sha256:{actual_hash}":
                raise PublishError("release_asset_hash")
            if size != actual_size:
                raise PublishError("release_asset_size")


def check_releases(releases, version, included=None, *, site_root=None):
    """只部署最高正式版本，并将每版文件绑定到 Release 的原资产身份。"""
    version_key(version)
    if not isinstance(releases, list):
        raise PublishError("release_inventory_invalid")
    published = {}
    for item in releases:
        if not isinstance(item, dict) or type(item.get("draft")) is not bool or type(item.get("prerelease")) is not bool:
            raise PublishError("release_inventory_invalid")
        if item["draft"] or item["prerelease"]:
            continue
        tag = item.get("tag_name")
        if isinstance(tag, str) and re.fullmatch("v" + VERSION, tag):
            current = tag[1:]
            if current in published:
                raise PublishError("release_inventory_invalid")
            published[current] = item
    if version not in published:
        raise PublishError("release_not_published")
    if max(published, key=version_key) != version:
        raise PublishError("newer_release_exists")
    if included is not None and set(included) != set(published):
        raise PublishError("release_history_missing")
    for current, release in published.items():
        _check_release_assets(release, current, site_root)


def unpack_site(bundle, checksum, output, version, *, releases=None, limit=PAGES_LIMIT):
    version_key(version)
    bundle, checksum, output = map(Path, (bundle, checksum, output))
    if output.exists() or output.is_symlink():
        raise PublishError("site_exists")
    _regular(bundle)
    _regular(checksum)
    if bundle.name != f"Nexus-site-{version}.zip":
        raise PublishError("site_filename")
    if checksum.stat().st_size > 256 or bundle.stat().st_size > limit + 1_000_000:
        raise PublishError("pages_size_limit")
    digest, _ = publisher._sha256_and_size(bundle)
    if checksum.read_text(encoding="ascii").strip() != f"{digest}  {bundle.name}":
        raise PublishError("site_hash")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".release-site-", dir=output.parent) as temporary:
        stage = Path(temporary) / "site"
        stage.mkdir()
        with zipfile.ZipFile(bundle) as archive:
            members = archive.infolist()
            names = set()
            for member in members:
                _allowed_name(member.filename, complete=True)
                if member.filename in names:
                    raise PublishError("site_duplicate")
                names.add(member.filename)
                mode = member.external_attr >> 16
                if member.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    raise PublishError("site_file_type")
            if sum(member.file_size for member in members) > limit:
                raise PublishError("pages_size_limit")
            for member in sorted(members, key=lambda m: (m.filename == "latest.json", m.filename)):
                with archive.open(member) as incoming, (stage / member.filename).open("xb") as target:
                    shutil.copyfileobj(incoming, target, length=1024 * 1024)
        catalogs = validate_site(stage, version, limit=limit)
        check_releases(releases, version, {item["version"] for item in catalogs}, site_root=stage)
        stage.rename(output)
    return catalogs


def _release_list(path):
    value = _json(Path(path))
    # gh api --paginate --slurp 返回按页嵌套的数组。
    if isinstance(value, list) and all(isinstance(page, list) for page in value):
        return [item for page in value for item in page]
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    tag = commands.add_parser("version")
    tag.add_argument("--tag", required=True)
    pack = commands.add_parser("pack")
    pack.add_argument("--publish-root", required=True)
    pack.add_argument("--install-script", required=True)
    pack.add_argument("--output-dir", required=True)
    pack.add_argument("--version", required=True)
    unpack = commands.add_parser("unpack")
    unpack.add_argument("--bundle", required=True)
    unpack.add_argument("--checksum", required=True)
    unpack.add_argument("--output", required=True)
    unpack.add_argument("--version", required=True)
    unpack.add_argument("--releases", required=True)
    gate = commands.add_parser("gate")
    gate.add_argument("--version", required=True)
    gate.add_argument("--releases", required=True)
    gate.add_argument("--site")
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(version_from_tag(args.tag))
        elif args.command == "pack":
            print(pack_site(args.publish_root, args.install_script, args.output_dir, args.version))
        elif args.command == "unpack":
            catalogs = unpack_site(args.bundle, args.checksum, args.output, args.version,
                                   releases=_release_list(args.releases))
            print(json.dumps({"validated_versions": [item["version"] for item in catalogs]}))
        else:
            included = None
            if args.site:
                included = {item["version"] for item in validate_site(args.site, args.version)}
            check_releases(_release_list(args.releases), args.version, included, site_root=args.site)
            print(json.dumps({"eligible_version": args.version}))
    except PublishError as exc:
        print(exc.code, file=sys.stderr)
        return 2
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"site_io_invalid:{type(exc).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
