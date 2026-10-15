#!/usr/bin/env python3
"""Safely extract and inventory an APK, IPA, APKM, or XAPK using Python's standard library."""

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import subprocess
import sys
import zipfile

MAX_ENTRIES = 250_000
MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative_path(member_name):
    normalized = member_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"Unsafe archive path: {member_name!r}")
    if re.match(r"^[A-Za-z]:", path.parts[0]):
        raise ValueError(f"Unsafe archive path: {member_name!r}")
    return Path(*path.parts)


def is_symlink(info):
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def run_optional(command):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def android_metadata(package_path):
    result = {"application_id": None, "version_name": None, "version_code": None, "tool": None}
    apkanalyzer = shutil.which("apkanalyzer")
    if apkanalyzer:
        app_id = run_optional([apkanalyzer, "manifest", "application-id", str(package_path)])
        version_name = run_optional([apkanalyzer, "manifest", "version-name", str(package_path)])
        version_code = run_optional([apkanalyzer, "manifest", "version-code", str(package_path)])
        if app_id or version_name or version_code:
            result.update(
                application_id=app_id,
                version_name=version_name,
                version_code=version_code,
                tool="apkanalyzer",
            )
            return result

    aapt = shutil.which("aapt")
    if aapt:
        output = run_optional([aapt, "dump", "badging", str(package_path)])
        if output:
            first = output.splitlines()[0]
            match = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", first)
            if match:
                result.update(
                    application_id=match.group(1),
                    version_code=match.group(2),
                    version_name=match.group(3),
                    tool="aapt",
                )
    return result


def parse_ipa_plists(archive):
    apps = []
    for name in archive.namelist():
        if not (name.endswith(".app/Info.plist") or name.endswith(".appex/Info.plist")):
            continue
        try:
            data = plistlib.loads(archive.read(name))
        except Exception as error:
            apps.append({"path": name, "parse_error": type(error).__name__})
            continue
        apps.append(
            {
                "path": name,
                "bundle_identifier": data.get("CFBundleIdentifier"),
                "display_name": data.get("CFBundleDisplayName") or data.get("CFBundleName"),
                "short_version": data.get("CFBundleShortVersionString"),
                "build_version": data.get("CFBundleVersion"),
                "minimum_os": data.get("MinimumOSVersion"),
                "executable": data.get("CFBundleExecutable"),
            }
        )
    return apps


def extract_safely(archive, destination, infos):
    destination.mkdir(parents=True, exist_ok=False)
    root = destination.resolve()
    extracted_bytes = 0
    seen_paths = set()
    for info in infos:
        relative = safe_relative_path(info.filename)
        path_key = relative.as_posix().casefold()
        if path_key in seen_paths:
            raise ValueError(f"Duplicate or case-colliding archive path: {info.filename!r}")
        seen_paths.add(path_key)
        if is_symlink(info):
            raise ValueError(f"Refusing symbolic link in archive: {info.filename!r}")
        if info.flag_bits & 1:
            raise ValueError(f"Refusing encrypted ZIP member: {info.filename!r}")
        if info.file_size < 0:
            raise ValueError(f"Invalid size for archive member: {info.filename!r}")
        extracted_bytes += info.file_size
        if extracted_bytes > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Archive exceeds the 20 GiB uncompressed-size limit.")

        target = (destination / relative).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            raise ValueError(f"Archive path escapes output directory: {info.filename!r}") from None
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as source, target.open("wb") as output:
            copied = 0
            while True:
                block = source.read(CHUNK_SIZE)
                if not block:
                    break
                copied += len(block)
                if copied > info.file_size or copied > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError(f"Unexpected expanded size for {info.filename!r}")
                output.write(block)
            if copied != info.file_size:
                raise ValueError(f"Size mismatch for archive member {info.filename!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="path to an APK, IPA, APKM, or XAPK")
    parser.add_argument("outdir", help="new analysis directory; it must not already exist")
    parser.add_argument("--no-extract", action="store_true", help="write inventory only")
    args = parser.parse_args()

    package = Path(args.package)
    outdir = Path(args.outdir)
    if not package.is_file():
        parser.error(f"package file not found: {package}")
    if outdir.exists():
        parser.error(f"output directory already exists: {outdir}")
    if not zipfile.is_zipfile(package):
        parser.error("input is not a ZIP-based app package")

    suffix = package.suffix.lower()
    kind = {
        ".apk": "APK",
        ".ipa": "IPA",
        ".apkm": "APKM split-package archive",
        ".xapk": "XAPK split-package archive",
        ".aab": "Android App Bundle",
    }.get(suffix, "ZIP-based package")

    try:
        outdir.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(package) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ValueError("Archive contains too many entries.")
            total_uncompressed = sum(info.file_size for info in infos)
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Archive exceeds the 20 GiB uncompressed-size limit.")

            names = [info.filename for info in infos]
            extension_counts = Counter(Path(name).suffix.lower() or "[no extension]" for name in names)
            dex_files = [name for name in names if re.search(r"(^|/)classes(?:\d+)?\.dex$", name)]
            native_files = [name for name in names if name.lower().endswith((".so", ".dylib"))]
            nested_apks = [name for name in names if name.lower().endswith(".apk")]
            largest = sorted(
                (
                    {"path": info.filename, "bytes": info.file_size}
                    for info in infos
                    if not info.is_dir()
                ),
                key=lambda item: item["bytes"],
                reverse=True,
            )[:25]

            report = {
                "source_file": package.name,
                "sha256": sha256_file(package),
                "bytes": package.stat().st_size,
                "package_type": kind,
                "archive_entries": len(infos),
                "uncompressed_bytes": total_uncompressed,
                "extension_counts": dict(extension_counts),
                "dex_files": dex_files,
                "native_libraries": native_files,
                "nested_apks": nested_apks,
                "largest_files": largest,
            }
            if suffix == ".apk":
                report["android_manifest"] = android_metadata(package)
            if suffix == ".ipa":
                report["apple_bundles"] = parse_ipa_plists(archive)

            if not args.no_extract:
                extract_safely(archive, outdir / "extracted", infos)
            else:
                outdir.mkdir(parents=True, exist_ok=False)
            (outdir / "intake.json").write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as error:
        print(f"Inspection failed: {error}", file=sys.stderr)
        return 1

    print(f"Type: {kind}")
    print(f"SHA-256: {report['sha256']}")
    print(f"Archive entries: {report['archive_entries']}")
    if suffix == ".apk":
        print(f"Android metadata: {json.dumps(report['android_manifest'], ensure_ascii=False)}")
    if suffix == ".ipa":
        print(f"Apple bundles: {len(report['apple_bundles'])}")
    print(f"Report: {outdir / 'intake.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
