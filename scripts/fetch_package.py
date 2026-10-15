#!/usr/bin/env python3
"""Fetch a direct HTTPS mobile-app package without echoing its URL or query string."""

import argparse
import getpass
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile

MAX_BYTES = 20 * 1024 * 1024 * 1024
MAX_ENTRIES = 250_000
CHUNK_SIZE = 1024 * 1024


def read_url():
    if sys.stdin.isatty():
        value = getpass.getpass("Paste the direct HTTPS URL (input hidden): ")
    else:
        value = sys.stdin.readline().strip()
    if not value:
        raise ValueError("No URL was supplied.")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Only direct HTTPS URLs are accepted.")
    if parts.username or parts.password:
        raise ValueError("Do not place account credentials in a URL.")
    return value, parts.hostname


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="new output filename, such as work/apks/app.ipa")
    parser.add_argument("--force", action="store_true", help="replace an existing output file")
    args = parser.parse_args()

    output = Path(args.output)
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not args.force:
        parser.error("output already exists; choose a new path or pass --force")

    temp_path = None
    try:
        url, source_host = read_url()
        request = Request(url, headers={"User-Agent": "mobile-package-intake/1.0"})
        try:
            response = urlopen(request, timeout=60)
        except HTTPError as error:
            if error.code in (403, 410, 618):
                raise RuntimeError(
                    f"HTTP {error.code} from {source_host}; the signed link may have expired. "
                    "Request a fresh URL. The URL itself was not printed."
                ) from None
            raise RuntimeError(
                f"HTTP {error.code} from {source_host}; the URL itself was not printed."
            ) from None
        except URLError:
            raise RuntimeError(
                f"Could not reach {source_host}; check the URL or network. The URL was not printed."
            ) from None

        with response:
            final_url = urlsplit(response.geturl())
            if final_url.scheme != "https":
                raise RuntimeError("The download redirected away from HTTPS; refusing it.")
            final_host = final_url.hostname or source_host
            content_type = response.headers.get("Content-Type", "unknown")
            digest = hashlib.sha256()
            byte_count = 0

            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".package-download-", dir=parent, delete=False
            ) as temporary:
                temp_path = Path(temporary.name)
                while True:
                    block = response.read(CHUNK_SIZE)
                    if not block:
                        break
                    byte_count += len(block)
                    if byte_count > MAX_BYTES:
                        raise RuntimeError("Download exceeded the 20 GiB safety limit.")
                    temporary.write(block)
                    digest.update(block)
                temporary.flush()
                os.fsync(temporary.fileno())

        if byte_count == 0:
            raise RuntimeError("The server returned an empty file.")
        if not zipfile.is_zipfile(temp_path):
            raise RuntimeError(
                f"Downloaded {content_type} from {final_host}, but it is not a ZIP-based app package. "
                "The URL may have returned an error page."
            )
        with zipfile.ZipFile(temp_path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise RuntimeError("Archive contains too many entries.")
            if sum(info.file_size for info in infos) > MAX_BYTES:
                raise RuntimeError("Archive exceeds the 20 GiB uncompressed-size limit.")
            damaged_member = archive.testzip()
            if damaged_member:
                raise RuntimeError(f"Archive CRC check failed at {damaged_member!r}.")

        if output.exists() and not args.force:
            raise RuntimeError("Output appeared during download; refusing to overwrite it.")
        os.replace(temp_path, output)
        temp_path = None

        print(f"Saved: {output}")
        print(f"Source host: {final_host}")
        print(f"Content-Type: {content_type}")
        print(f"Bytes: {byte_count}")
        print(f"SHA-256: {digest.hexdigest()}")
    except (ValueError, RuntimeError) as error:
        print(f"Download failed: {error}", file=sys.stderr)
        return 1
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
