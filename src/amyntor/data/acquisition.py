"""Bounded, transactional GUIDE acquisition. Dataset payloads remain opaque bytes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import time
import tomllib
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.client import HTTPException, HTTPResponse
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import IO, BinaryIO, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import BadZipFile, ZipFile

DATASET = "microsoft/microsoft-security-incident-prediction"
SOURCE = f"https://www.kaggle.com/datasets/{DATASET}"
API = "https://www.kaggle.com/api/v1/datasets"
LICENSE = "CDLA-Permissive-2.0"
LICENSE_PAGE = "https://cdla.dev/permissive-2-0/"
LICENSE_TEXT = (
    "https://raw.githubusercontent.com/Community-Data-License-Agreements/"
    "Releases/main/CDLA-Permissive-2.0.txt"
)
CHUNK = 1024 * 1024
METADATA_LIMIT = 2 * 1024 * 1024
ZIP_DIRECTORY_LIMIT = 64 * 1024
ALLOWED_HOSTS = {
    "www.kaggle.com",
    "storage.googleapis.com",
    "raw.githubusercontent.com",
}


class AcquisitionError(ValueError):
    """Missing provenance or failed integrity/resource invariant."""


@dataclass(frozen=True)
class FileSpec:
    name: str
    bytes: int


@dataclass(frozen=True)
class Limits:
    archive_bytes: int
    expanded_bytes: int
    metadata_bytes: int
    timeout_seconds: int
    total_seconds: int
    attempts: int


@dataclass(frozen=True)
class AcquisitionConfig:
    version: int
    created_at: str
    license_sha256: str
    files: tuple[FileSpec, ...]
    limits: Limits


@dataclass
class Response:
    body: BinaryIO
    url: str
    length: int | None = None


Transport = Callable[[str, int], AbstractContextManager[Response]]


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AcquisitionError("Expected a JSON/TOML object")
    if any(not isinstance(k, str) for k in cast(dict[object, object], value)):
        raise AcquisitionError("Expected string object keys")
    return cast(dict[str, object], value)


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AcquisitionError("Expected a list")
    return cast(list[object], value)


def _positive(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise AcquisitionError("Expected a positive integer")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AcquisitionError("Missing text evidence")
    return value


def _filename(value: object) -> str:
    name = _text(value)
    # GUIDE's release has flat filenames. Reject traversal, Windows ADS/devices,
    # ambiguous separators/case and any format requiring recursive extraction.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise AcquisitionError("Unsafe or unsupported member name")
    if name.endswith((".", " ")) or name.split(".")[0].upper() in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        raise AcquisitionError("Reserved member name")
    return name


def read_config(path: Path) -> AcquisitionConfig:
    raw = _object(tomllib.loads(_metadata_bytes(path).decode("utf-8")))
    if set(raw) != {"source", "limits", "files"}:
        raise AcquisitionError("Unexpected configuration sections")
    source = _object(raw["source"])
    if set(source) != {"version", "created_at", "license_sha256"}:
        raise AcquisitionError("Missing or unexpected release configuration")
    limits_raw = _object(raw["limits"])
    if set(limits_raw) != set(Limits.__dataclass_fields__):
        raise AcquisitionError("Missing or unexpected acquisition limits")
    limits = Limits(**{key: _positive(value) for key, value in limits_raw.items()})
    if limits.attempts > 5:
        raise AcquisitionError("At most five attempts are permitted")
    files: list[FileSpec] = []
    for item in _list(raw["files"]):
        entry = _object(item)
        if set(entry) != {"name", "bytes"}:
            raise AcquisitionError("Missing or unexpected file metadata")
        files.append(FileSpec(_filename(entry["name"]), _positive(entry["bytes"])))
    if not files or len({f.name.casefold() for f in files}) != len(files):
        raise AcquisitionError("Empty or duplicate file inventory")
    if sum(f.bytes for f in files) > limits.expanded_bytes:
        raise AcquisitionError("Expected inventory exceeds expansion budget")
    license_digest = _text(source["license_sha256"])
    if not re.fullmatch(r"[0-9a-f]{64}", license_digest):
        raise AcquisitionError("Missing/invalid pinned license digest")
    return AcquisitionConfig(
        _positive(source["version"]),
        _text(source["created_at"]),
        license_digest,
        tuple(sorted(files, key=lambda f: f.name)),
        limits,
    )


def sanitize_origin(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname not in ALLOWED_HOSTS
        or parts.username
        or parts.password
        or parts.port not in (None, 443)
    ):
        raise AcquisitionError("Unapproved acquisition origin")
    # Signed redirect queries are ephemeral credentials, never persisted.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


class _Redirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> Request | None:
        sanitize_origin(newurl)
        # No authorization headers are used or forwarded by this public client.
        return Request(newurl, headers={"User-Agent": "amyntor-acquisition/1"})


@contextmanager
def open_public(url: str, timeout: int) -> Generator[Response]:
    """Public HTTPS only; no SDK, stored credentials or credential discovery."""
    sanitize_origin(url)
    opener = build_opener(_Redirects())
    request = Request(url, headers={"User-Agent": "amyntor-acquisition/1"})
    with cast(HTTPResponse, opener.open(request, timeout=timeout)) as response:
        origin = response.url
        sanitize_origin(origin)
        length = response.headers.get("Content-Length")
        yield Response(
            cast(BinaryIO, response),
            origin,
            int(length) if length else None,
        )


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _fetch(
    url: str,
    destination: Path,
    maximum: int,
    config: AcquisitionConfig,
    transport: Transport,
    deadline: float,
) -> dict[str, object]:
    """Retry interrupted transfers from byte zero; never append unverified parts."""
    partial = destination.with_suffix(destination.suffix + ".part")
    for attempt in range(config.limits.attempts):
        try:
            if time.monotonic() >= deadline:
                raise AcquisitionError("Acquisition deadline exceeded")
            with transport(url, config.limits.timeout_seconds) as response:
                origin = sanitize_origin(response.url)
                if response.length is not None and not 0 < response.length <= maximum:
                    raise AcquisitionError("Response length outside configured budget")
                size = 0
                with partial.open("wb") as output:
                    while True:
                        count = min(CHUNK, maximum - size + 1)
                        # HTTPResponse.read(n) can wait to fill n bytes despite
                        # slow trickling. read1 returns after one underlying read,
                        # allowing the total deadline to be checked each time.
                        block = (
                            response.body.read1(count)
                            if isinstance(response.body, HTTPResponse)
                            else response.body.read(count)
                        )
                        if not block:
                            break
                        size += len(block)
                        if size > maximum or time.monotonic() >= deadline:
                            raise AcquisitionError("Transfer byte/time budget exceeded")
                        output.write(block)
                if not size or (
                    response.length is not None and size != response.length
                ):
                    raise OSError("Incomplete response")
            partial.replace(destination)
            return {"origin": origin, "bytes": size, "sha256": _digest(destination)}
        except (OSError, URLError, HTTPException) as error:
            if isinstance(error, HTTPError) and error.code not in {
                408,
                429,
                500,
                502,
                503,
                504,
            }:
                raise AcquisitionError(
                    f"Public source returned HTTP {error.code}"
                ) from None
            if attempt + 1 == config.limits.attempts:
                raise AcquisitionError(
                    "Transfer failed after bounded retries"
                ) from None
            time.sleep(min(2**attempt, 4))
        finally:
            partial.unlink(missing_ok=True)
    raise AcquisitionError("Transfer did not complete")


def _read_json(path: Path) -> dict[str, object]:
    try:
        return _object(cast(object, json.loads(_metadata_bytes(path))))
    except (UnicodeError, json.JSONDecodeError):
        raise AcquisitionError("Invalid JSON metadata") from None


def _metadata_bytes(path: Path) -> bytes:
    with path.open("rb") as stream:
        payload = stream.read(METADATA_LIMIT + 1)
    if len(payload) > METADATA_LIMIT:
        raise AcquisitionError("Metadata exceeds 2 MiB budget")
    return payload


def _check_inventory(root: Path, expected: set[str]) -> None:
    """Fail at the first unexpected entry; never materialize an arbitrary tree."""
    directories = {
        parent.as_posix()
        for name in expected
        for parent in Path(name).parents
        if parent != Path(".")
    }
    pending = [root]
    seen: set[str] = set()
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if entry.is_symlink():
                    raise AcquisitionError("Symlink in file inventory")
                if entry.is_dir(follow_symlinks=False) and relative in directories:
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False) and relative in expected:
                    seen.add(relative)
                else:
                    raise AcquisitionError("Unexpected bundle file inventory")
    if seen != expected:
        raise AcquisitionError("Missing bundle file inventory")


def _verify_file(path: Path, digest: object, size: object = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise AcquisitionError("Missing or unsafe bundle file")
    if size is not None and path.stat().st_size != size:
        raise AcquisitionError("Bundle content size mismatch")
    if _digest(path) != digest:
        raise AcquisitionError("Bundle content digest mismatch")


def _bound_zip_directory(archive: Path, member_count: int) -> None:
    # Read only the bounded end record/comment before ZipFile allocates its
    # central-directory objects. GUIDE v1 needs neither multipart nor ZIP64 EOCD.
    with archive.open("rb") as stream:
        stream.seek(max(0, archive.stat().st_size - 65557))
        tail = stream.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise AcquisitionError("Missing ZIP end record")
    _, disk, directory_disk, disk_count, total, size, _, comment = struct.unpack_from(
        "<4s4H2LH", tail, offset
    )
    if (
        disk != 0
        or directory_disk != 0
        or disk_count != total
        or total != member_count
        or size > ZIP_DIRECTORY_LIMIT
        or len(tail) != offset + 22 + comment
        or tail[max(0, offset - 20) : offset - 16] == b"PK\x06\x07"
    ):
        raise AcquisitionError("ZIP directory count/size outside supported bounds")


def _verify_source(
    metadata: dict[str, object],
    inventory: dict[str, object],
    config: AcquisitionConfig,
) -> dict[str, object]:
    if (
        _text(metadata.get("ref")).casefold() != DATASET
        or metadata.get("id") != 5371198
        or metadata.get("ownerName") != "Microsoft"
        or metadata.get("ownerRef") not in {"Microsoft", "organizations/Microsoft"}
    ):
        raise AcquisitionError("Publisher/dataset identity mismatch")
    releases = [_object(v) for v in _list(metadata.get("versions"))]
    matches = [v for v in releases if v.get("versionNumber") == config.version]
    if len(matches) != 1:
        raise AcquisitionError("Pinned release absent or ambiguous")
    release = matches[0]
    if (
        release.get("creationDate") != config.created_at
        or release.get("status") != "Ready"
    ):
        raise AcquisitionError("Pinned release identity/status changed")
    description = _text(metadata.get("description"))
    # Only the publisher's explicit license statement establishes dataset terms;
    # the generic Kaggle license dropdown does not.
    license_section = description.rsplit("# License", 1)
    if (
        len(license_section) != 2
        or LICENSE_PAGE not in license_section[1]
        or LICENSE not in license_section[1]
    ):
        raise AcquisitionError("Publisher license evidence missing or changed")
    if inventory.get("errorMessage") or inventory.get("nextPageToken"):
        raise AcquisitionError(
            "Incomplete/failed upstream inventory; review pagination"
        )
    files = [_object(f) for f in _list(inventory.get("datasetFiles"))]
    actual = [
        FileSpec(_filename(f.get("name")), _positive(f.get("totalBytes")))
        for f in files
    ]
    if sorted(actual, key=lambda f: f.name) != list(config.files):
        raise AcquisitionError("Release inventory differs from pinned configuration")
    return release


def extract_archive(
    archive: Path,
    destination: Path,
    config: AcquisitionConfig,
    deadline: float,
) -> list[dict[str, object]]:
    """Validate the complete central directory before writing any payload."""
    expected = {f.name: f.bytes for f in config.files}
    records: list[dict[str, object]] = []
    _bound_zip_directory(archive, len(expected))
    with ZipFile(archive) as zipped:
        members = zipped.infolist()
        if len(members) != len(expected):
            raise AcquisitionError("Unexpected ZIP member count")
        names: set[str] = set()
        for member in members:
            name = _filename(member.filename)
            mode = member.external_attr >> 16
            if (
                name.casefold() in names
                or name not in expected
                or member.file_size != expected[name]
                or member.flag_bits & 1
                or (stat.S_IFMT(mode) not in (0, stat.S_IFREG))
            ):
                raise AcquisitionError("Unsafe, duplicate or unexpected ZIP member")
            names.add(name.casefold())
        if sum(m.file_size for m in members) > config.limits.expanded_bytes:
            raise AcquisitionError("ZIP expansion exceeds budget")
        destination.mkdir()
        for member in sorted(members, key=lambda m: m.filename):
            path = destination / member.filename
            size = 0
            digest = hashlib.sha256()
            with zipped.open(member) as stream, path.open("xb") as output:
                while block := stream.read(min(CHUNK, member.file_size - size + 1)):
                    size += len(block)
                    if size > member.file_size or time.monotonic() >= deadline:
                        raise AcquisitionError(
                            "ZIP extraction byte/time budget exceeded"
                        )
                    digest.update(block)
                    output.write(block)
            if size != member.file_size:
                raise AcquisitionError("Truncated ZIP member")
            records.append(
                {
                    "path": f"files/{member.filename}",
                    "bytes": size,
                    "sha256": digest.hexdigest(),
                }
            )
    return records


def acquire(
    config_path: Path,
    output: Path,
    *,
    transport: Transport = open_public,
    expected_archive_sha256: str | None = None,
    git_commit: str = "unknown",
    environment: str = "local",
) -> Path:
    """Create a fresh bundle atomically. Existing output is never overwritten."""
    config = read_config(config_path)
    if expected_archive_sha256 is not None and not re.fullmatch(
        r"[0-9a-f]{64}", expected_archive_sha256
    ):
        raise AcquisitionError(
            "Expected archive SHA-256 must be 64 lowercase hex characters"
        )
    if output.exists() or output.is_symlink():
        raise AcquisitionError(
            "Output already exists; verify it or choose a fresh directory"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + config.limits.total_seconds
    try:
        with TemporaryDirectory(
            prefix=".guide-acquire-", dir=output.parent
        ) as temporary:
            root = Path(temporary) / "bundle"
            evidence = root / "evidence"
            evidence.mkdir(parents=True)
            endpoints = {
                "publisher.json": f"{API}/view/{DATASET}",
                "inventory.json": f"{API}/list/{DATASET}?datasetVersionNumber={config.version}",
                "LICENSE.txt": LICENSE_TEXT,
            }
            evidence_records: dict[str, object] = {}
            for name, url in endpoints.items():
                evidence_records[name] = {
                    "request": url,
                    "path": f"evidence/{name}",
                    **_fetch(
                        url,
                        evidence / name,
                        config.limits.metadata_bytes,
                        config,
                        transport,
                        deadline,
                    ),
                }
            release = _verify_source(
                _read_json(evidence / "publisher.json"),
                _read_json(evidence / "inventory.json"),
                config,
            )
            if _digest(evidence / "LICENSE.txt") != config.license_sha256:
                raise AcquisitionError(
                    "License agreement digest differs from reviewed text"
                )
            url = f"{API}/download/{DATASET}?datasetVersionNumber={config.version}"
            archive_record = {
                "path": "archive.zip",
                "request": url,
                **_fetch(
                    url,
                    root / "archive.zip",
                    config.limits.archive_bytes,
                    config,
                    transport,
                    deadline,
                ),
            }
            if (
                expected_archive_sha256 is not None
                and archive_record["sha256"] != expected_archive_sha256
            ):
                raise AcquisitionError("Archive SHA-256 differs from expected digest")
            files = extract_archive(
                root / "archive.zip", root / "files", config, deadline
            )
            (evidence / "config.toml").write_bytes(config_path.read_bytes())
            manifest = {
                "manifest_version": 1,
                "gate": "G1",
                "status": "ACQUIRED_G1_ONLY",
                "training_allowed": False,
                "schema_inspected": False,
                "dataset": DATASET,
                "publisher": "Microsoft",
                "source": SOURCE,
                "release": release,
                "version": config.version,
                "license": {
                    "id": LICENSE,
                    "url": LICENSE_PAGE,
                    "text": "evidence/LICENSE.txt",
                    "publisher_evidence": "evidence/publisher.json",
                },
                "acquired_at_utc": datetime.now(UTC).isoformat(),
                "git_commit": git_commit,
                "environment": environment,
                "config": {
                    "path": "evidence/config.toml",
                    "sha256": _digest(evidence / "config.toml"),
                },
                "limits": asdict(config.limits),
                "evidence": evidence_records,
                "archive": archive_record,
                "files": files,
                "expected_archive_sha256": expected_archive_sha256,
                "checksum_provenance": "Locally computed SHA-256, not publisher-signed checksums",
            }
            _write_json(root / "manifest.json", manifest)
            (root / "manifest.sha256").write_text(
                _digest(root / "manifest.json") + "\n", encoding="ascii"
            )
            root.rename(output)
    except (BadZipFile, UnicodeError, json.JSONDecodeError) as error:
        raise AcquisitionError(
            f"Invalid acquisition artifact: {type(error).__name__}"
        ) from None
    return output / "manifest.json"


def verify_bundle(root: Path) -> Path:
    """Offline rehash: no network, CSV decoding, row counting or schema access."""
    if root.is_symlink():
        raise AcquisitionError("Bundle must not be a symlink")
    manifest_path = root / "manifest.json"
    expected = _metadata_bytes(root / "manifest.sha256").decode("ascii").strip()
    if _digest(manifest_path) != expected:
        raise AcquisitionError("Manifest digest mismatch")
    manifest = _read_json(manifest_path)
    if (
        manifest.get("status") != "ACQUIRED_G1_ONLY"
        or manifest.get("training_allowed") is not False
    ):
        raise AcquisitionError("Unsupported acquisition manifest")
    records = [_object(manifest.get("archive")), _object(manifest.get("config"))]
    records.extend(_object(r) for r in _list(manifest.get("files")))
    records.extend(_object(r) for r in _object(manifest.get("evidence")).values())
    expected_paths = {"manifest.json", "manifest.sha256"}
    for record in records:
        relative = _text(record.get("path"))
        path = root / relative
        if (
            path.is_symlink()
            or not path.resolve().is_relative_to(root.resolve())
            or not path.is_file()
        ):
            raise AcquisitionError("Missing or unsafe bundle file")
        _verify_file(path, record.get("sha256"), record.get("bytes"))
        expected_paths.add(relative)
    _check_inventory(root, expected_paths)
    return manifest_path


def verify_files(root: Path, lock_path: Path) -> dict[str, object]:
    """Verify read-only mounted/local payloads against a trusted repository lock.

    No archive, original manifest, network, copying or writes to the mount are
    required. The caller must trust the reviewed lock independently of the data.
    """
    lock = _read_json(lock_path)
    if (
        lock.get("lock_version") != 1
        or lock.get("dataset") != DATASET
        or lock.get("publisher") != "Microsoft"
        or lock.get("source") != SOURCE
        or lock.get("license") != LICENSE
        or lock.get("checksum_provenance") != "locally_generated_sha256"
        or lock.get("publisher_hashes") is not None
        or "publisher_hashes" not in lock
    ):
        raise AcquisitionError("Unsupported release-lock identity or hash provenance")
    version = _positive(lock.get("version"))
    _text(lock.get("release_created_at"))
    _text(lock.get("acquired_at_utc"))
    manifest_digest = _text(lock.get("acquisition_manifest_sha256"))
    archive = _object(lock.get("archive"))
    _positive(archive.get("bytes"))
    records = [_object(item) for item in _list(lock.get("files"))]
    names = [_filename(record.get("name")) for record in records]
    if not names or len(set(n.casefold() for n in names)) != len(names):
        raise AcquisitionError("Empty or duplicate release-lock inventory")
    for digest in [
        manifest_digest,
        archive.get("sha256"),
        *(r.get("sha256") for r in records),
    ]:
        if not re.fullmatch(r"[0-9a-f]{64}", _text(digest)):
            raise AcquisitionError("Invalid pinned SHA-256")
    for record in records:
        _positive(record.get("bytes"))
    # Resolve the caller-selected root once; all release members are flat names.
    root = root.resolve(strict=True)
    _check_inventory(root, set(names))
    for name, record in zip(names, records, strict=True):
        _verify_file(root / name, record["sha256"], record["bytes"])
    return {
        "status": "VERIFIED_G1_FILES_ONLY",
        "training_allowed": False,
        "schema_inspected": False,
        "dataset": DATASET,
        "version": version,
        "checksum_provenance": lock["checksum_provenance"],
        "publisher_hashes": None,
        "release_lock_sha256": _digest(lock_path),
        "acquisition_manifest_sha256": manifest_digest,
        "files": records,
    }
