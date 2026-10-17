from __future__ import annotations

import hashlib
import io
import json
import stat
import struct
import tracemalloc
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

from amyntor.data.acquire_guide import main
from amyntor.data.acquisition import (
    API,
    DATASET,
    LICENSE_TEXT,
    METADATA_LIMIT,
    SOURCE,
    AcquisitionConfig,
    AcquisitionError,
    Response,
    acquire,
    extract_archive,
    read_config,
    sanitize_origin,
    verify_bundle,
    verify_files,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        pytest.fail("Acquisition tests must never access the network")

    monkeypatch.setattr("socket.socket.connect", blocked)

    def no_wait(seconds: float) -> None:
        pass

    monkeypatch.setattr("amyntor.data.acquisition.time.sleep", no_wait)


def make_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


class FakeSource:
    """Synthetic artifacts; deliberately no valid CSV/schema payload."""

    def __init__(self) -> None:
        self.payload = b"\xff\x00inert opaque artifact\n"
        self.archive = make_zip({"sample.bin": self.payload})
        self.metadata: dict[str, object] = {
            "id": 5371198,
            "ref": DATASET,
            "ownerName": "Microsoft",
            "ownerRef": "Microsoft",
            "description": "# License\nCDLA-Permissive-2.0 https://cdla.dev/permissive-2-0/",
            "versions": [
                {"versionNumber": 1, "creationDate": "release-time", "status": "Ready"}
            ],
        }
        self.inventory: dict[str, object] = {
            "datasetFiles": [{"name": "sample.bin", "totalBytes": len(self.payload)}],
            "nextPageToken": "",
            "errorMessage": "",
        }
        self.calls: list[str] = []
        self.failures = 0
        self.truncate = False
        self.length: int | None = None

    @contextmanager
    def open(self, url: str, timeout: int) -> Generator[Response]:
        assert timeout > 0
        self.calls.append(url)
        if "/download/" in url:
            if self.failures:
                self.failures -= 1
                raise OSError("interrupted transfer")
            body = self.archive[:-4] if self.truncate else self.archive
            origin = (
                "https://storage.googleapis.com/public/archive.zip?secret=do-not-store"
            )
            length = self.length if self.length is not None else len(self.archive)
        elif "/view/" in url:
            body, origin = json.dumps(self.metadata).encode(), url
            length = len(body)
        elif "/list/" in url:
            body, origin = json.dumps(self.inventory).encode(), url
            length = len(body)
        else:
            assert url == LICENSE_TEXT
            body = b"Community Data License Agreement 2.0\n2.1. Sharing\n3.1. Results\n"
            origin, length = url, len(body)
        with io.BytesIO(body) as stream:
            yield Response(stream, origin, length)


@pytest.fixture
def source() -> FakeSource:
    return FakeSource()


@pytest.fixture
def config(tmp_path: Path, source: FakeSource) -> Path:
    path = tmp_path / "source.toml"
    license_hash = hashlib.sha256(
        b"Community Data License Agreement 2.0\n2.1. Sharing\n3.1. Results\n"
    ).hexdigest()
    path.write_text(
        '[source]\nversion=1\ncreated_at="release-time"\n'
        f'license_sha256="{license_hash}"\n'
        "[limits]\narchive_bytes=2048\nexpanded_bytes=2048\nmetadata_bytes=2048\n"
        "timeout_seconds=1\ntotal_seconds=30\nattempts=2\n"
        f'[[files]]\nname="sample.bin"\nbytes={len(source.payload)}\n',
        encoding="utf-8",
    )
    return path


def test_acquire_and_rehash_opaque_bytes(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    root = tmp_path / "bundle"
    manifest = acquire(config, root, transport=source.open, git_commit="test-commit")
    assert verify_bundle(root) == manifest
    text = manifest.read_text(encoding="utf-8")
    assert '"training_allowed": false' in text
    assert '"schema_inspected": false' in text
    assert '"status": "ACQUIRED_G1_ONLY"' in text
    assert hashlib.sha256(source.payload).hexdigest() in text
    assert "secret" not in text and str(tmp_path) not in text
    assert (root / "files/sample.bin").read_bytes() == source.payload
    assert f"{API}/download/{DATASET}?datasetVersionNumber=1" in source.calls


def test_relocated_repeated_acquisition_has_same_identity(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    roots = [tmp_path / "first", tmp_path / "elsewhere" / "second"]
    for root in roots:
        acquire(config, root, transport=source.open)
        verify_bundle(root)
    for relative in ["files/sample.bin", "archive.zip", "evidence/config.toml"]:
        assert (roots[0] / relative).read_bytes() == (roots[1] / relative).read_bytes()
    assert source.calls.count(f"{API}/download/{DATASET}?datasetVersionNumber=1") == 2


@pytest.mark.parametrize(
    "change", ["publisher", "version", "license", "inventory", "pagination"]
)
def test_provenance_failure_prevents_download(
    change: str, config: Path, source: FakeSource, tmp_path: Path
) -> None:
    if change == "publisher":
        source.metadata["ownerName"] = "mirror"
    elif change == "version":
        source.metadata["versions"] = []
    elif change == "license":
        source.metadata["description"] = "Other (specified in description)"
    elif change == "pagination":
        source.inventory["nextPageToken"] = "unread-page"
    else:
        source.inventory["datasetFiles"] = []
    with pytest.raises(AcquisitionError):
        acquire(config, tmp_path / "bad", transport=source.open)
    assert not any("/download/" in call for call in source.calls)
    assert not (tmp_path / "bad").exists()


def test_bounded_retry_restarts_transfer(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    source.failures = 1
    acquire(config, tmp_path / "good", transport=source.open)
    assert sum("/download/" in call for call in source.calls) == 2
    assert not list(tmp_path.rglob("*.part"))


@pytest.mark.parametrize(
    "failure", ["truncate", "size", "digest", "corrupt", "exhaust"]
)
def test_no_partial_bundle_on_failure(
    failure: str, config: Path, source: FakeSource, tmp_path: Path
) -> None:
    if failure == "truncate":
        source.truncate = True
    elif failure == "size":
        source.length = 9999
    elif failure == "corrupt":
        source.archive = b"not a zip archive"
    elif failure == "exhaust":
        source.failures = 100
    with pytest.raises(AcquisitionError):
        acquire(
            config,
            tmp_path / "bad",
            transport=source.open,
            expected_archive_sha256="0" * 64 if failure == "digest" else None,
        )
    assert not (tmp_path / "bad").exists()
    assert not list(tmp_path.glob(".guide-acquire-*"))
    assert sum("/download/" in call for call in source.calls) <= 2


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "C:drive", "dir\\file", "CON", "sample.bin."]
)
def test_unsafe_zip_names(config: Path, tmp_path: Path, name: str) -> None:
    archive = tmp_path / "unsafe.zip"
    archive.write_bytes(make_zip({name: b"opaque"}))
    with pytest.raises(AcquisitionError):
        extract_archive(archive, tmp_path / "files", read_config(config), float("inf"))
    assert not (tmp_path / "files").exists()


def test_zip_symlink_and_expansion_budget(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    archive = tmp_path / "bad.zip"
    info = ZipInfo("sample.bin")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(archive, "w") as zipped:
        zipped.writestr(info, source.payload)
    with pytest.raises(AcquisitionError):
        extract_archive(archive, tmp_path / "links", read_config(config), float("inf"))
    archive.write_bytes(source.archive)
    normal = read_config(config)
    small: AcquisitionConfig = replace(
        normal, limits=replace(normal.limits, expanded_bytes=1)
    )
    with pytest.raises(AcquisitionError, match="expansion"):
        extract_archive(archive, tmp_path / "large", small, float("inf"))


@pytest.mark.parametrize("mutation", ["data", "manifest", "extra", "missing"])
def test_offline_verify_rejects_tampering(
    mutation: str, config: Path, source: FakeSource, tmp_path: Path
) -> None:
    root = tmp_path / "bundle"
    acquire(config, root, transport=source.open)
    if mutation == "data":
        (root / "files/sample.bin").write_bytes(b"changed")
    elif mutation == "manifest":
        (root / "manifest.json").write_text("{}")
    elif mutation == "missing":
        (root / "files/sample.bin").unlink()
    else:
        (root / "files/extra").write_bytes(b"new")
    with pytest.raises(AcquisitionError):
        verify_bundle(root)


def test_existing_bundle_not_overwritten(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    root = tmp_path / "bundle"
    acquire(config, root, transport=source.open)
    calls = len(source.calls)
    with pytest.raises(AcquisitionError, match="already exists"):
        acquire(config, root, transport=source.open)
    assert len(source.calls) == calls


@pytest.mark.parametrize(
    "url",
    [
        "http://www.kaggle.com/path",
        "https://evil.example/file",
        "https://user:pass@www.kaggle.com/path",
    ],
)
def test_redirect_origin_restrictions(url: str) -> None:
    with pytest.raises(AcquisitionError):
        sanitize_origin(url)


def test_cli_offline_verify(config: Path, source: FakeSource, tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    acquire(config, root, transport=source.open)
    assert main(["verify", "--bundle", str(root)]) == 0
    (root / "manifest.json").write_text("{}")
    assert main(["verify", "--bundle", str(root)]) == 1


def test_missing_license_pin_blocks_before_network(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    lines = config.read_text(encoding="utf-8").splitlines()
    config.write_text(
        "\n".join(line for line in lines if not line.startswith("license_sha256")),
        encoding="utf-8",
    )
    with pytest.raises(AcquisitionError):
        acquire(config, tmp_path / "bad", transport=source.open)
    assert not source.calls


def test_changed_license_text_blocks_archive(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    text = config.read_text(encoding="utf-8")
    text = text.replace(read_config(config).license_sha256, "0" * 64)
    config.write_text(text, encoding="utf-8")
    with pytest.raises(AcquisitionError, match="License agreement digest"):
        acquire(config, tmp_path / "bad", transport=source.open)
    assert not any("/download/" in url for url in source.calls)


def test_unknown_length_stream_still_has_byte_limit(
    config: Path, source: FakeSource, tmp_path: Path
) -> None:
    @contextmanager
    def unbounded(url: str, timeout: int) -> Generator[Response]:
        if "/download/" in url:
            with io.BytesIO(b"x" * 4096) as body:
                yield Response(body, url, None)
        else:
            with source.open(url, timeout) as response:
                yield response

    with pytest.raises(AcquisitionError, match="budget"):
        acquire(config, tmp_path / "bad", transport=unbounded)
    assert not (tmp_path / "bad").exists()


def test_total_deadline_blocks_before_network(
    config: Path, source: FakeSource, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter([0.0, 31.0])

    def elapsed() -> float:
        return next(ticks)

    monkeypatch.setattr("amyntor.data.acquisition.time.monotonic", elapsed)
    with pytest.raises(AcquisitionError, match="deadline"):
        acquire(config, tmp_path / "bad", transport=source.open)
    assert not source.calls


@pytest.mark.parametrize("mutation", ["wrong_size", "extra", "crc"])
def test_damaged_zip_is_never_published(
    mutation: str, config: Path, source: FakeSource, tmp_path: Path
) -> None:
    if mutation == "wrong_size":
        source.archive = make_zip({"sample.bin": b"wrong length"})
    elif mutation == "extra":
        source.archive = make_zip(
            {"sample.bin": source.payload, "extra": b"unexpected"}
        )
    else:
        # Change the local-header payload of a stored ZIP, leaving its CRC intact.
        buffer = io.BytesIO()
        with ZipFile(buffer, "w") as zipped:
            zipped.writestr("sample.bin", source.payload)
        source.archive = buffer.getvalue().replace(
            source.payload, b"x" * len(source.payload)
        )
    with pytest.raises(AcquisitionError):
        acquire(config, tmp_path / "bad", transport=source.open)
    assert not (tmp_path / "bad").exists()


@pytest.fixture
def mounted_files(tmp_path: Path, source: FakeSource) -> tuple[Path, Path]:
    root = tmp_path / "read-only-mount"
    root.mkdir()
    (root / "sample.bin").write_bytes(source.payload)
    lock = tmp_path / "trusted-repository" / "release.lock.json"
    lock.parent.mkdir()
    lock.write_text(
        json.dumps(
            {
                "lock_version": 1,
                "dataset": DATASET,
                "publisher": "Microsoft",
                "source": SOURCE,
                "version": 1,
                "release_created_at": "fixture-release",
                "license": "CDLA-Permissive-2.0",
                "checksum_provenance": "locally_generated_sha256",
                "publisher_hashes": None,
                "acquired_at_utc": "fixture-acquisition",
                "acquisition_manifest_sha256": "1" * 64,
                "archive": {
                    "bytes": len(source.archive),
                    "sha256": hashlib.sha256(source.archive).hexdigest(),
                },
                "files": [
                    {
                        "name": "sample.bin",
                        "bytes": len(source.payload),
                        "sha256": hashlib.sha256(source.payload).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return root, lock


def test_mounted_verification_needs_no_bundle_or_writes(
    mounted_files: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, lock = mounted_files
    # No original bundle, manifest, archive or evidence directory exists.
    before = (root / "sample.bin").read_bytes()

    def forbid_copy(*args: object, **kwargs: object) -> None:
        pytest.fail("Mounted verification must never create or copy files")

    monkeypatch.setattr(Path, "write_bytes", forbid_copy)
    monkeypatch.setattr(Path, "write_text", forbid_copy)
    monkeypatch.setattr(Path, "mkdir", forbid_copy)
    report = verify_files(root, lock)
    assert report["status"] == "VERIFIED_G1_FILES_ONLY"
    assert report["training_allowed"] is False and report["schema_inspected"] is False
    assert report["publisher_hashes"] is None
    assert report["checksum_provenance"] == "locally_generated_sha256"
    assert str(tmp_path) not in json.dumps(report)
    assert (root / "sample.bin").read_bytes() == before
    assert sorted(p.name for p in root.iterdir()) == ["sample.bin"]


def test_same_core_verifies_local_and_relocated_mount(
    mounted_files: tuple[Path, Path], tmp_path: Path
) -> None:
    root, lock = mounted_files
    original = verify_files(root, lock)
    relocated = tmp_path / "another-environment" / "mounted-artifacts"
    relocated.parent.mkdir()
    root.rename(relocated)
    assert verify_files(relocated, lock) == original


@pytest.mark.parametrize("mutation", ["hash", "size", "missing", "extra", "directory"])
def test_mounted_mismatch_rejected(
    mutation: str, mounted_files: tuple[Path, Path], source: FakeSource
) -> None:
    root, lock = mounted_files
    if mutation == "hash":
        (root / "sample.bin").write_bytes(b"x" * len(source.payload))
    elif mutation == "size":
        (root / "sample.bin").write_bytes(b"short")
    elif mutation == "missing":
        (root / "sample.bin").unlink()
    elif mutation == "extra":
        (root / "unexpected.bin").write_bytes(b"extra")
    else:
        (root / "unexpected-directory").mkdir()
    with pytest.raises(AcquisitionError):
        verify_files(root, lock)


@pytest.mark.parametrize(
    "field,value",
    [
        ("publisher", "unverified mirror"),
        ("version", 0),
        ("checksum_provenance", "publisher_provided"),
        ("publisher_hashes", {}),
        ("acquisition_manifest_sha256", "invalid"),
        ("files", []),
    ],
)
def test_untrusted_or_malformed_lock_rejected(
    field: str, value: object, mounted_files: tuple[Path, Path]
) -> None:
    root, lock = mounted_files
    record: dict[str, object] = json.loads(lock.read_text(encoding="utf-8"))
    record[field] = value
    lock.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(AcquisitionError):
        verify_files(root, lock)


def test_cli_verifies_files_offline(
    mounted_files: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    root, lock = mounted_files
    assert main(["verify-files", "--files-root", str(root), "--lock", str(lock)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VERIFIED_G1_FILES_ONLY"
    (root / "sample.bin").unlink()
    assert main(["verify-files", "--files-root", str(root), "--lock", str(lock)]) == 1


def test_verification_metadata_has_explicit_memory_limit(
    mounted_files: tuple[Path, Path],
) -> None:
    root, lock = mounted_files
    lock.write_bytes(b" " * (METADATA_LIMIT + 1))
    with pytest.raises(AcquisitionError, match="2 MiB"):
        verify_files(root, lock)


def test_hash_memory_does_not_scale_with_payload_size(
    mounted_files: tuple[Path, Path],
) -> None:
    root, lock = mounted_files
    block = b"x" * 65536
    digest = hashlib.sha256()
    with (root / "sample.bin").open("wb") as stream:
        for _ in range(128):
            stream.write(block)
            digest.update(block)
    record: dict[str, object] = json.loads(lock.read_text(encoding="utf-8"))
    record["files"] = [
        {"name": "sample.bin", "bytes": 128 * len(block), "sha256": digest.hexdigest()}
    ]
    lock.write_text(json.dumps(record), encoding="utf-8")
    tracemalloc.start()
    try:
        verify_files(root, lock)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # Allow the 2 MiB metadata read budget plus bookkeeping; the 8 MiB
    # payload must never be loaded whole.
    assert peak < 4 * 1024 * 1024


@pytest.mark.parametrize("offset,value", [(10, 65535), (12, 65537)])
def test_zip_metadata_bounds_checked_before_parser_allocation(
    offset: int, value: int, config: Path, source: FakeSource, tmp_path: Path
) -> None:
    content = bytearray(source.archive)
    end = content.rfind(b"PK\x05\x06")
    struct.pack_into("<H" if offset == 10 else "<L", content, end + offset, value)
    archive = tmp_path / "oversized-directory.zip"
    archive.write_bytes(content)
    with pytest.raises(AcquisitionError, match="directory"):
        extract_archive(archive, tmp_path / "out", read_config(config), float("inf"))
