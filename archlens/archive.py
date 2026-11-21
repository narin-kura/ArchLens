"""Safe extraction of uploaded archives (.zip, .tgz, .tar.gz, .tar).

A Helm chart is a folder, usually shared as a .tgz from `helm package`, and a
set of Kubernetes manifests or Terraform files is easiest to upload as one
archive. Uploaded archives are untrusted, so extraction refuses anything that
could write outside the target folder (absolute paths, `..`, links, devices)
and caps file count and total size against archive bombs.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ARCHIVE_SUFFIXES = (".zip", ".tgz", ".tar.gz", ".tar")

MAX_MEMBERS = 2000
MAX_TOTAL_BYTES = 25 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
_CHUNK = 64 * 1024


class ArchiveError(ValueError):
    """Raised for archives ArchLens will not extract; the message is shown to the user."""


def is_archive(filename: str) -> bool:
    return filename.lower().endswith(ARCHIVE_SUFFIXES)


def _safe_relpath(name: str) -> PurePosixPath | None:
    """Return a safe relative path for an archive member, or None to skip it."""
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    if path.is_absolute() or name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise ArchiveError(f"Archive contains an absolute path: {name}")
    parts = [p for p in path.parts if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ArchiveError(f"Archive contains a path that leaves its folder: {name}")
    if not parts or parts[0] == "__MACOSX":
        return None
    return PurePosixPath(*parts)


class _Budget:
    def __init__(self) -> None:
        self.members = 0
        self.total = 0

    def member(self) -> None:
        self.members += 1
        if self.members > MAX_MEMBERS:
            raise ArchiveError(f"Archive has more than {MAX_MEMBERS} files.")

    def copy(self, src, dest: Path) -> None:
        written = 0
        with open(dest, "wb") as out:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                self.total += len(chunk)
                if written > MAX_FILE_BYTES:
                    raise ArchiveError(f"A file in the archive is larger than {MAX_FILE_BYTES // 1024 // 1024} MB.")
                if self.total > MAX_TOTAL_BYTES:
                    raise ArchiveError(
                        f"Archive expands to more than {MAX_TOTAL_BYTES // 1024 // 1024} MB.")
                out.write(chunk)


def _write(dest_root: Path, rel: PurePosixPath, src, budget: _Budget) -> None:
    target = dest_root.joinpath(*rel.parts)
    # Belt and braces: the resolved target must stay inside dest_root.
    if dest_root.resolve() not in target.resolve().parents:
        raise ArchiveError(f"Archive contains a path that leaves its folder: {rel}")
    target.parent.mkdir(parents=True, exist_ok=True)
    budget.copy(src, target)


def extract_archive(data: bytes, filename: str, dest: Path) -> Path:
    """Extract `data` into `dest` and return the folder to analyse."""
    dest.mkdir(parents=True, exist_ok=True)
    budget = _Budget()
    lower = filename.lower()
    try:
        if lower.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    budget.member()
                    if info.is_dir():
                        continue
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode and mode != 0o100000:
                        # Symlinks and special files are skipped, never followed.
                        continue
                    rel = _safe_relpath(info.filename)
                    if rel is None:
                        continue
                    with zf.open(info) as src:
                        _write(dest, rel, src, budget)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                for member in tf:
                    budget.member()
                    if not member.isfile():
                        continue   # directories, links, devices, fifos
                    rel = _safe_relpath(member.name)
                    if rel is None:
                        continue
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    with src:
                        _write(dest, rel, src, budget)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError(f"Could not read the archive: {exc}") from exc
    return analysis_root(dest)


def analysis_root(dest: Path) -> Path:
    """The chart folder if the archive holds a Helm chart (ignoring subcharts
    under charts/), else the single top-level folder, else `dest` itself."""
    charts = [p.parent for p in dest.rglob("Chart.y*ml")
              if p.name in ("Chart.yaml", "Chart.yml") and "charts" not in p.relative_to(dest).parts[:-2]]
    if charts:
        return min(charts, key=lambda p: len(p.relative_to(dest).parts))
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest
