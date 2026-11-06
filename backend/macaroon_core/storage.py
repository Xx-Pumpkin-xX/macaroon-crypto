"""File-system storage for blobs, root keys and share bookkeeping.

Layout (``backend/storage/`` by default, git-ignored)::

    files/<file_id>/blob           encrypted blob, at most 1 MiB
    files/<file_id>/root_key       32 random bytes, mode 0600
    files/<file_id>/shares.json    {"issued": [...], "revoked": [...]}

The storage layer is shared with the teammate implementing share/revoke/
delete: it exposes the issued/revoked accessors and :meth:`delete_file`, but
the first three endpoints only read them.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterable

from . import ids
from .errors import NotFound

DEFAULT_STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage"

_BLOB_NAME = "blob"
_ROOT_KEY_NAME = "root_key"
_SHARES_NAME = "shares.json"
_FILE_MODE = 0o600
_DIR_MODE = 0o700


class FileStore:
    """Per-file state rooted in a directory."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root is not None else DEFAULT_STORAGE_DIR
        self.files_dir = self.root / "files"

    # -- creation ---------------------------------------------------------

    def create(self, blob: bytes) -> tuple[str, bytes]:
        """Store a new blob and return ``(file_id, root_key)``."""
        if not isinstance(blob, (bytes, bytearray)):
            raise TypeError("blob must be bytes")

        self._ensure_dirs()
        while True:
            file_id = ids.new_file_id()
            path = self.files_dir / file_id
            try:
                path.mkdir(mode=_DIR_MODE)
            except FileExistsError:
                continue
            break

        root_key = ids.new_root_key()
        try:
            self._atomic_write(path / _ROOT_KEY_NAME, root_key)
            self._atomic_write(path / _BLOB_NAME, bytes(blob))
            self._write_shares(path, issued=(), revoked=())
        except BaseException:
            shutil.rmtree(path, ignore_errors=True)
            raise
        return file_id, root_key

    # -- reads ------------------------------------------------------------

    def get_blob(self, file_id: str) -> bytes:
        return self._read_file(file_id, _BLOB_NAME)

    def get_root_key(self, file_id: str) -> bytes:
        root_key = self._read_file(file_id, _ROOT_KEY_NAME)
        if len(root_key) != ids.ROOT_KEY_BYTES:
            raise RuntimeError("stored root key is corrupted")
        return root_key

    def exists(self, file_id: str) -> bool:
        return ids.is_valid_file_id(file_id) and (
            self.files_dir / file_id
        ).is_dir()

    # -- writes -----------------------------------------------------------

    def replace_blob(self, file_id: str, blob: bytes) -> None:
        if not isinstance(blob, (bytes, bytearray)):
            raise TypeError("blob must be bytes")
        path = self._dir_for(file_id)
        self._atomic_write(path / _BLOB_NAME, bytes(blob))

    def delete_file(self, file_id: str) -> None:
        path = self._dir_for(file_id)
        shutil.rmtree(path)

    # -- share bookkeeping (used by the share/revoke endpoints) -----------

    def get_issued_share_ids(self, file_id: str) -> frozenset[str]:
        return frozenset(self._read_shares(file_id)["issued"])

    def get_revoked_share_ids(self, file_id: str) -> frozenset[str]:
        return frozenset(self._read_shares(file_id)["revoked"])

    def is_share_issued(self, file_id: str, share_id: str) -> bool:
        return share_id in self._read_shares(file_id)["issued"]

    def add_issued_share_id(self, file_id: str, share_id: str) -> None:
        if not ids.is_valid_share_id(share_id):
            raise ValueError(f"invalid share_id: {share_id!r}")
        path = self._dir_for(file_id)
        shares = self._read_shares_path(path)
        shares["issued"].add(share_id)
        self._write_shares(path, shares["issued"], shares["revoked"])

    def revoke_share_id(self, file_id: str, share_id: str) -> None:
        if not ids.is_valid_share_id(share_id):
            raise ValueError(f"invalid share_id: {share_id!r}")
        path = self._dir_for(file_id)
        shares = self._read_shares_path(path)
        shares["revoked"].add(share_id)
        self._write_shares(path, shares["issued"], shares["revoked"])

    # -- internals --------------------------------------------------------

    def _ensure_dirs(self) -> None:
        for path in (self.root, self.files_dir):
            path.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            try:
                os.chmod(path, _DIR_MODE)
            except OSError:
                pass

    def _dir_for(self, file_id: str) -> Path:
        if not ids.is_valid_file_id(file_id):
            raise NotFound()
        path = self.files_dir / file_id
        if not path.is_dir():
            raise NotFound()
        return path

    def _read_file(self, file_id: str, name: str) -> bytes:
        path = self._dir_for(file_id) / name
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise NotFound() from exc

    def _read_shares(self, file_id: str) -> dict[str, set[str]]:
        return self._read_shares_path(self._dir_for(file_id))

    def _read_shares_path(self, path: Path) -> dict[str, set[str]]:
        try:
            raw = (path / _SHARES_NAME).read_text(encoding="utf-8")
        except FileNotFoundError:
            return {"issued": set(), "revoked": set()}

        data = json.loads(raw)
        if not isinstance(data, dict):
            raise RuntimeError("shares.json is corrupted")
        return {
            "issued": _clean_share_ids(data.get("issued", [])),
            "revoked": _clean_share_ids(data.get("revoked", [])),
        }

    def _write_shares(
        self,
        path: Path,
        issued: Iterable[str],
        revoked: Iterable[str],
    ) -> None:
        payload = {
            "issued": sorted(set(issued)),
            "revoked": sorted(set(revoked)),
        }
        encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        self._atomic_write(path / _SHARES_NAME, encoded.encode("utf-8"))

    @staticmethod
    def _atomic_write(path: Path, data: bytes, mode: int = _FILE_MODE) -> None:
        fd, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, mode)
            os.replace(temp_name, path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise


def _clean_share_ids(values: object) -> set[str]:
    if not isinstance(values, list):
        raise RuntimeError("shares.json is corrupted")
    return {value for value in values if ids.is_valid_share_id(value)}


__all__ = ["DEFAULT_STORAGE_DIR", "FileStore"]
