from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


class JsonCache:
    def __init__(self, directory: str | Path = ".breachcheck-cache") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / f"{namespace}-{digest}.json"

    def get(self, namespace: str, key: str) -> Any | None:
        path = self._path(namespace, key)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    def set(self, namespace: str, key: str, value: Any) -> None:
        path = self._path(namespace, key)
        fd, temp_name = tempfile.mkstemp(prefix=path.name, dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2)
                handle.write("\n")
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
