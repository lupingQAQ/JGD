"""Task 7: static-only security checks (no target execution)."""
import zipfile
from pathlib import Path

import pytest

from jgd.security.archive import ArchiveError, SafeJar


def test_zip_bomb_rejected_before_parse(tmp_path: Path):
    p = tmp_path / "bomb.jar"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a/B.class", b"\0" * 5_000_000)
    with pytest.raises(ArchiveError):
        with SafeJar(p):
            pass
