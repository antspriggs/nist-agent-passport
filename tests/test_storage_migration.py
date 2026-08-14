"""Coverage for the chained XDG-directory migration in `_storage.xdg_data_dir`.

The package was renamed twice: `nist-agent-passport` (v0.0.1-v0.1.x) →
`agent-passport` (v0.2.0, never released to PyPI) → `csp-agent-passport`
(v0.2.1+). The storage layer auto-migrates either legacy directory to the
current `csp-agent-passport` on first call so users don't lose their issuer
signing key. Tests cover: each legacy migrates independently, the newer legacy
(`agent-passport`) wins when both legacies exist, the current dir is never
clobbered, and a fresh install creates the current dir cleanly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from csp_agent_passport._storage import _DIR_NAME, _LEGACY_DIR_NAMES, xdg_data_dir


@pytest.fixture
def xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point `$XDG_DATA_HOME` at an empty temp dir for the duration of the test."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    return tmp_path


def test_v0_1_x_legacy_migrates(xdg_home: Path) -> None:
    """nist-agent-passport (v0.0.1-v0.1.x) directory rolls forward."""
    legacy = xdg_home / "nist-agent-passport"
    legacy.mkdir()
    (legacy / "issuer_signing_key.json").write_text('{"kty": "RSA"}')

    returned = xdg_data_dir()

    assert returned == xdg_home / _DIR_NAME
    assert (returned / "issuer_signing_key.json").read_text() == '{"kty": "RSA"}'
    assert not legacy.exists(), "legacy dir should be renamed away, not left behind"


def test_v0_2_0_legacy_migrates(xdg_home: Path) -> None:
    """agent-passport (v0.2.0, never released to PyPI but used by local devs)
    directory rolls forward."""
    legacy = xdg_home / "agent-passport"
    legacy.mkdir()
    (legacy / "issuer_signing_key.json").write_text('{"kty": "RSA"}')

    returned = xdg_data_dir()

    assert returned == xdg_home / _DIR_NAME
    assert (returned / "issuer_signing_key.json").read_text() == '{"kty": "RSA"}'
    assert not legacy.exists(), "legacy dir should be renamed away, not left behind"


def test_newer_legacy_wins_when_both_present(xdg_home: Path) -> None:
    """A user who has both v0.1.x and v0.2.0 dirs (e.g. manually preserved):
    take the newer (v0.2.0 → `agent-passport`) since it's chronologically later.
    The older legacy stays put."""
    older = xdg_home / "nist-agent-passport"
    older.mkdir()
    (older / "issuer_signing_key.json").write_text('{"kty": "older"}')
    newer = xdg_home / "agent-passport"
    newer.mkdir()
    (newer / "issuer_signing_key.json").write_text('{"kty": "newer"}')

    returned = xdg_data_dir()

    assert returned == xdg_home / _DIR_NAME
    assert (returned / "issuer_signing_key.json").read_text() == '{"kty": "newer"}'
    assert older.exists(), "older legacy left untouched once newer wins"


def test_current_dir_not_clobbered_when_legacy_also_exists(xdg_home: Path) -> None:
    """If `csp-agent-passport` already exists, migration must not overwrite it."""
    legacy = xdg_home / "nist-agent-passport"
    legacy.mkdir()
    (legacy / "issuer_signing_key.json").write_text('{"kty": "legacy"}')
    current = xdg_home / _DIR_NAME
    current.mkdir()
    (current / "issuer_signing_key.json").write_text('{"kty": "current"}')

    returned = xdg_data_dir()

    assert returned == current
    assert (current / "issuer_signing_key.json").read_text() == '{"kty": "current"}'
    assert legacy.exists(), "legacy must remain untouched when current already exists"


def test_fresh_install_creates_current_dir(xdg_home: Path) -> None:
    returned = xdg_data_dir()

    assert returned == xdg_home / _DIR_NAME
    assert returned.exists()
    for legacy_name in _LEGACY_DIR_NAMES:
        assert not (xdg_home / legacy_name).exists()
