"""Persistent first-launch bootstrap secret tests."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.bootstrap_secrets import (
    _migration_environment,
    _run_migration,
    initialize_bootstrap_secrets,
    load_bootstrap_secrets,
    runtime_settings,
)


def test_initializer_generates_complete_read_only_secrets_once(tmp_path: Path) -> None:
    directory = tmp_path / "bootstrap"
    initialize_bootstrap_secrets(directory)
    first = load_bootstrap_secrets(directory)

    assert set(first) == {
        "postgres_password",
        "migrator_password",
        "runtime_password",
        "session_secret",
        "data_key",
    }
    assert all(len(value) >= 43 for value in first.values())
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o444 for path in directory.iterdir() if path.is_file()
    )

    initialize_bootstrap_secrets(directory)
    assert load_bootstrap_secrets(directory) == first


def test_generated_secrets_supply_runtime_and_migration_configuration(tmp_path: Path) -> None:
    initialize_bootstrap_secrets(tmp_path)
    values = load_bootstrap_secrets(tmp_path)

    runtime = runtime_settings(tmp_path)
    assert runtime["environment"] == "production"
    assert runtime["session_secret"] == values["session_secret"]
    assert runtime["data_key"] == values["data_key"]
    assert values["runtime_password"] in str(runtime["database_url"])
    assert runtime["trusted_hosts"] == ("*",)
    assert runtime["allow_unconfigured_hosts"] is True
    # The consolidated stack has no worker container, so the web process must drain the queue.
    assert runtime["run_inprocess_worker"] is True

    bootstrap = _migration_environment("bootstrap", tmp_path)
    assert values["postgres_password"] in bootstrap["LC_MIGRATION_DATABASE_URL"]
    assert bootstrap["LC_MIGRATOR_DB_PASSWORD"] == values["migrator_password"]
    assert bootstrap["LC_RUNTIME_DB_PASSWORD"] == values["runtime_password"]

    migrate = _migration_environment("migrate", tmp_path)
    assert values["migrator_password"] in migrate["LC_MIGRATION_DATABASE_URL"]


def test_migration_credentials_do_not_outlive_the_migration_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The web process runs migrations then serves; privileged passwords must not linger."""

    initialize_bootstrap_secrets(tmp_path)
    # The module reads its directory through a default argument bound at import time, so the
    # lookup itself is the seam that has to be redirected at the temporary secret set.
    monkeypatch.setattr(
        "app.bootstrap_secrets._migration_environment",
        lambda role: _migration_environment(role, tmp_path),
    )

    def explode() -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("app.bootstrap_database.main", explode)
    with pytest.raises(RuntimeError):
        _run_migration("bootstrap")

    for key in ("LC_MIGRATION_DATABASE_URL", "LC_MIGRATOR_DB_PASSWORD", "LC_RUNTIME_DB_PASSWORD"):
        assert key not in os.environ


def test_runtime_settings_keep_the_worker_off_by_default() -> None:
    """Only the bootstrap-secret stack opts in; the dev stack keeps a separate worker service."""

    from app.config import Settings

    settings = Settings(
        database_url="postgresql+asyncpg://user:password@postgres:5432/leakcheck",
        session_secret="s" * 40,
        data_key="k" * 43,
    )
    assert settings.run_inprocess_worker is False


def test_unwritable_secret_directory_reports_the_remedy(tmp_path: Path) -> None:
    """An unwritable volume must name the fix instead of failing on an opaque open()."""

    directory = tmp_path / "bootstrap"
    directory.mkdir(mode=0o555)
    try:
        with pytest.raises(RuntimeError, match="not writable"):
            initialize_bootstrap_secrets(directory)
    finally:
        directory.chmod(0o755)


def test_the_server_waits_for_a_late_database_instead_of_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A restarting or slow database must delay startup, not turn into a crash loop."""

    import app.bootstrap_secrets as module

    initialize_bootstrap_secrets(tmp_path)
    attempts = {"n": 0}

    def flaky(coro: object) -> None:
        coro.close()  # type: ignore[attr-defined]
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("Temporary failure in name resolution")

    monkeypatch.setattr("asyncio.run", flaky)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)

    module._wait_for_database(tmp_path)

    assert attempts["n"] == 3


def test_an_unreachable_database_eventually_gives_a_readable_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.bootstrap_secrets as module

    initialize_bootstrap_secrets(tmp_path)

    def always_fail(coro: object) -> None:
        coro.close()  # type: ignore[attr-defined]
        raise OSError("Temporary failure in name resolution")

    clock = iter([0.0, 0.0, 1e9, 1e9])
    monkeypatch.setattr("asyncio.run", always_fail)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))

    with pytest.raises(SystemExit, match="postgres container"):
        module._wait_for_database(tmp_path)
