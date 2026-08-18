"""Persistent first-launch bootstrap secret tests."""

from __future__ import annotations

import stat
from pathlib import Path

from app.bootstrap_secrets import (
    _migration_environment,
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

    bootstrap = _migration_environment("bootstrap", tmp_path)
    assert values["postgres_password"] in bootstrap["LC_MIGRATION_DATABASE_URL"]
    assert bootstrap["LC_MIGRATOR_DB_PASSWORD"] == values["migrator_password"]
    assert bootstrap["LC_RUNTIME_DB_PASSWORD"] == values["runtime_password"]

    migrate = _migration_environment("migrate", tmp_path)
    assert values["migrator_password"] in migrate["LC_MIGRATION_DATABASE_URL"]
