"""Generate and load persistent zero-input deployment bootstrap secrets."""

from __future__ import annotations

import base64
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Final

BOOTSTRAP_SECRET_DIR: Final = Path("/run/leakcheck-bootstrap")
# Binds inside the container network namespace only; Compose publishes the port and a
# reverse proxy terminates TLS in front of it.
_BIND_HOST: Final = "0.0.0.0"  # noqa: S104  # nosec B104
_BIND_PORT: Final = 8000
_SECRET_FILES: Final = {
    "postgres_password": "postgres-password",
    "migrator_password": "migrator-password",
    "runtime_password": "runtime-password",
    "session_secret": "session-secret",
    "data_key": "data-key",
}


def _new_secret(name: str) -> str:
    if name == "data_key":
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return secrets.token_hex(32)


def _secret_path(directory: Path, name: str) -> Path:
    return directory / _SECRET_FILES[name]


def _read_secret(path: Path) -> str:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"bootstrap secret is not a regular file: {path.name}")
    value = path.read_text(encoding="ascii").strip()
    if len(value) < 32 or "\n" in value or "\r" in value:
        raise RuntimeError(f"bootstrap secret is invalid: {path.name}")
    return value


def initialize_bootstrap_secrets(directory: Path = BOOTSTRAP_SECRET_DIR) -> None:
    """Create missing secrets atomically and leave every existing value unchanged."""

    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    directory.chmod(0o755)
    for name in _SECRET_FILES:
        path = _secret_path(directory, name)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
        except FileExistsError:
            _read_secret(path)
            continue
        try:
            os.write(descriptor, (_new_secret(name) + "\n").encode("ascii"))
        finally:
            os.close(descriptor)
        path.chmod(0o444)


def load_bootstrap_secrets(directory: Path = BOOTSTRAP_SECRET_DIR) -> dict[str, str]:
    """Load a complete generated secret set, rejecting partial or malformed state."""

    return {name: _read_secret(_secret_path(directory, name)) for name in _SECRET_FILES}


def bootstrap_secrets_available(directory: Path = BOOTSTRAP_SECRET_DIR) -> bool:
    return directory.is_dir()


def runtime_settings(directory: Path = BOOTSTRAP_SECRET_DIR) -> dict[str, object]:
    values = load_bootstrap_secrets(directory)
    return {
        "environment": "production",
        "database_url": (
            "postgresql+asyncpg://leakcheck_runtime:"
            f"{values['runtime_password']}@postgres:5432/leakcheck"
        ),
        "session_secret": values["session_secret"],
        "data_key": values["data_key"],
        # The zero-input stack cannot know its public hostname before the first request. Reverse
        # proxies should enforce the public host; operators can use the standard deployment path
        # when application-level host allow-listing is required.
        "trusted_hosts": ("*",),
        "allow_unconfigured_hosts": True,
        # The consolidated stack has no separate worker container.
        "run_inprocess_worker": True,
    }


def _migration_environment(role: str, directory: Path = BOOTSTRAP_SECRET_DIR) -> dict[str, str]:
    values = load_bootstrap_secrets(directory)
    if role == "bootstrap":
        username = "postgres"
        password = values["postgres_password"]
    elif role == "migrate":
        username = "leakcheck_migrator"
        password = values["migrator_password"]
    else:
        raise RuntimeError("unknown database migration role")
    environment = {
        "LC_MIGRATION_DATABASE_URL": (
            f"postgresql+asyncpg://{username}:{password}@postgres:5432/leakcheck"
        )
    }
    if role == "bootstrap":
        environment.update(
            {
                "LC_MIGRATOR_DB_PASSWORD": values["migrator_password"],
                "LC_RUNTIME_DB_PASSWORD": values["runtime_password"],
            }
        )
    return environment


def _run_migration(role: str) -> None:
    environment = _migration_environment(role)
    os.environ.update(environment)
    try:
        if role == "bootstrap":
            from app.bootstrap_database import main as bootstrap_database

            bootstrap_database()
            return
        from alembic import command
        from alembic.config import Config

        command.upgrade(Config("alembic.ini"), "head")
    finally:
        # The web process outlives these steps; privileged database credentials must not
        # remain readable in its environment once the schema is current.
        for key in environment:
            os.environ.pop(key, None)


def _serve() -> None:
    """Bring the schema up to date, then serve the application in this same container."""

    import uvicorn

    _run_migration("bootstrap")
    _run_migration("migrate")
    uvicorn.run("app.main:create_app", factory=True, host=_BIND_HOST, port=_BIND_PORT)


def main() -> None:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action == "init":
        initialize_bootstrap_secrets()
        return
    if action in {"bootstrap", "migrate"}:
        _run_migration(action)
        return
    if action == "serve":
        _serve()
        return
    raise SystemExit("usage: python -m app.bootstrap_secrets {init|bootstrap|migrate|serve}")


if __name__ == "__main__":
    main()
