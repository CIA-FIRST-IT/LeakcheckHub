"""Create the initial local super-admin without ever accepting a password as an argument."""

from __future__ import annotations

import argparse
import asyncio
import getpass
from collections.abc import Sequence

from app.auth.local import (
    CreatedSuperAdmin,
    LocalAuthenticationError,
    SuperAdminAlreadyExistsError,
    create_superadmin,
)
from app.config import get_settings
from app.db import get_async_session_factory


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the non-secret command interface; the password is always prompted interactively."""

    parser = argparse.ArgumentParser(
        prog="create-superadmin",
        description="Create a password-only local super-admin. MFA is enrolled after sign-in.",
    )
    parser.add_argument("--email", help="super-admin account email (prompted when omitted)")
    parser.add_argument("--display-name", help="super-admin display name (prompted when omitted)")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Prompt safely and create the password-only account transactionally."""

    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    try:
        email = arguments.email or input("Email: ")
        display_name = arguments.display_name or input("Display name: ")
        password = getpass.getpass("Password (15+ characters): ")
        confirmation = getpass.getpass("Confirm password: ")
    except (EOFError, KeyboardInterrupt):
        parser.exit(1, "\nSuper-admin creation cancelled.\n")
    if password != confirmation:
        parser.exit(1, "Passwords did not match; no account was created.\n")

    try:
        created = asyncio.run(_create(email=email, display_name=display_name, password=password))
    except LocalAuthenticationError:
        parser.exit(1, "Invalid account details or password; no account was created.\n")
    except SuperAdminAlreadyExistsError:
        parser.exit(1, "An account with that email already exists; no account was changed.\n")

    print(f"Created super-admin account for {created.user.email}.")
    print("Sign in with the password, then enroll MFA from Account security.")


async def _create(*, email: str, display_name: str, password: str) -> CreatedSuperAdmin:
    """Run creation in its own transaction for the standalone operator command."""

    settings = get_settings()
    session_factory = get_async_session_factory()
    async with session_factory() as db:
        try:
            created = await create_superadmin(
                db,
                settings=settings,
                email=email,
                display_name=display_name,
                password=password,
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise
    return created


if __name__ == "__main__":
    main()
