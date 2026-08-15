"""Global test safeguards."""

from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def forbid_network_access(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests cannot accidentally call the live LeakCheck API or any other network host."""

    def blocked_connect(self: socket.socket, address: object) -> None:
        msg = f"network access is disabled in tests (attempted {address!r})"
        raise AssertionError(msg)

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
