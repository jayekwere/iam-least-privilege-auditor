import socket
from collections.abc import Iterator

import pytest

from iam_auditor.demo import demo_snapshot
from iam_auditor.models import Snapshot


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


@pytest.fixture(scope="module")
def environment() -> Iterator[Snapshot]:
    yield demo_snapshot()


@pytest.fixture
def snapshot(environment: Snapshot) -> Snapshot:
    return environment.model_copy(deep=True)
