"""Conftest for keyserver plugin tests."""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--live-server",
        action="store",
        default=None,
        help="Keyserver URL for live connectivity tests",
    )


@pytest.fixture
def live_server(request):
    url = request.config.getoption("--live-server")
    if url is None:
        pytest.skip("--live-server not provided")
    return url
