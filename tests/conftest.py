import pytest

from tongsuopy.backends.tongsuo import backend as openssl_backend

from .utils import check_backend_support


def pytest_configure(config):
    pass


def pytest_report_header(config):
    return "\n".join(
        [
            "OpenSSL: {}".format(openssl_backend.openssl_version_text()),
        ]
    )


def pytest_addoption(parser):
    parser.addoption("--wycheproof-root", default=None)


def pytest_runtest_setup(item):
    pass


@pytest.fixture()
def backend(request):
    check_backend_support(openssl_backend, request)

    # Ensure the error stack is clear before the test
    errors = openssl_backend._consume_errors_with_text()
    assert not errors
    yield openssl_backend
    # Ensure the error stack is clear after the test
    errors = openssl_backend._consume_errors_with_text()
    assert not errors
