"""
Docker-exec harness for P0.2 container-hardening E2E tests.

Tests in `test_security.py::SEC-35..38` need to prove properties of the
live `sentry-backend` container — that `/var/run/docker.sock` isn't
mounted, the process runs as non-root, capabilities are dropped, and
`${SERVICE_HOST_PATH}` is mounted read-only. The only way to prove that
is to shell into the running container and inspect it.

This harness deliberately avoids importing `docker` (the Python SDK) so
no additional dependency is required. It shells out to the `docker` CLI
which is the minimum viable dependency for an operator running Sentry.

Usage pattern in a test:

    from backend.tests.e2e.docker_exec import exec_in_backend, require_running_backend

    require_running_backend()        # skips the test if container is down
    out = exec_in_backend("whoami")
    assert out.stdout.strip() == "sentry"

Both test and CI entrypoints should first:

    docker compose up -d --build

so the container is live. The harness then runs `docker exec sentry-backend …`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

import pytest


CONTAINER_NAME = "sentry-backend"


@dataclass(frozen=True)
class ExecResult:
    returncode: int
    stdout: str
    stderr: str


# ──────────────────────────────────────────────────────────────────────
# Pre-flight helpers
# ──────────────────────────────────────────────────────────────────────


def _docker_cli_available() -> bool:
    """True iff a `docker` binary is on PATH."""
    return shutil.which("docker") is not None


def _docker_daemon_reachable() -> bool:
    """True iff `docker info` succeeds (i.e. a daemon is running)."""
    if not _docker_cli_available():
        return False
    try:
        # Use a short timeout — if docker daemon isn't up we shouldn't
        # stall the test suite for 30 s.
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _container_is_running(name: str = CONTAINER_NAME) -> bool:
    """True iff the named container exists and is in state 'running'."""
    if not _docker_daemon_reachable():
        return False
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0 and proc.stdout.strip() == "true"
    except (subprocess.TimeoutExpired, OSError):
        return False


def require_running_backend() -> None:
    """Skip the test if the `sentry-backend` container isn't up and running.

    Use this at the top of SEC-35..38 tests so they're safe to run
    locally without `docker compose up -d` (they become no-ops) while
    still running in CI where the container IS up.
    """
    if not _docker_cli_available():
        pytest.skip("docker CLI not installed")
    if not _docker_daemon_reachable():
        pytest.skip("docker daemon not reachable (start Docker Desktop / dockerd)")
    if not _container_is_running(CONTAINER_NAME):
        pytest.skip(
            f"{CONTAINER_NAME!r} container not running; run `docker compose up -d` first"
        )


# ──────────────────────────────────────────────────────────────────────
# The exec primitive
# ──────────────────────────────────────────────────────────────────────


def exec_in_backend(
    cmd: str | list[str],
    *,
    timeout: float = 10.0,
    expect_rc: int | None = None,
) -> ExecResult:
    """Run `cmd` inside the sentry-backend container.

    Args:
        cmd: A shell string (will be invoked with `/bin/sh -c`) or an argv list
            (exec'd directly).
        timeout: Hard timeout in seconds.
        expect_rc: If not None, raise AssertionError when the observed return
            code differs.  Use this for tests that want the expected exit
            status baked into the harness call rather than a subsequent
            assert.

    Returns:
        ExecResult with returncode, stdout, stderr.
    """
    if isinstance(cmd, str):
        argv = ["docker", "exec", CONTAINER_NAME, "/bin/sh", "-c", cmd]
    else:
        argv = ["docker", "exec", CONTAINER_NAME, *cmd]

    try:
        proc = subprocess.run(
            argv,
            capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(
            f"docker exec timed out after {timeout}s: {cmd!r}"
        ) from e

    result = ExecResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
    if expect_rc is not None and proc.returncode != expect_rc:
        raise AssertionError(
            f"docker exec {cmd!r}: expected rc={expect_rc}, "
            f"got rc={proc.returncode}\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return result


def inspect_backend(format_expr: str, *, timeout: float = 5.0) -> str:
    """Run `docker inspect -f <fmt> sentry-backend` and return stdout (stripped)."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", format_expr, CONTAINER_NAME],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"docker inspect timed out: {format_expr!r}") from e
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker inspect failed rc={proc.returncode}: {proc.stderr}"
        )
    return proc.stdout.strip()
