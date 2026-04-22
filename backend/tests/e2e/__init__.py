"""
End-to-end test suite for Sentry.

Each test maps to a row in `ops/E2E_TEST_CATALOG.md` via a Test-ID embedded
in the docstring (e.g. "E2E FN-04: ..."). Tests that depend on features
that have not yet landed are marked `@pytest.mark.xfail(strict=True,
reason="Pending Pxx.y")` so the first green run of each test is a proof
point for the corresponding phase of `implementation_plan.md`.

Gated by the `SENTRY_E2E=1` environment variable for CI so these can
take longer than unit tests without slowing the normal dev loop.
"""
