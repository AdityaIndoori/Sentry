"""
SaaS auth — Cloudflare Access JWT verification.

When Sentry is deployed behind **Cloudflare Access** (Zero Trust), every
request that reaches the origin carries a signed assertion in the
``Cf-Access-Jwt-Assertion`` header (Cloudflare also sets a
``CF_Authorization`` cookie). This module verifies that JWT so the
backend can trust the caller's identity *without* running its own
password database.

How it works
------------
1. Cloudflare publishes the team's public signing keys (JWKS) at
   ``https://<team>.cloudflareaccess.com/cdn-cgi/access/certs``.
2. We fetch + cache those keys (they rotate, so we refresh on a miss /
   TTL) and verify the RS256 signature, the ``aud`` (the Access
   Application's AUD tag), and the issuer.
3. On success we read the verified ``email`` claim — that's the stable
   tenant identity.

This module is import-safe without ``PyJWT`` installed (dev machines /
CI that don't pull the full production requirements): the verifier
simply reports "unavailable" and the auth layer falls back to the
existing opaque-bearer / dev-mode behaviour.

Security notes
--------------
* We never trust the ``email`` header Cloudflare also sets
  (``Cf-Access-Authenticated-User-Email``) on its own — a misconfigured
  origin that's reachable outside the Cloudflare edge could be fed a
  forged header. We only trust the *cryptographically verified* JWT.
* ``aud`` MUST match the configured Access app, otherwise a token minted
  for a different Access app in the same team would be accepted.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Optional dependency — verification is a no-op when PyJWT isn't present.
try:  # pragma: no cover - exercised implicitly by env
    import jwt
    from jwt import PyJWKClient

    _HAS_JWT = True
except Exception:  # pragma: no cover
    jwt = None  # type: ignore[assignment]
    PyJWKClient = None  # type: ignore[assignment,misc]
    _HAS_JWT = False


# The header Cloudflare Access injects after a successful login.
CF_ACCESS_JWT_HEADER = "cf-access-jwt-assertion"

# How long to cache a constructed PyJWKClient before rebuilding it.
# PyJWKClient does its own per-key caching; this just bounds the
# lifetime of the whole client object.
_JWKS_CLIENT_TTL_SECONDS = 600.0


@dataclass
class CloudflareAccessVerifier:
    """Verifies ``Cf-Access-Jwt-Assertion`` tokens for one Access app.

    Parameters
    ----------
    team_domain:
        Either the bare team name (``myteam``) or the full host
        (``myteam.cloudflareaccess.com``). We normalize to the full host.
    audience:
        The Application Audience (AUD) tag of the Access application.
    """

    team_domain: str
    audience: str
    _client: Any = field(default=None, init=False, repr=False)
    _client_built_at: float = field(default=0.0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        """True iff this verifier is configured AND PyJWT is installed."""
        return bool(_HAS_JWT and self.team_domain and self.audience)

    @property
    def _team_host(self) -> str:
        td = self.team_domain.strip().rstrip("/")
        if not td:
            return ""
        if td.startswith("http://") or td.startswith("https://"):
            td = td.split("://", 1)[1]
        if not td.endswith(".cloudflareaccess.com"):
            td = f"{td}.cloudflareaccess.com"
        return td

    @property
    def issuer(self) -> str:
        return f"https://{self._team_host}"

    @property
    def certs_url(self) -> str:
        return f"{self.issuer}/cdn-cgi/access/certs"

    @property
    def logout_url(self) -> str:
        """URL the SPA can send the user to in order to log out of Access."""
        return f"{self.issuer}/cdn-cgi/access/logout"

    # ------------------------------------------------------------------
    def _get_client(self) -> Any:
        """Return a (cached) PyJWKClient pointed at the team's certs."""
        now = time.monotonic()
        with self._lock:
            if (
                self._client is None
                or (now - self._client_built_at) > _JWKS_CLIENT_TTL_SECONDS
            ):
                self._client = PyJWKClient(self.certs_url)
                self._client_built_at = now
            return self._client

    def verify(self, token: str) -> dict[str, Any] | None:
        """Verify ``token`` and return its claims, or ``None`` on failure.

        Never raises — a bad/expired/forged token simply yields ``None``
        so the caller can return a clean 401.
        """
        if not self.enabled or not token:
            return None
        try:
            client = self._get_client()
            signing_key = client.get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat"]},
            )
            return claims
        except Exception as exc:  # pragma: no cover - many failure shapes
            logger.debug("CF Access JWT verification failed: %s", exc)
            return None

    @staticmethod
    def email_from_claims(claims: dict[str, Any]) -> str | None:
        """Extract the stable identity (email) from verified claims."""
        email = claims.get("email") or claims.get("identity")
        if isinstance(email, str) and email.strip():
            return email.strip().lower()
        return None


def build_verifier(settings: Any) -> CloudflareAccessVerifier | None:
    """Construct a verifier from settings, or ``None`` when not configured.

    Returns ``None`` when no ``cf_access_team_domain`` is set so the
    factory can leave Access auth switched off (dev / single-tenant).
    """
    team = (getattr(settings, "cf_access_team_domain", "") or "").strip()
    aud = (getattr(settings, "cf_access_aud", "") or "").strip()
    if not team or not aud:
        return None
    verifier = CloudflareAccessVerifier(team_domain=team, audience=aud)
    if not _HAS_JWT:
        logger.warning(
            "CF Access configured (team=%s) but PyJWT is not installed — "
            "Access verification is disabled. `pip install pyjwt[crypto]`.",
            team,
        )
    else:
        logger.info("CF Access auth enabled (team=%s)", verifier._team_host)
    return verifier


__all__ = [
    "CF_ACCESS_JWT_HEADER",
    "CloudflareAccessVerifier",
    "build_verifier",
]
