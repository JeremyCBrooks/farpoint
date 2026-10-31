"""How each scan domain signs in to Microsoft (with --tenants): cloud passwords (managed), federated
to an identity provider, or not in Microsoft at all. Two requests per domain to Microsoft's public
sign-in endpoints; nothing goes to the organisation, and no real username is ever sent.

Federation to a self-hosted ADFS server is what matters to an attacker: it takes passwords outside
Entra's lockout protection, and its token-signing key forges sign-ins for every user (Golden SAML).
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Mapping
from functools import cache
from importlib import resources
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from farpoint.sources.base import HttpSource
from farpoint.suffixes import registered

LOGIN = "https://login.microsoftonline.com"
_SIGN_IN = {"managed": "managed", "federated": "federated", "unknown": "none"}
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


class SignIn(Protocol):
    def realm(self, domain: str) -> dict: ...  # getuserrealm's answer

    def openid(self, domain: str) -> dict | None: ...  # the tenant's OpenID configuration; None: no tenant


class MicrosoftSignIn(HttpSource):
    name = "entra"
    max_concurrency = 2
    min_interval = 0.5

    def realm(self, domain: str) -> dict:
        login = f"{secrets.token_hex(8)}@{domain}"  # a made-up user: the answer is about the domain
        return self.get(f"{LOGIN}/getuserrealm.srf", params={"login": login, "json": "1"}).json()

    def openid(self, domain: str) -> dict | None:
        try:
            return self.get(f"{LOGIN}/{domain}/v2.0/.well-known/openid-configuration").json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (400, 404):
                return None
            raise


@cache
def _providers() -> dict[str, str]:
    data = json.loads(resources.files("farpoint.data").joinpath("identity_providers.json").read_text(encoding="utf-8"))
    return {d: p["name"] for p in data["providers"] for d in p["domains"]}


def classify(domain: str, realm: Mapping, openid: Mapping | None) -> dict:
    """One identity row for a scan domain from Microsoft's two answers."""
    sign_in = _SIGN_IN.get(str(realm.get("NameSpaceType", "")).lower())
    provider = host = None
    if sign_in == "federated" and realm.get("AuthURL"):
        url = urlsplit(realm["AuthURL"])
        host = (url.hostname or "").lower() or None
        if "/adfs/" in url.path.lower():
            provider = "adfs"
        else:
            provider = _providers().get(registered(host or "") or host or "", "other")
    tenant = _GUID.search((openid or {}).get("issuer") or "")
    return {
        "domain": domain,
        "sign_in": sign_in,
        "provider": provider,
        "sign_in_host": host,
        "brand": realm.get("FederationBrandName") or None,
        "tenant_id": tenant.group(0).lower() if tenant else None,
        "region": (openid or {}).get("tenant_region_scope"),
    }
