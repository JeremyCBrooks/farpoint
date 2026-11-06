"""Credential provider registry. To add a provider: implement `credential_sources.base.CredentialProvider` and list it here."""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from farpoint.credential_sources.base import CredentialProvider
from farpoint.credential_sources.hibp import HibpPublic
from farpoint.credential_sources.hudsonrock import HudsonRockOsint
from farpoint.sources.base import Source
from farpoint.sources.hudsonrock import HudsonRock


def build_credential_providers(http: httpx.Client, sources: Sequence[Source]) -> dict[str, CredentialProvider]:
    """The providers by name. `hudsonrock-osint` shares the `hudsonrock` hostname source's answers, so a
    domain is requested once whichever of the two asks first."""
    hudson = next((s for s in sources if isinstance(s, HudsonRock)), None) or HudsonRock(http)
    providers: list[CredentialProvider] = [HudsonRockOsint(hudson), HibpPublic(http)]
    return {p.name: p for p in providers}
