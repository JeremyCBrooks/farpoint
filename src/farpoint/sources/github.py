"""GitHub code search: public code that mentions the organisation's domain.

As a discovery source (`github`, with GITHUB_TOKEN), the in-scope hostnames in the matched lines.
For --code, files that name the domain next to a credential word: leads to read, recorded by
repository, path and URL only. The matched text itself is never kept, since it may be the secret.
"""

from __future__ import annotations

from collections.abc import Iterator

from farpoint.models import Observation
from farpoint.names import extract_hostnames
from farpoint.sources.base import HttpSource

SECRET_WORDS = ("password", "secret", "api_key", "token")
PER_PAGE = 100


class GitHubCode(HttpSource):
    name = "github"
    key_required = True
    max_concurrency = 1
    min_interval = 6.5  # code search allows 10 requests a minute
    max_pages = 10  # GitHub returns at most 1,000 results

    def _search(self, query: str, pages: int) -> Iterator[dict]:
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "application/vnd.github.text-match+json", "X-GitHub-Api-Version": "2022-11-28"}
        for page in range(1, pages + 1):
            body = self.get("https://api.github.com/search/code", params={"q": query, "per_page": PER_PAGE, "page": page}, headers=headers).json()
            items = body.get("items", [])
            yield from items
            if len(items) < PER_PAGE:
                return

    def collect(self, domain: str) -> Iterator[Observation]:
        for item in self._search(f'"{domain}"', self.max_pages):
            for match in item.get("text_matches", []):
                for host in extract_hostnames(match.get("fragment", ""), domain):
                    yield self.observe(host)

    def leads(self, domain: str) -> Iterator[dict]:
        """Files naming `domain` next to a credential word: url, repository, path, keyword and domain. No text."""
        for word in SECRET_WORDS:
            for item in self._search(f'"{domain}" {word}', 1):
                if item.get("html_url") and item.get("path"):
                    yield {"url": item["html_url"], "repository": (item.get("repository") or {}).get("full_name", ""),
                           "path": item["path"], "keyword": word, "domain": domain}
