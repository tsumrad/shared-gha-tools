import pytest

from src.tools.github_codescanning_collector import codescanning_alerts_tool as tool_module
from src.tools.github_codescanning_collector.codescanning_alerts_tool import (
    codescanning_alerts_tool,
    get_codescanning_alerts,
)


class StubResponse:
    def __init__(self, data, headers=None):
        self.data = data
        self.headers = headers or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


class StubAsyncClient:
    requests = []
    pages = []
    links = []
    headers = None

    def __init__(self, *, headers, timeout):
        type(self).headers = headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url, params):
        type(self).requests.append({"url": url, "params": params})
        return StubResponse(type(self).pages.pop(0), {"Link": type(self).links.pop(0)})


@pytest.mark.asyncio
async def test_get_codescanning_alerts_fetches_open_alerts_with_link_pagination(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(tool_module.httpx, "AsyncClient", StubAsyncClient)
    StubAsyncClient.requests = []
    StubAsyncClient.pages = [
        [{"number": index} for index in range(tool_module.PER_PAGE)],
        [{"number": tool_module.PER_PAGE}],
    ]
    StubAsyncClient.links = [
        '<https://api.github.com/repositories/1/code-scanning/alerts?page=2>; rel="next"',
        "",
    ]

    alerts = await get_codescanning_alerts("octo-org", "octo-repo")

    assert len(alerts) == tool_module.PER_PAGE + 1
    assert StubAsyncClient.headers["Authorization"] == "Bearer token"
    assert StubAsyncClient.requests == [
        {
            "url": "https://api.github.com/repos/octo-org/octo-repo/code-scanning/alerts",
            "params": {"state": "open", "per_page": tool_module.PER_PAGE},
        },
        {
            "url": "https://api.github.com/repositories/1/code-scanning/alerts?page=2",
            "params": None,
        },
    ]


@pytest.mark.asyncio
async def test_codescanning_alerts_tool_invokes_fetcher(monkeypatch):
    async def stub_get_codescanning_alerts(owner, repo):
        return [{"owner": owner, "repo": repo}]

    monkeypatch.setattr(tool_module, "get_codescanning_alerts", stub_get_codescanning_alerts)

    alerts = await codescanning_alerts_tool.ainvoke(
        {"owner": "octo-org", "repo": "octo-repo"}
    )

    assert alerts == [{"owner": "octo-org", "repo": "octo-repo"}]
