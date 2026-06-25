import os
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..github_vulnerability_collector.dependabot_alerts_tool import (
    GITHUB_API_VERSION,
    PER_PAGE,
    get_next_link,
)
from .model.pull_request_metadata import filter_security_dependency_pull_requests


class SecurityDependencyPullRequestInput(BaseModel):
    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Open Dependabot alerts used to match dependency PRs to security fixes.",
    )
    severities: list[str] | None = Field(
        default=None,
        description="Optional alert severities to include: critical, high, medium, or low.",
    )


async def get_open_pull_requests(owner: str, repo: str) -> list[dict[str, Any]]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required")

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    params = {"state": "open", "per_page": PER_PAGE}

    pull_requests: list[dict[str, Any]] = []
    async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(30.0)) as client:
        while True:
            response = await client.get(url, params=params)
            response.raise_for_status()

            data = response.json()
            pull_requests.extend(data)

            next_url = get_next_link(response.headers.get("Link", ""))
            if not next_url:
                break

            url = next_url
            params = None

    return pull_requests


@tool(
    "collect_security_dependency_pull_requests",
    args_schema=SecurityDependencyPullRequestInput,
)
async def security_dependency_pull_requests_tool(
    owner: str,
    repo: str,
    alerts: list[dict[str, Any]],
    severities: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Collect open pull requests that remediate dependency security alerts."""
    pull_requests = await get_open_pull_requests(owner=owner, repo=repo)
    return filter_security_dependency_pull_requests(
        pull_requests=pull_requests,
        alerts=alerts,
        severities=severities,
    )
