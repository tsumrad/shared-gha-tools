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


class CodeScanningAlertInput(BaseModel):
    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")


async def get_codescanning_alerts(owner: str, repo: str) -> list[dict[str, Any]]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required")

    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    params = {"state": "open", "per_page": PER_PAGE}

    alerts: list[dict[str, Any]] = []
    async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(30.0)) as client:
        while True:
            response = await client.get(url, params=params)
            response.raise_for_status()

            alerts.extend(response.json())

            next_url = get_next_link(response.headers.get("Link", ""))
            if not next_url:
                break

            url = next_url
            params = None

    return alerts


@tool(
    "collect_codescanning_alerts",
    args_schema=CodeScanningAlertInput,
)
async def codescanning_alerts_tool(owner: str, repo: str) -> list[dict[str, Any]]:
    """Collect open GitHub code scanning alerts for a repository."""
    return await get_codescanning_alerts(owner=owner, repo=repo)
