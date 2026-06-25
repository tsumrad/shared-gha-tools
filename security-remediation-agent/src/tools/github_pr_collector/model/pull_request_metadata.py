import re
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel

from ...github_vulnerability_collector.dependabot_alerts_tool import DEFAULT_SEVERITIES
from ...github_vulnerability_collector.model.vulnerability_alert import build_alerts_by_package

VERSION_BUMP_PATTERNS = (
    re.compile(r"[Bb]ump\s+(\S+)\s+from\s+(\S+)\s+to\s+(\S+)(?:\s+in\s+.+)?$"),
    re.compile(r"[Uu]pdate\s+(\S+)\s+requirements?\s+from\s+(\S+)\s+to\s+(\S+)"),
    re.compile(r"[Uu]pdate\s+(\S+)\s+from\s+(\S+)\s+to\s+(\S+)"),
)


class VersionBump(BaseModel):
    package: str
    from_version: str
    to_version: str


class PullRequestMetadata(BaseModel):
    pr_number: int | None = None
    pr_title: str = ""
    pr_branch: str = ""
    pr_url: str = ""
    package: str
    from_version: str
    to_version: str
    breaking: bool
    severity: str
    impact: str
    alerts: list[dict[str, Any]]
    author: str = ""

    @classmethod
    def from_pull_request(
        cls,
        pull_request: dict[str, Any],
        package_alerts: list[dict[str, Any]],
        severity: str,
        version_bump: VersionBump,
    ) -> "PullRequestMetadata":
        breaking = is_breaking_change(version_bump.from_version, version_bump.to_version)
        return cls(
            pr_number=pull_request.get("number"),
            pr_title=pull_request.get("title", ""),
            pr_branch=(pull_request.get("head") or {}).get("ref", ""),
            pr_url=pull_request.get("html_url", ""),
            package=version_bump.package,
            from_version=version_bump.from_version,
            to_version=version_bump.to_version,
            breaking=breaking,
            severity=severity,
            impact="breaking" if breaking else "non-breaking",
            alerts=package_alerts,
            author=(pull_request.get("user") or {}).get("login", ""),
        )


def parse_version_bump(title: str) -> VersionBump | None:
    for pattern in VERSION_BUMP_PATTERNS:
        match = pattern.search(title)
        if match:
            return VersionBump(
                package=match.group(1),
                from_version=match.group(2),
                to_version=match.group(3),
            )

    return None


def parse_major(version: str) -> int | None:
    version_without_prefix = re.sub(r"^[^0-9]*", "", str(version))
    major = re.split(r"[.\-+]", version_without_prefix)[0]
    return int(major) if major.isdigit() else None


def is_breaking_change(from_version: str, to_version: str) -> bool:
    from_major = parse_major(from_version)
    to_major = parse_major(to_version)
    return from_major is not None and to_major is not None and to_major > from_major


def highest_severity(alerts: Iterable[dict[str, Any]]) -> str | None:
    for severity in ("critical", "high", "medium", "low"):
        if any(alert.get("severity") == severity for alert in alerts):
            return severity

    return None


def find_alerts_for_package(
    package_name: str,
    alerts_by_package: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    lower_name = package_name.lower()
    if lower_name in alerts_by_package:
        return alerts_by_package[lower_name]

    for indexed_name, alerts in alerts_by_package.items():
        if lower_name.endswith(f"/{indexed_name}") or indexed_name.endswith(f"/{lower_name}"):
            return alerts

    return []


def filter_security_dependency_pull_requests(
    pull_requests: Iterable[dict[str, Any]],
    alerts: Iterable[dict[str, Any]],
    severities: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    requested_severities = set(severities or DEFAULT_SEVERITIES)
    alerts_by_package = build_alerts_by_package(alerts)
    candidates: list[dict[str, Any]] = []

    for pull_request in pull_requests:
        version_bump = parse_version_bump(pull_request.get("title", ""))
        if not version_bump:
            continue

        package_alerts = find_alerts_for_package(version_bump.package, alerts_by_package)
        if not package_alerts:
            continue

        severity = highest_severity(package_alerts)
        if not severity or severity not in requested_severities:
            continue

        candidates.append(
            PullRequestMetadata.from_pull_request(
                pull_request=pull_request,
                package_alerts=package_alerts,
                severity=severity,
                version_bump=version_bump,
            ).model_dump()
        )

    return candidates
