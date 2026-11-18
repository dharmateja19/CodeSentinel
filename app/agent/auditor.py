
from pathlib import Path
from collections import Counter

from app.scanner.repository import scan_repository
from app.analyzers.security import analyze_security
from app.analyzers.slop import analyze_slop
from app.analyzers.coding_gaps import analyze_coding_gaps
from app.analyzers.loose_ends import analyze_loose_ends
from app.agent.reasoner import analyze_findings

import time


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}


BANDIT_FAMILIES = {
    "B105": "hardcoded_credentials",
    "B307": "dynamic_execution",
    "B602": "command_injection",
    "B301": "unsafe_deserialization",
    "B324": "weak_hash"
}


TITLE_FAMILIES = {
    "hardcoded credentials": "hardcoded_credentials",
    "dangerous dynamic execution": "dynamic_execution",
    "command injection risk": "command_injection",
    "unsafe deserialization": "unsafe_deserialization",
    "weak cryptographic hash": "weak_hash"
}


def normalize_file(file_path: str, root: Path) -> str:
    try:
        path = Path(file_path)

        if not path.is_absolute():
            path = root / path

        return path.resolve().relative_to(root).as_posix()

    except (ValueError, OSError):
        return str(file_path).replace("\\", "/")


def get_issue_family(finding: dict) -> str:
    issue_id = str(finding.get("id", "")).upper()
    title = str(finding.get("title", "")).lower().strip()
    category = str(finding.get("category", "Unknown")).lower()

    # Known equivalent issues across different analyzers.
    if issue_id in BANDIT_FAMILIES:
        return BANDIT_FAMILIES[issue_id]

    if title in TITLE_FAMILIES:
        return TITLE_FAMILIES[title]

    # Do not merge unrelated issues just because their IDs match.
    return f"{category}:{issue_id or title}"


def get_sources(finding: dict) -> set:
    sources = finding.get("sources", [])

    if isinstance(sources, str):
        sources = [sources]

    if not isinstance(sources, (list, set, tuple)):
        sources = []

    source = finding.get("source")

    if source:
        sources = list(sources) + [source]

    return {
        str(item)
        for item in sources
        if item
    }


def get_categories(finding: dict) -> set:
    categories = finding.get("categories", [])

    if isinstance(categories, str):
        categories = [categories]

    if not isinstance(categories, (list, set, tuple)):
        categories = []

    category = finding.get("category")

    if category:
        categories = list(categories) + [category]

    return {
        str(item)
        for item in categories
        if item
    }


def merge_findings(existing: dict, incoming: dict) -> dict:

    # Preserve all contributing categories.
    categories = get_categories(existing)
    categories.update(get_categories(incoming))

    existing["categories"] = sorted(categories)

    # Preserve all analyzer sources.
    sources = get_sources(existing)
    sources.update(get_sources(incoming))

    existing["sources"] = sorted(sources)

    # Preserve all rule IDs.
    rule_ids = set(existing.get("rule_ids", []))
    rule_ids.update(incoming.get("rule_ids", []))

    for finding in (existing, incoming):
        if finding.get("id"):
            rule_ids.add(str(finding["id"]))

    existing["rule_ids"] = sorted(rule_ids)

    # Keep the highest static severity.
    current_severity = str(
        existing.get("severity", "LOW")
    ).upper()

    incoming_severity = str(
        incoming.get("severity", "LOW")
    ).upper()

    if SEVERITY_ORDER.get(
        incoming_severity, 3
    ) < SEVERITY_ORDER.get(
        current_severity, 3
    ):
        existing["severity"] = incoming_severity

    # Preserve additional descriptions as evidence.
    descriptions = set()

    for finding in (existing, incoming):
        description = finding.get("description")

        if description:
            descriptions.add(str(description))

    if descriptions:
        existing["evidence"] = sorted(descriptions)

    return existing


def deduplicate_findings(findings: list, root: Path) -> list:

    unique = {}

    for finding in findings:

        normalized = dict(finding)

        normalized["file"] = normalize_file(
            finding.get("file", ""),
            root
        )

        normalized["severity"] = str(
            normalized.get("severity", "LOW")
        ).upper()

        # Only equivalent issue families at the same location merge.
        key = (
            normalized["file"],
            normalized.get("line"),
            get_issue_family(normalized)
        )

        if key not in unique:
            normalized["categories"] = sorted(
                get_categories(normalized)
            )

            normalized["sources"] = sorted(
                get_sources(normalized)
            )

            normalized["rule_ids"] = (
                [str(normalized["id"])]
                if normalized.get("id")
                else []
            )

            unique[key] = normalized

        else:
            unique[key] = merge_findings(
                unique[key],
                normalized
            )

    return list(unique.values())


def run_full_audit(repo_path: str) -> dict:

    start_time = time.perf_counter()
    
    root = Path(repo_path).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError("Invalid repository directory")

    # Repository overview.
    stage_start = time.perf_counter()
    repository_info = scan_repository(str(root))
    print(f"Repository scanning: {time.perf_counter() - stage_start:.2f}s")
    
    print("Repository files:", repository_info["total_files"])
    print("Languages:", repository_info["languages"])
    print("Skipped files:", repository_info["skipped_files"])

    # Run all four analyzers.
    stage_start = time.perf_counter()
    security = analyze_security(str(root))
    print(f"Security: {time.perf_counter() - stage_start:.2f}s")

    stage_start = time.perf_counter()
    slop = analyze_slop(str(root))
    print(f"Slop: {time.perf_counter() - stage_start:.2f}s")

    stage_start = time.perf_counter()
    coding_gaps = analyze_coding_gaps(str(root))
    print(f"Coding gaps: {time.perf_counter() - stage_start:.2f}s")

    stage_start = time.perf_counter()
    loose_ends = analyze_loose_ends(str(root))
    print(f"Loose ends: {time.perf_counter() - stage_start:.2f}s")

    categories = [
        security,
        slop,
        coding_gaps,
        loose_ends
    ]

    all_findings = []

    for category_result in categories:

        category_name = category_result["category"]

        for finding in category_result["findings"]:

            normalized = dict(finding)
            normalized["category"] = category_name

            all_findings.append(normalized)

    # Deduplicate equivalent findings.
    stage_start = time.perf_counter()
    all_findings = deduplicate_findings(all_findings, root)
    print(f"Deduplication: {time.perf_counter() - stage_start:.2f}s")

    # Sort by severity.
    all_findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(
                item.get("severity", "LOW"), 3
            ),
            item.get("file", ""),
            item.get("line") or 0
        )
    )

    # AI-powered validation.
    # Static findings and severity remain unchanged.
    stage_start = time.perf_counter()
    all_findings = analyze_findings(str(root), all_findings)
    print(f"AI validation: {time.perf_counter() - stage_start:.2f}s")

    # AI validation statistics.
    ai_verdict_counts = Counter(
        finding.get("ai_analysis", {}).get(
            "verdict", "UNCERTAIN"
        )
        for finding in all_findings
    )

    # Severity statistics.
    severity_counts = Counter(
        finding.get("severity", "LOW")
        for finding in all_findings
    )

    # Count each finding under every contributing category.
    category_counts = Counter()

    for finding in all_findings:
        for category in get_categories(finding):
            category_counts[category] += 1

    category_summary = {
        category["category"]: category_counts.get(
            category["category"], 0
        )
        for category in categories
    }
    
    print(
        f"Total audit time: "
        f"{time.perf_counter() - start_time:.2f}s"
    )

    return {
        "project": "CodeSentinel",
        "status": "completed",
        "repository": repository_info,
        "audit_summary": {
            "total_findings": len(all_findings),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "by_category": dict(category_counts),
            "category_summary": category_summary,
            "ai_validation": {
                "confirmed": ai_verdict_counts.get("CONFIRMED", 0),
                "likely": ai_verdict_counts.get("LIKELY", 0),
                "false_positives": ai_verdict_counts.get(
                    "FALSE_POSITIVE", 0
                ),
                "uncertain": ai_verdict_counts.get(
                    "UNCERTAIN", 0
                )
            }
        },
        "findings": all_findings
    }
