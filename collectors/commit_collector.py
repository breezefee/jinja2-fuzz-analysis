from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from pydriller import Repository

import config
from utils.helpers import dump_csv, dump_json, utc_now_iso


def is_bugfix_message(message: str) -> bool:
    lowered = message.lower()
    return any(keyword in lowered for keyword in config.BUG_KEYWORDS)


def _commit_row(commit: Any) -> dict[str, Any]:
    author_date = commit.author_date
    message = commit.msg or ""
    files = [
        modified_file.new_path or modified_file.old_path or "<unknown>"
        for modified_file in commit.modified_files
    ]
    return {
        "hash": commit.hash,
        "author_name": commit.author.name,
        "author_email": commit.author.email,
        "date": author_date.isoformat(),
        "year": author_date.year,
        "month": f"{author_date.year:04d}-{author_date.month:02d}",
        "iso_week": f"{author_date.isocalendar().year}-W{author_date.isocalendar().week:02d}",
        "weekday": author_date.weekday(),
        "hour": author_date.hour,
        "message": message,
        "is_bugfix": int(is_bugfix_message(message)),
        "insertions": int(commit.insertions or 0),
        "deletions": int(commit.deletions or 0),
        "files_changed": int(len(files)),
        "files": "|".join(files),
    }


def _build_summary(rows: list[dict[str, Any]], collected_at: str) -> dict[str, Any]:
    by_year = Counter(row["year"] for row in rows)
    by_month = Counter(row["month"] for row in rows)
    by_week = Counter(row["iso_week"] for row in rows)
    by_author = Counter(row["author_name"] for row in rows)
    by_weekday = Counter(row["weekday"] for row in rows)
    by_hour = Counter(row["hour"] for row in rows)
    file_counter: Counter[str] = Counter()
    churn_by_month: dict[str, dict[str, int]] = defaultdict(
        lambda: {"insertions": 0, "deletions": 0}
    )

    bugfix_count = 0
    total_insertions = 0
    total_deletions = 0
    for row in rows:
        if row["is_bugfix"]:
            bugfix_count += 1
        total_insertions += int(row["insertions"])
        total_deletions += int(row["deletions"])
        churn = churn_by_month[row["month"]]
        churn["insertions"] += int(row["insertions"])
        churn["deletions"] += int(row["deletions"])
        for file_name in str(row["files"]).split("|"):
            if file_name and file_name != "<unknown>":
                file_counter[file_name] += 1

    return {
        "collector": "pydriller",
        "status": "ok",
        "collected_at": collected_at,
        "total_commits": len(rows),
        "bugfix_commits": bugfix_count,
        "bugfix_ratio": (bugfix_count / len(rows)) if rows else 0.0,
        "total_insertions": total_insertions,
        "total_deletions": total_deletions,
        "frequency_by_year": dict(sorted(by_year.items())),
        "frequency_by_month": dict(sorted(by_month.items())),
        "frequency_by_week": dict(sorted(by_week.items())),
        "frequency_by_weekday": dict(sorted(by_weekday.items())),
        "frequency_by_hour": dict(sorted(by_hour.items())),
        "top_authors": by_author.most_common(20),
        "top_files": file_counter.most_common(20),
        "monthly_churn": dict(sorted(churn_by_month.items())),
    }


def collect_commits(repo_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    collected_at = utc_now_iso()
    repository = Repository(str(repo_root))
    for commit in repository.traverse_commits():
        rows.append(_commit_row(commit))

    summary = _build_summary(rows, collected_at)
    summary["repo_root"] = str(repo_root)

    dump_csv(config.DATA_DIR / "commits.csv", rows)
    dump_json(config.DATA_DIR / "commit_summary.json", summary)
    return summary
