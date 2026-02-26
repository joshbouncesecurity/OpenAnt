#!/usr/bin/env python3
"""
GitHub Repository Scanner for High-Star JavaScript Projects

Scans GitHub for JavaScript repositories with very high star counts.
Outputs repository metadata for further analysis.
"""
from __future__ import annotations

import json
import os
import random
import time
from typing import Any, Dict, List, Optional, Set

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# Env / Auth
# =========================

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
if not GITHUB_TOKEN:
    raise RuntimeError("Missing GITHUB_TOKEN. Put it in your environment or .env file.")

GITHUB_API = "https://api.github.com"

# =========================
# Configuration
# =========================

# Very high star threshold for JavaScript repos
MIN_STARS = 10000

# Query for high-star JavaScript repositories
DEFAULT_QUERY = f"language:JavaScript fork:false archived:false stars:>{MIN_STARS}"

# Query variations to get diverse high-star repos
QUERY_VARIATIONS = [
    # Pure JavaScript repos with very high stars
    f"language:JavaScript fork:false archived:false stars:>{MIN_STARS}",
    # TypeScript repos (also JavaScript ecosystem)
    f"language:TypeScript fork:false archived:false stars:>{MIN_STARS}",
    # Node.js specific
    f"language:JavaScript fork:false archived:false stars:>{MIN_STARS} topic:nodejs",
    # React ecosystem
    f"language:JavaScript fork:false archived:false stars:>{MIN_STARS} topic:react",
    # Vue ecosystem
    f"language:JavaScript fork:false archived:false stars:>{MIN_STARS} topic:vue",
]

# =========================
# HTTP session + retries
# =========================

def _make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=6,
        connect=6,
        read=6,
        status=6,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount("https://", adapter)
    s.headers.update({
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "openant-repo-scanner/1.0",
        "Connection": "keep-alive",
    })
    return s


def _sleep_for_rate_limit(resp: requests.Response) -> None:
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    msg = ""
    try:
        msg = (resp.json() or {}).get("message", "")
    except Exception:
        pass

    if remaining == "0" and reset:
        wait = max(1, int(reset) - int(time.time()) + 2)
        print(f"[rate-limit] sleeping {wait}s until reset...")
        time.sleep(wait)
        return

    if "secondary rate limit" in (msg or "").lower() or resp.status_code in (403, 429):
        wait = 20 + random.randint(0, 10)
        print(f"[throttle] sleeping {wait}s (status {resp.status_code})...")
        time.sleep(wait)


def _get_json(
    s: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    allow_404: bool = False,
) -> Optional[Any]:
    for _ in range(10):
        time.sleep(0.12 + random.random() * 0.18)
        try:
            resp = s.get(url, params=params, timeout=30)
        except requests.RequestException:
            continue

        if resp.status_code == 404 and allow_404:
            return None

        if resp.status_code in (403, 429):
            _sleep_for_rate_limit(resp)
            s.close()
            s = _make_session()
            continue

        if resp.status_code >= 500:
            continue

        if resp.status_code != 200:
            return None

        try:
            return resp.json()
        except Exception:
            return None

    return None


# =========================
# JSONL IO helpers
# =========================

def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except FileNotFoundError:
        pass
    return out


# =========================
# Collection Functions
# =========================

def retrieve_repos(
    num_repos: int,
    query: str,
    already_seen: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve JavaScript repos from GitHub matching the query.

    Args:
        num_repos: Target number of repos to retrieve
        query: GitHub search query
        already_seen: Set of repo names to skip

    Returns:
        List of repo dictionaries
    """
    s = _make_session()
    collected: List[Dict[str, Any]] = []
    seen = set()
    if already_seen:
        seen.update(already_seen)

    page = 1
    print(f"[retrieve] Query: {query[:80]}...")

    while len(collected) < num_repos and page <= 10:  # Max 10 pages (1000 repos)
        data = _get_json(
            s,
            f"{GITHUB_API}/search/repositories",
            params={"q": query, "sort": "stars", "order": "desc", "per_page": 100, "page": page},
        )
        if not data:
            break

        items = data.get("items", [])
        if not items:
            break

        for it in items:
            full_name = it.get("full_name")
            if not full_name or full_name in seen:
                continue
            seen.add(full_name)

            repo_data = {
                "full_name": full_name,
                "html_url": it.get("html_url"),
                "default_branch": it.get("default_branch"),
                "stars": it.get("stargazers_count"),
                "language": it.get("language"),
                "description": (it.get("description") or "")[:500],
                "topics": it.get("topics", []),
                "created_at": it.get("created_at"),
                "updated_at": it.get("updated_at"),
                "size_kb": it.get("size"),
                "open_issues": it.get("open_issues_count"),
                "forks": it.get("forks_count"),
            }
            collected.append(repo_data)

            if len(collected) >= num_repos:
                break

        page += 1

    return collected


# =========================
# Main orchestration
# =========================

def main() -> None:
    out_dir = "out"
    repos_path = f"{out_dir}/high_star_js_repos.jsonl"

    os.makedirs(out_dir, exist_ok=True)

    all_repos: List[Dict[str, Any]] = []
    seen_repo_names: Set[str] = set()

    print("=" * 60)
    print(f"COLLECTING HIGH-STAR JAVASCRIPT REPOS (stars > {MIN_STARS})")
    print("=" * 60)

    for query_idx, query in enumerate(QUERY_VARIATIONS):
        print(f"\n[Query {query_idx + 1}/{len(QUERY_VARIATIONS)}] {query[:60]}...")

        # Retrieve repos for this query
        query_repos = retrieve_repos(
            num_repos=200,  # Get up to 200 repos per query
            query=query,
            already_seen=seen_repo_names,
        )

        # Deduplicate
        new_count = 0
        for r in query_repos:
            repo_name = r.get("full_name")
            if repo_name and repo_name not in seen_repo_names:
                seen_repo_names.add(repo_name)
                all_repos.append(r)
                new_count += 1

        print(f"  Found {new_count} new repos (total: {len(all_repos)})")

    # Sort by stars descending
    all_repos.sort(key=lambda x: x.get("stars", 0), reverse=True)

    # Save results
    _write_jsonl(repos_path, all_repos)

    print("\n" + "=" * 60)
    print("COLLECTION COMPLETE")
    print("=" * 60)
    print(f"Output file: {repos_path}")
    print(f"Total repos: {len(all_repos)}")

    # Print summary
    if all_repos:
        print(f"\nStar range: {all_repos[-1].get('stars', 0):,} - {all_repos[0].get('stars', 0):,}")

        # Language distribution
        lang_counts: Dict[str, int] = {}
        for r in all_repos:
            lang = r.get("language", "Unknown")
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        print("\nBy language:")
        for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1]):
            print(f"  {lang}: {count}")

        # Top 20 repos
        print("\nTop 20 repos by stars:")
        for i, r in enumerate(all_repos[:20], 1):
            stars = r.get("stars", 0)
            name = r.get("full_name", "")
            lang = r.get("language", "")
            print(f"  {i:2}. {name} ({lang}) - {stars:,} stars")


if __name__ == "__main__":
    main()
