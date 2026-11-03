#!/usr/bin/env python3
"""Delete old Actions runs while protecting release evidence.

Protection set:
  - every run of the Release Xray workflow
  - every run whose head SHA is the target of a published Release tag
  - every run id referenced by release-manifest.json (qualificationRunId)

This replaces a blind retention action so a Release rerun can still verify
its qualification evidence after the normal retention window.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

API = "https://api.github.com"
USER_AGENT = "xray-actions-cleanup/1.0"


def _request(path, accept="application/vnd.github+json", raw=False):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required")
    url = path if path.startswith("http") else API + path
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": accept,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read()
    return body if raw else json.loads(body)


def _delete(path):
    token = os.getenv("GITHUB_TOKEN")
    req = urllib.request.Request(
        API + path,
        method="DELETE",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=30):
        pass


def _paginate(path):
    page = 1
    while True:
        sep = "&" if "?" in path else "?"
        data = _request(f"{path}{sep}per_page=100&page={page}")
        items = data.get("workflow_runs") if isinstance(data, dict) and "workflow_runs" in data else data
        if not items:
            return
        yield from items
        if len(items) < 100:
            return
        page += 1


def _release_tag_shas(repo, releases):
    shas = set()
    for release in releases:
        tag = release.get("tag_name")
        if not tag:
            continue
        try:
            ref = _request(f"/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag)}")
        except urllib.error.HTTPError:
            continue
        obj = ref.get("object", {})
        sha = obj.get("sha")
        if obj.get("type") == "tag" and sha:
            try:
                sha = _request(f"/repos/{repo}/git/tags/{sha}").get("object", {}).get("sha")
            except urllib.error.HTTPError:
                continue
        if sha:
            shas.add(sha)
    return shas


def _manifest_run_ids(repo, releases):
    ids = set()
    for release in releases:
        asset = next(
            (item for item in release.get("assets", [])
             if item.get("name") == "release-manifest.json"),
            None,
        )
        if not asset:
            continue
        try:
            body = _request(asset["url"], accept="application/octet-stream", raw=True)
            manifest = json.loads(body)
        except (urllib.error.HTTPError, json.JSONDecodeError):
            continue
        run_id = manifest.get("qualificationRunId")
        if isinstance(run_id, int):
            ids.add(run_id)
        elif isinstance(run_id, str) and run_id.isdigit():
            ids.add(int(run_id))
    return ids


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--retain-days", type=int, default=14)
    parser.add_argument("--keep-minimum-runs", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not args.repo:
        raise SystemExit("--repo or GITHUB_REPOSITORY is required")

    releases = list(_paginate(f"/repos/{args.repo}/releases"))
    release_shas = _release_tag_shas(args.repo, releases)
    manifest_run_ids = _manifest_run_ids(args.repo, releases)

    runs = list(_paginate(f"/repos/{args.repo}/actions/runs"))
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.retain_days)
    grouped = defaultdict(list)
    for run in runs:
        grouped[run.get("workflow_id")].append(run)

    protected = {}
    candidates = []
    for workflow_runs in grouped.values():
        workflow_runs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        for index, run in enumerate(workflow_runs):
            run_id = run["id"]
            reasons = []
            if run.get("name") == "Release Xray":
                reasons.append("release-workflow")
            if run.get("head_sha") in release_shas:
                reasons.append("release-tag-sha")
            if run_id in manifest_run_ids:
                reasons.append("manifest-qualification-run")
            if index < args.keep_minimum_runs:
                reasons.append("keep-minimum")
            if run.get("status") != "completed":
                reasons.append("not-completed")
            created_at = run.get("created_at", "")
            if reasons:
                protected[run_id] = reasons
                continue
            try:
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError:
                protected[run_id] = ["unparseable-created-at"]
                continue
            if created < cutoff:
                candidates.append(run)
            else:
                protected[run_id] = ["within-retention"]

    candidates.sort(key=lambda item: item.get("created_at", ""))
    print(f"repo={args.repo} runs={len(runs)} releases={len(releases)}")
    print(f"protected: {len(protected)} (release-workflow/release-tag-sha/manifest/keep-minimum/..."
          f"/within-retention)")
    print(f"candidates: {len(candidates)}")
    for run in candidates:
        print(
            f"DELETE {run['id']} {run.get('name')} "
            f"{run.get('created_at')} sha={str(run.get('head_sha'))[:12]} "
            f"{run.get('conclusion')}"
        )
    for run_id, reasons in sorted(protected.items()):
        if any(reason in reasons for reason in ("release-workflow", "release-tag-sha",
                                                "manifest-qualification-run")):
            print(f"PROTECT {run_id} {reasons}")

    if args.dry_run:
        print("dry-run: no runs deleted")
        return 0

    failures = 0
    for run in candidates:
        try:
            _delete(f"/repos/{args.repo}/actions/runs/{run['id']}")
            print(f"DELETED {run['id']}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"SKIP {run['id']} already gone")
                continue
            print(f"FAIL delete {run['id']}: HTTP {e.code} {e.read().decode('utf-8', 'replace')}",
                  file=sys.stderr)
            failures += 1
    print(f"deleted={len(candidates) - failures} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
