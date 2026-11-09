"""Summarize a study results file into the README tables.

    python -m mcp_posture.summarize results/registry_npm_sample1500.jsonl
"""

from __future__ import annotations

import json
import math
import sys
from collections import Counter
from pathlib import Path

from .posture import MCP_SDK, SEVERITY_ORDER


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def pct(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({100 * k / n:.1f}%, 95% CI {100 * lo:.1f}-{100 * hi:.1f})" if n else "0/0"


def at_least(r: dict, sev: str, relations=("SELF", "DIRECT", "INDIRECT")) -> bool:
    floor = SEVERITY_ORDER[sev]
    return any(SEVERITY_ORDER.get(f[4], 0) >= floor and f[2] in relations for f in r["findings"])


def summarize(rows: list[dict]) -> dict:
    res = [r for r in rows if r["resolved"]]
    n = len(res)
    s = {"sampled": len(rows), "resolved": n}
    s["any"] = sum(bool(r["findings"]) for r in res)
    s["high_plus"] = sum(at_least(r, "HIGH") for r in res)
    s["critical"] = sum(at_least(r, "CRITICAL") for r in res)
    s["direct_or_self_high_plus"] = sum(at_least(r, "HIGH", ("SELF", "DIRECT")) for r in res)
    s["self_any"] = sum(any(f[2] == "SELF" for f in r["findings"]) for r in res)
    s["install_scripts"] = sum(bool(r["install_scripts"]) for r in rows)
    s["uses_sdk"] = sum(bool(r["sdk_versions"]) for r in res)
    s["sdk_vulnerable"] = sum(any(f[0] == MCP_SDK for f in r["findings"]) for r in res)
    nodes = sorted(r["nodes"] for r in res)
    s["median_nodes"] = nodes[len(nodes) // 2] if nodes else 0
    adv_pkgs = Counter()
    adv_sev = {}
    for r in res:
        for adv in {(f[0], f[3]) for f in r["findings"]}:
            adv_pkgs[adv] += 1
        for f in r["findings"]:
            adv_sev[(f[0], f[3])] = f[4]
    s["top_advisories"] = [(name, adv, adv_sev[(name, adv)], k) for (name, adv), k in adv_pkgs.most_common(10)]
    # how much of the HIGH+ exposure goes away if the single most common advisory is fixed
    if s["top_advisories"]:
        top = s["top_advisories"][0]
        s["high_plus_without_top"] = sum(
            any(SEVERITY_ORDER.get(f[4], 0) >= 3 and (f[0], f[3]) != (top[0], top[1]) for f in r["findings"]) for r in res)
    return s


def report(s: dict, meta: dict | None = None) -> str:
    n = s["resolved"]
    lines = []
    if meta:
        lines.append(f"Registry snapshot: {meta['registry_latest_servers']} latest server entries, "
                     f"{meta['npm_packages']} distinct npm packages, {meta['sampled']} sampled.")
    lines += [
        f"Dependency graph resolved by deps.dev: {s['resolved']}/{s['sampled']}; median graph size {s['median_nodes']} packages.",
        "",
        "| posture (npm MCP servers, resolved graphs) | count |",
        "|---|---|",
        f"| any OSV advisory in the resolved dependency graph | {pct(s['any'], n)} |",
        f"| HIGH or CRITICAL advisory anywhere in the graph | {pct(s['high_plus'], n)} |",
        f"| CRITICAL advisory anywhere in the graph | {pct(s['critical'], n)} |",
        f"| HIGH/CRITICAL in the package itself or a direct dependency | {pct(s['direct_or_self_high_plus'], n)} |",
        f"| advisory against the published server package itself | {pct(s['self_any'], n)} |",
        f"| depends on {MCP_SDK} | {pct(s['uses_sdk'], n)} |",
        f"| resolved {MCP_SDK} version has an advisory | {pct(s['sdk_vulnerable'], n)} |",
        f"| package runs an npm install hook (pre/post/install) | {pct(s['install_scripts'], s['sampled'])} |",
    ]
    if "high_plus_without_top" in s:
        lines.append(f"| HIGH/CRITICAL left if the most common advisory were fixed | {pct(s['high_plus_without_top'], n)} |")
    lines += ["", "| most common advisories (packages affected) | severity | servers |", "|---|---|---|"]
    lines += [f"| {name} {adv} | {sev} | {k} |" for name, adv, sev, k in s["top_advisories"]]
    return "\n".join(lines)


def main(argv=None):
    path = Path((argv or sys.argv[1:])[0])
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    meta_path = path.with_suffix(".meta.json")
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else None
    print(report(summarize(rows), meta))


if __name__ == "__main__":
    main()
