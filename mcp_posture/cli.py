"""mcp-posture: inventory local MCP servers and check what they would install.

    python -m mcp_posture.cli scan                       # configs under $HOME
    python -m mcp_posture.cli scan --project . --json    # plus this repo's .mcp.json / .vscode/mcp.json
    python -m mcp_posture.cli scan --fail-on high        # exit 2 if any HIGH/CRITICAL advisory
    python -m mcp_posture.cli scan --state .mcp-posture.json   # report drift since the last run

Nothing is executed: configs are parsed, and versions/advisories come from the npm
registry, PyPI, deps.dev and OSV (public, no keys).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .inventory import ServerDef, discover
from .posture import SEVERITY_ORDER, advisory_severity, assess, osv_batch
from .sources import Fetcher

NPM_LATEST = "https://registry.npmjs.org/{}/latest"
PYPI_JSON = "https://pypi.org/pypi/{}/json"


def resolve_version(f: Fetcher, s: ServerDef) -> str | None:
    if s.pinned:
        return s.requested
    if s.ecosystem == "npm":
        doc = f.get_json(NPM_LATEST.format(s.package.replace("/", "%2f"))) or {}
        return doc.get("version")
    if s.ecosystem == "pypi":
        doc = f.get_json(PYPI_JSON.format(s.package)) or {}
        return (doc.get("info") or {}).get("version")
    return None


def config_hash(s: ServerDef) -> str:
    blob = json.dumps({"t": s.transport, "c": s.command, "a": s.args, "u": s.url}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def ident(s: ServerDef) -> str:
    return f"{s.client}:{s.project or '-'}:{s.name}"


def scan(f: Fetcher, servers: list[ServerDef]) -> list[dict]:
    rows = []
    npm_pkgs, py_pkgs = [], []
    for s in servers:
        version = resolve_version(f, s) if s.package else None
        flags = []
        if s.transport == "stdio" and s.package and not s.pinned:
            flags.append("UNPINNED")
        if s.transport == "stdio" and not s.package:
            flags.append("LOCAL-COMMAND")
        if s.transport in ("http", "sse") and s.url.startswith("http://") and "localhost" not in s.url and "127.0.0.1" not in s.url:
            flags.append("PLAINTEXT-REMOTE")
        row = {"id": ident(s), "client": s.client, "config": s.config, "name": s.name,
               "transport": s.transport, "command": s.command, "args": s.args, "url": s.url,
               "ecosystem": s.ecosystem, "package": s.package, "requested": s.requested,
               "resolved_version": version, "config_hash": config_hash(s), "flags": flags,
               "install_scripts": [], "advisories": [], "max_severity": None}
        rows.append(row)
        if s.ecosystem == "npm" and version:
            npm_pkgs.append((s.package, version))
        elif s.ecosystem == "pypi" and version:
            py_pkgs.append((s.package, version))

    postures = {(p.package, p.version): p for p in assess(f, sorted(set(npm_pkgs)))} if npm_pkgs else {}
    py_ids = osv_batch(f, py_pkgs, ecosystem="PyPI") if py_pkgs else {}
    for row in rows:
        key = (row["package"], row["resolved_version"])
        if row["ecosystem"] == "npm" and key in postures:
            p = postures[key]
            row["install_scripts"] = p.install_scripts
            row["advisories"] = [list(x) for x in p.findings]
            row["max_severity"] = p.max_severity
            if p.install_scripts:
                row["flags"].append("INSTALL-SCRIPTS")
            if not p.resolved:
                row["flags"].append("GRAPH-UNKNOWN")
        elif row["ecosystem"] == "pypi" and key in py_ids:
            advs = [[row["package"], row["resolved_version"], "SELF", a, advisory_severity(f, a)] for a in py_ids[key]]
            row["advisories"] = advs
            row["max_severity"] = max((a[4] for a in advs), key=lambda s: SEVERITY_ORDER.get(s, 0), default=None)
        if row["max_severity"]:
            row["flags"].append(f"VULN-{row['max_severity']}")
    return rows


def drift(previous: dict, rows: list[dict]) -> list[str]:
    """Changes since the last snapshot: added/removed servers, edited launch config,
    and unpinned packages whose resolved version moved."""
    notes = []
    now = {r["id"]: r for r in rows}
    for rid in sorted(set(now) - set(previous)):
        notes.append(f"ADDED {rid}")
    for rid in sorted(set(previous) - set(now)):
        notes.append(f"REMOVED {rid}")
    for rid in sorted(set(now) & set(previous)):
        old, new = previous[rid], now[rid]
        if old.get("config_hash") != new["config_hash"]:
            notes.append(f"CHANGED-CONFIG {rid}")
        elif old.get("resolved_version") != new["resolved_version"]:
            notes.append(f"VERSION {rid}: {old.get('resolved_version')} -> {new['resolved_version']}")
    return notes


def render(rows: list[dict], notes: list[str]) -> str:
    lines = [f"{len(rows)} MCP server definitions"]
    for r in rows:
        what = r["url"] or (f"{r['package']}@{r['resolved_version']}" if r["package"] else " ".join([r["command"], *r["args"]]))
        lines.append(f"- {r['id']} [{r['transport']}] {what} {' '.join(r['flags'])}".rstrip())
        for name, ver, rel, adv, sev in r["advisories"][:5]:
            lines.append(f"    {sev:<8} {adv} in {name}@{ver} ({rel.lower()})")
        if len(r["advisories"]) > 5:
            lines.append(f"    ... {len(r['advisories']) - 5} more")
    if notes:
        lines.append("drift since last scan:")
        lines.extend(f"  {n}" for n in notes)
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-posture")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan")
    sc.add_argument("--home", default=str(Path.home()))
    sc.add_argument("--project", action="append", default=[])
    sc.add_argument("--json", action="store_true")
    sc.add_argument("--fail-on", choices=["low", "moderate", "high", "critical"])
    sc.add_argument("--state", help="snapshot file used to report drift between scans")
    sc.add_argument("--cache", default=str(Path.home() / ".cache" / "mcp-posture"))
    sc.add_argument("--offline", action="store_true", help="use cached responses only")
    args = ap.parse_args(argv)

    f = Fetcher(Path(args.cache), offline=args.offline)
    servers = discover(Path(args.home), [Path(p) for p in args.project])
    rows = scan(f, servers)
    notes = []
    if args.state:
        sp = Path(args.state)
        if sp.exists():
            notes = drift(json.loads(sp.read_text()), rows)
        sp.write_text(json.dumps({r["id"]: {"config_hash": r["config_hash"], "resolved_version": r["resolved_version"]} for r in rows}, indent=1))
    if args.json:
        print(json.dumps({"servers": rows, "drift": notes}, indent=1))
    else:
        print(render(rows, notes))
    if args.fail_on:
        floor = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER.get(r["max_severity"] or "", 0) >= floor for r in rows):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
