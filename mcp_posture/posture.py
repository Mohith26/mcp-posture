"""Posture checks for one npm-distributed MCP server: resolved dependency graph,
known advisories (OSV) anywhere in it, and install-time scripts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .sources import Fetcher, depsdev_dependencies, npm_version_manifest

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
SEVERITY_ORDER = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
MCP_SDK = "@modelcontextprotocol/sdk"


@dataclass
class Node:
    name: str
    version: str
    relation: str  # SELF, DIRECT, INDIRECT


@dataclass
class PackagePosture:
    package: str
    version: str
    resolved: bool = False
    nodes: list[Node] = field(default_factory=list)
    install_scripts: list[str] = field(default_factory=list)
    # (dep name, dep version, relation, advisory id, severity)
    findings: list[tuple[str, str, str, str, str]] = field(default_factory=list)

    @property
    def max_severity(self) -> str | None:
        best = None
        for *_, sev in self.findings:
            if best is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(best, 0):
                best = sev
        return best

    def vulnerable(self, min_severity: str = "LOW", relations: tuple[str, ...] = ("SELF", "DIRECT", "INDIRECT")) -> bool:
        floor = SEVERITY_ORDER[min_severity]
        return any(SEVERITY_ORDER.get(sev, 0) >= floor and rel in relations for _, _, rel, _, sev in self.findings)

    def sdk_versions(self) -> list[str]:
        return sorted({n.version for n in self.nodes if n.name == MCP_SDK})

    def sdk_advisories(self) -> list[str]:
        return sorted({adv for name, _, _, adv, _ in self.findings if name == MCP_SDK})


def resolve_graph(f: Fetcher, name: str, version: str) -> list[Node] | None:
    graph = depsdev_dependencies(f, "npm", name, version)
    if not graph or not graph.get("nodes"):
        return None
    nodes = []
    for n in graph["nodes"]:
        vk = n.get("versionKey") or {}
        if vk.get("name") and vk.get("version"):
            nodes.append(Node(vk["name"], vk["version"], n.get("relation", "INDIRECT")))
    return nodes


def install_scripts(f: Fetcher, name: str, version: str) -> list[str]:
    manifest = npm_version_manifest(f, name, version) or {}
    scripts = manifest.get("scripts") or {}
    return [h for h in INSTALL_HOOKS if isinstance(scripts.get(h), str) and scripts[h].strip()]


def osv_batch(f: Fetcher, pairs: list[tuple[str, str]], ecosystem: str = "npm") -> dict[tuple[str, str], list[str]]:
    """Advisory ids per (name, version), via OSV querybatch. Cached per chunk."""
    out: dict[tuple[str, str], list[str]] = {}
    pairs = sorted(set(pairs))
    for i in range(0, len(pairs), 1000):
        chunk = pairs[i:i + 1000]
        body = {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk]}
        res = f.post_json(OSV_BATCH, body)
        for (n, v), r in zip(chunk, res.get("results", [])):
            out[(n, v)] = [x["id"] for x in (r or {}).get("vulns", [])]
    return out


def advisory_severity(f: Fetcher, adv_id: str) -> str:
    vuln = f.get_json(OSV_VULN + adv_id) or {}
    sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(sev, str) and sev.upper() in SEVERITY_ORDER:
        return "MODERATE" if sev.upper() == "MEDIUM" else sev.upper()
    return "UNKNOWN"


def assess(f: Fetcher, packages: list[tuple[str, str]], with_scripts: bool = True) -> list[PackagePosture]:
    postures = []
    for name, version in packages:
        p = PackagePosture(name, version)
        nodes = resolve_graph(f, name, version)
        if nodes is not None:
            p.resolved = True
            p.nodes = nodes
        if with_scripts:
            p.install_scripts = install_scripts(f, name, version)
        postures.append(p)
    pairs = [(n.name, n.version) for p in postures for n in p.nodes]
    ids = osv_batch(f, pairs) if pairs else {}
    sev_cache: dict[str, str] = {}
    for p in postures:
        seen = set()
        for n in p.nodes:
            for adv in ids.get((n.name, n.version), []):
                key = (n.name, n.version, adv)
                if key in seen:
                    continue
                seen.add(key)
                if adv not in sev_cache:
                    sev_cache[adv] = advisory_severity(f, adv)
                p.findings.append((n.name, n.version, n.relation, adv, sev_cache[adv]))
    return postures


def sample(items: list[tuple[str, str]], n: int, seed: str = "mcp-posture") -> list[tuple[str, str]]:
    """Deterministic sample: order by a salted hash of the package name."""
    keyed = sorted(items, key=lambda it: hashlib.sha256((seed + it[0]).encode()).hexdigest())
    return keyed[:n]


def npm_targets(servers: list[dict]) -> list[tuple[str, str]]:
    """Distinct (package, version) for npm stdio packages with a concrete version."""
    out = set()
    for s in servers:
        for pkg in s.get("packages") or []:
            if pkg.get("registryType") != "npm":
                continue
            ident, ver = pkg.get("identifier"), pkg.get("version")
            if not ident or not ver or ver in ("latest", "*"):
                continue
            out.add((ident, ver))
    # one version per package (registry entries can repeat a package across servers)
    by_pkg: dict[str, str] = {}
    for ident, ver in sorted(out):
        by_pkg.setdefault(ident, ver)
    return sorted(by_pkg.items())


def to_json(p: PackagePosture) -> dict:
    return {
        "package": p.package, "version": p.version, "resolved": p.resolved,
        "nodes": len(p.nodes), "install_scripts": p.install_scripts,
        "max_severity": p.max_severity, "sdk_versions": p.sdk_versions(),
        "findings": [list(x) for x in p.findings],
    }


def dumps(postures: list[PackagePosture]) -> str:
    return "\n".join(json.dumps(to_json(p)) for p in postures)
