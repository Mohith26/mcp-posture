import hashlib
import json
from pathlib import Path

import pytest

from mcp_posture import cli
from mcp_posture.inventory import decode_launcher, discover
from mcp_posture.posture import OSV_BATCH, OSV_VULN, assess, npm_targets, sample
from mcp_posture.sources import DEPSDEV, NPM, Fetcher
from mcp_posture.summarize import summarize

# ---------- launcher decoding ----------

@pytest.mark.parametrize("command,args,expected", [
    ("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], ("npm", "@modelcontextprotocol/server-filesystem", None)),
    ("npx", ["-y", "mcp-remote@0.1.15", "https://x"], ("npm", "mcp-remote", "0.1.15")),
    ("npx", ["@scope/pkg@^1.2.0"], ("npm", "@scope/pkg", "^1.2.0")),
    ("npx", ["-y", "--package=@a/b@2.0.0", "b-bin"], ("npm", "@a/b", "2.0.0")),
    ("/usr/local/bin/npx", ["-p", "tool@1.0.0", "run"], ("npm", "tool", "1.0.0")),
    ("bunx", ["some-mcp"], ("npm", "some-mcp", None)),
    ("pnpm", ["dlx", "x-mcp@3.1.4"], ("npm", "x-mcp", "3.1.4")),
    ("uvx", ["mcp-server-git"], ("pypi", "mcp-server-git", None)),
    ("uvx", ["--from", "mcp-server-fetch==2025.4.7", "mcp-server-fetch"], ("pypi", "mcp-server-fetch", "2025.4.7")),
    ("uv", ["tool", "run", "Awesome_Pkg==1.0.0"], ("pypi", "awesome_pkg", "1.0.0")),
    ("pipx", ["run", "mcp-thing"], ("pypi", "mcp-thing", None)),
    ("node", ["/opt/server/index.js"], (None, None, None)),
    ("npx", ["-y", "./local-server"], (None, None, None)),
    ("docker", ["run", "-i", "mcp/github"], (None, None, None)),
])
def test_decode_launcher(command, args, expected):
    assert decode_launcher(command, args) == expected


def test_discover_reads_client_configs(tmp_path):
    home, proj = tmp_path / "home", tmp_path / "proj"
    (home / ".cursor").mkdir(parents=True)
    (proj / ".vscode").mkdir(parents=True)
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21"]}},
        "projects": {"/work/app": {"mcpServers": {"remote": {"type": "http", "url": "https://mcp.example.com/mcp"}}}},
    }))
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}))
    (proj / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"local": {"command": "node", "args": ["srv.js"]}}}))
    (proj / ".mcp.json").write_text("{not json")  # broken configs are skipped, not fatal

    found = {(s.client, s.name): s for s in discover(home, [proj])}
    assert set(found) == {("claude-code", "fs"), ("claude-code", "remote"), ("cursor", "git"), ("vscode", "local")}
    assert found[("claude-code", "fs")].pinned
    assert found[("claude-code", "remote")].transport == "http"
    assert found[("claude-code", "remote")].project == "/work/app"
    assert not found[("cursor", "git")].pinned
    assert found[("vscode", "local")].package is None


# ---------- offline fixtures through the real cache format ----------

def seed(cache: Path, url: str, body, post: dict | None = None):
    key = url if post is None else url + "\n" + json.dumps(post, sort_keys=True)
    cache.mkdir(parents=True, exist_ok=True)
    (cache / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")).write_text(json.dumps({"url": url, "body": body}))


def seed_world(cache: Path):
    seed(cache, f"{DEPSDEV}/systems/npm/packages/demo-mcp/versions/1.0.0:dependencies", {"nodes": [
        {"versionKey": {"name": "demo-mcp", "version": "1.0.0"}, "relation": "SELF"},
        {"versionKey": {"name": "zod", "version": "3.25.76"}, "relation": "DIRECT"},
        {"versionKey": {"name": "@modelcontextprotocol/sdk", "version": "1.32.2"}, "relation": "DIRECT"},
        {"versionKey": {"name": "zod", "version": "3.25.76"}, "relation": "INDIRECT"},
    ]})
    seed(cache, f"{NPM}/demo-mcp/1.0.0", {"name": "demo-mcp", "scripts": {"postinstall": "node setup.js", "test": "jest"}})
    pairs = sorted({("@modelcontextprotocol/sdk", "1.32.2"), ("demo-mcp", "1.0.0"), ("zod", "3.25.76")})
    seed(cache, OSV_BATCH, {"results": [{} if n != "zod" else {"vulns": [{"id": "GHSA-test-zod"}]} for n, _ in pairs]},
         post={"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in pairs]})
    seed(cache, OSV_VULN + "GHSA-test-zod", {"id": "GHSA-test-zod", "database_specific": {"severity": "HIGH"}})
    seed(cache, f"{NPM}/demo-mcp/latest", {"version": "1.0.0"})


def test_assess_offline(tmp_path):
    seed_world(tmp_path)
    f = Fetcher(tmp_path, offline=True)
    [p] = assess(f, [("demo-mcp", "1.0.0")])
    assert p.resolved and len(p.nodes) == 4
    assert p.install_scripts == ["postinstall"]
    # an advisory on a package@version is reported once, with its first (closest) relation
    assert [(x[0], x[2], x[3], x[4]) for x in p.findings] == [("zod", "DIRECT", "GHSA-test-zod", "HIGH")]
    assert p.max_severity == "HIGH"
    assert p.vulnerable("HIGH", ("DIRECT",))
    assert not p.vulnerable("CRITICAL")
    assert p.sdk_versions() == ["1.32.2"] and p.sdk_advisories() == []


def test_unindexed_package_is_unresolved_not_clean(tmp_path):
    seed(tmp_path, f"{DEPSDEV}/systems/npm/packages/ghost/versions/0.0.1:dependencies", None)
    seed(tmp_path, f"{NPM}/ghost/0.0.1", None)
    [p] = assess(Fetcher(tmp_path, offline=True), [("ghost", "0.0.1")])
    assert not p.resolved and p.findings == [] and p.install_scripts == []


def test_cli_scan_offline_flags_and_drift(tmp_path, capsys):
    cache = tmp_path / "cache"
    seed_world(cache)
    home = tmp_path / "home"
    home.mkdir()
    cfg = {"mcpServers": {"demo": {"command": "npx", "args": ["-y", "demo-mcp"]},
                          "insecure": {"type": "sse", "url": "http://mcp.example.com/sse"}}}
    (home / ".claude.json").write_text(json.dumps(cfg))
    state = tmp_path / "state.json"
    base = ["scan", "--home", str(home), "--cache", str(cache), "--offline", "--state", str(state)]

    assert cli.main(base + ["--json", "--fail-on", "high"]) == 2
    out = json.loads(capsys.readouterr().out)
    rows = {r["name"]: r for r in out["servers"]}
    assert rows["demo"]["resolved_version"] == "1.0.0"
    assert set(rows["demo"]["flags"]) == {"UNPINNED", "INSTALL-SCRIPTS", "VULN-HIGH"}
    assert rows["insecure"]["flags"] == ["PLAINTEXT-REMOTE"]
    assert out["drift"] == []

    # pin the package and drop the remote: drift reports both changes
    cfg["mcpServers"] = {"demo": {"command": "npx", "args": ["-y", "demo-mcp@1.0.0"]}}
    (home / ".claude.json").write_text(json.dumps(cfg))
    assert cli.main(base + ["--fail-on", "critical"]) == 0
    text = capsys.readouterr().out
    assert "CHANGED-CONFIG claude-code:-:demo" in text
    assert "REMOVED claude-code:-:insecure" in text
    assert "HIGH     GHSA-test-zod in zod@3.25.76 (direct)" in text


def test_npm_targets_and_sample_are_deterministic():
    servers = [
        {"packages": [{"registryType": "npm", "identifier": "a", "version": "1.0.0"}]},
        {"packages": [{"registryType": "npm", "identifier": "a", "version": "1.0.0"}]},
        {"packages": [{"registryType": "npm", "identifier": "b", "version": "latest"}]},
        {"packages": [{"registryType": "pypi", "identifier": "c", "version": "1"}]},
        {"remotes": [{"type": "streamable-http", "url": "https://x"}]},
    ]
    assert npm_targets(servers) == [("a", "1.0.0")]
    items = [(f"p{i}", "1") for i in range(50)]
    assert sample(items, 10) == sample(list(reversed(items)), 10)


def test_summarize_counts():
    rows = [
        {"resolved": True, "nodes": 10, "install_scripts": [], "sdk_versions": ["1.32.2"],
         "findings": [["zod", "3.25.76", "DIRECT", "GHSA-z", "HIGH"]]},
        {"resolved": True, "nodes": 20, "install_scripts": ["postinstall"], "sdk_versions": [],
         "findings": [["x", "1", "INDIRECT", "GHSA-x", "CRITICAL"], ["zod", "3.25.76", "DIRECT", "GHSA-z", "HIGH"]]},
        {"resolved": False, "nodes": 0, "install_scripts": [], "sdk_versions": [], "findings": []},
    ]
    s = summarize(rows)
    assert s["resolved"] == 2 and s["any"] == 2 and s["high_plus"] == 2 and s["critical"] == 1
    assert s["direct_or_self_high_plus"] == 2 and s["install_scripts"] == 1
    assert s["top_advisories"][0][:2] == ("zod", "GHSA-z")
    assert s["high_plus_without_top"] == 1
