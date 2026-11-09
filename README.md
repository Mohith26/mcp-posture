# mcp-posture

A small, read-only tool for two questions about MCP servers:

1. **What MCP servers are configured on this machine, and what will they actually run?** It reads Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI and VS Code configs, decodes `npx` / `bunx` / `pnpm dlx` / `uvx` / `pipx run` launchers into a package and version, flags unpinned launches, npm install hooks, plaintext remote URLs and known advisories anywhere in the resolved dependency graph, and reports drift between scans.
2. **How exposed is the public MCP ecosystem?** A reproducible study of npm-distributed servers in the official MCP Registry.

Nothing is executed. Configs are parsed, and versions and advisories come from public, keyless APIs: the npm registry, PyPI, [deps.dev](https://deps.dev) (dependency resolution) and [OSV](https://osv.dev) (advisories).

## Study: npm servers in the official MCP Registry (snapshot 2026-11-08)

The registry listed 59,754 latest server entries; 15,728 distinct npm packages had a concrete version. I took a deterministic sample of 1,500 (ordered by a salted hash of the package name), resolved each package's dependency graph with deps.dev (1,381 resolved; median graph 99 packages), and matched every package@version in each graph against OSV.

| posture (npm MCP servers, resolved graphs) | count |
|---|---|
| any OSV advisory in the resolved dependency graph | 553/1381 (40.0%, 95% CI 37.5-42.7) |
| HIGH or CRITICAL advisory anywhere in the graph | 536/1381 (38.8%, 95% CI 36.3-41.4) |
| CRITICAL advisory anywhere in the graph | 8/1381 (0.6%, 95% CI 0.3-1.1) |
| HIGH/CRITICAL in the package itself or a direct dependency | 507/1381 (36.7%, 95% CI 34.2-39.3) |
| depends on @modelcontextprotocol/sdk | 957/1381 (69.3%) |
| resolved @modelcontextprotocol/sdk version has an advisory | 36/1381 (2.6%) |
| package runs an npm install hook (pre/post/install) | 39/1500 (2.6%) |
| HIGH/CRITICAL left if the single most common advisory were fixed | 89/1381 (6.4%, 95% CI 5.3-7.9) |

| most common advisories | severity | servers |
|---|---|---|
| zod GHSA-mrhx-c7xc-m3w5 (CVE-2023-54404) | HIGH | 504 |
| @modelcontextprotocol/sdk GHSA-6prh-2h8m-c8cw | MODERATE | 36 |
| @modelcontextprotocol/sdk GHSA-46jr-4wx8-v453 | HIGH | 30 |
| @modelcontextprotocol/sdk GHSA-rvq5-wwqv-78pq | MODERATE | 30 |
| @modelcontextprotocol/sdk GHSA-f897-62hf-6gxq | HIGH | 29 |

**What stands out:** almost all of the HIGH-severity exposure is one advisory. GHSA-mrhx-c7xc-m3w5 (Zod can exhaust memory while validating oversized arrays without a length constraint; published 2026-10-01, GitHub-reviewed 2026-10-23) affects every Zod release before 4.6.6, so there is no fixed 3.x version. 481 of the 504 affected servers resolve `zod@3.25.76` (the last 3.x release), 458 of them as a direct dependency, and 454 of those 481 also resolve the current SDK (1.32.2), so the SDK being up to date does not help. Clearing it takes a Zod 4 migration, not a patch bump, which is why it will likely linger. Without it, the HIGH/CRITICAL rate drops from 38.8% to 6.4%. Zod is what MCP servers typically use to describe tool inputs, so whether a given server is actually affected depends on whether it validates model- or user-supplied arrays without a maximum length. I did not test exploitability of any server.

### What this is and is not
- Dependency resolution is deps.dev's, done at query time, so it approximates what a fresh `npx -y <server>` install would pull today, not what any particular user has installed.
- An advisory in the graph is exposure, not proof the vulnerable code path is reachable.
- npm only for the study (PyPI, OCI and remote servers are not covered); the 119 packages deps.dev could not resolve are excluded from the percentages, not counted as clean.
- One snapshot, one sample of 1,500. Per-package records are in `results/registry_npm_sample1500.jsonl`.

## Scanning your own machine

```bash
python3 -m mcp_posture.cli scan                          # configs under $HOME
python3 -m mcp_posture.cli scan --project . --json       # also ./.mcp.json, ./.vscode/mcp.json
python3 -m mcp_posture.cli scan --fail-on high           # exit 2 on HIGH/CRITICAL, for CI
python3 -m mcp_posture.cli scan --state ~/.mcp-posture.json   # report ADDED/REMOVED/CHANGED-CONFIG/VERSION drift
```

On the example config in `examples/home` (a few common servers), the scan finds the mcp-remote command-injection advisory (CVE-2025-6514) on a pinned `mcp-remote@0.1.15`, and flags the unpinned `npx -y` / `uvx` launches whose version can change under you (`examples/scan_output.txt`).

Flags: `UNPINNED` (package launched without an exact version), `INSTALL-SCRIPTS`, `VULN-<severity>`, `PLAINTEXT-REMOTE` (http:// to a non-local host), `LOCAL-COMMAND` (not a package launcher, nothing to resolve), `GRAPH-UNKNOWN` (deps.dev has no graph).

## Reproduce

Python 3.10+, standard library only (pytest for tests).

```bash
python3 -m pytest -q                                              # 20 tests, offline fixtures
python3 -m mcp_posture.study --sample 1500 --out results/registry_npm_sample1500.jsonl   # about 10 minutes, cached
python3 -m mcp_posture.summarize results/registry_npm_sample1500.jsonl
```

Rerunning the study on a later date will give different numbers: the registry, deps.dev's resolution and OSV all move.
