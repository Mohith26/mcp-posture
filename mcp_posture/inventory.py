"""Find MCP server definitions in local client configs and work out what each one runs.

Read-only: configs are parsed, nothing is launched. Package launchers (npx, bunx,
pnpm dlx, yarn dlx, uvx, pipx run) are decoded into a package spec so the version
that would actually run can be checked.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# (client, path relative to home, key holding the server map)
HOME_CONFIGS = [
    ("claude-code", ".claude.json", "mcpServers"),
    ("claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json", "mcpServers"),
    ("claude-desktop", ".config/Claude/claude_desktop_config.json", "mcpServers"),
    ("cursor", ".cursor/mcp.json", "mcpServers"),
    ("windsurf", ".codeium/windsurf/mcp_config.json", "mcpServers"),
    ("gemini-cli", ".gemini/settings.json", "mcpServers"),
]
PROJECT_CONFIGS = [
    ("claude-code", ".mcp.json", "mcpServers"),
    ("cursor", ".cursor/mcp.json", "mcpServers"),
    ("vscode", ".vscode/mcp.json", "servers"),
]

_NPM_SPEC = re.compile(r"^(?P<name>@[^/@\s]+/[^@\s]+|[^@/\s][^@\s]*)(?:@(?P<ver>[^\s]+))?$")
_PY_SPEC = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:==(?P<ver>[^\s;]+))?$")
_EXACT = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")


@dataclass
class ServerDef:
    client: str
    config: str
    name: str
    transport: str  # stdio, http, sse
    command: str = ""
    args: list[str] = field(default_factory=list)
    url: str = ""
    ecosystem: str | None = None  # npm, pypi
    package: str | None = None
    requested: str | None = None  # version or range as written, None if absent
    project: str | None = None  # project path for per-project entries in ~/.claude.json

    @property
    def pinned(self) -> bool:
        return bool(self.requested and _EXACT.match(self.requested))

    def key(self) -> tuple:
        return (self.transport, self.command, tuple(self.args), self.url)


def _first_non_flag(args: list[str], skip_values: tuple[str, ...] = ()) -> int | None:
    i = 0
    while i < len(args):
        a = args[i]
        if a in skip_values:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return i
    return None


def decode_launcher(command: str, args: list[str]) -> tuple[str | None, str | None, str | None]:
    """Return (ecosystem, package, requested version) for package-launcher commands."""
    cmd = Path(command).name.lower()
    args = list(args or [])
    if cmd in ("npx", "bunx") or (cmd in ("pnpm", "yarn", "bun") and args[:1] in (["dlx"], ["x"])):
        if cmd in ("pnpm", "yarn", "bun"):
            args = args[1:]
        # npx -p/--package <spec> <bin> wins over the positional spec
        for i, a in enumerate(args):
            if a in ("-p", "--package") and i + 1 < len(args):
                m = _NPM_SPEC.match(args[i + 1])
                if m:
                    return "npm", m.group("name"), m.group("ver")
            if a.startswith("--package="):
                m = _NPM_SPEC.match(a.split("=", 1)[1])
                if m:
                    return "npm", m.group("name"), m.group("ver")
        i = _first_non_flag(args, skip_values=("--registry", "--cache", "-c", "--call"))
        if i is None:
            return None, None, None
        m = _NPM_SPEC.match(args[i])
        if not m or args[i].startswith((".", "/", "file:", "http:", "https:", "git")):
            return None, None, None
        return "npm", m.group("name"), m.group("ver")
    if cmd == "uvx" or (cmd == "uv" and args[:2] == ["tool", "run"]) or (cmd == "pipx" and args[:1] == ["run"]):
        if cmd == "uv":
            args = args[2:]
        elif cmd == "pipx":
            args = args[1:]
        for i, a in enumerate(args):
            if a == "--from" and i + 1 < len(args):
                m = _PY_SPEC.match(args[i + 1])
                if m:
                    return "pypi", m.group("name").lower(), m.group("ver")
        i = _first_non_flag(args, skip_values=("--python", "--with", "--index-url", "--spec"))
        if i is None:
            return None, None, None
        m = _PY_SPEC.match(args[i])
        if not m:
            return None, None, None
        return "pypi", m.group("name").lower(), m.group("ver")
    return None, None, None


def _servers_from(obj, client: str, config: str, project: str | None = None) -> list[ServerDef]:
    out = []
    if not isinstance(obj, dict):
        return out
    for name, spec in obj.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or ""
        transport = spec.get("type") or ("http" if url else "stdio")
        if transport == "streamable-http":
            transport = "http"
        command = spec.get("command") or ""
        args = [str(a) for a in (spec.get("args") or [])]
        eco, pkg, ver = decode_launcher(command, args) if command else (None, None, None)
        out.append(ServerDef(client, config, name, transport, command, args, url, eco, pkg, ver, project))
    return out


def load_config(path: Path, client: str, key: str) -> list[ServerDef]:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []
    out = _servers_from(data.get(key), client, str(path))
    # Claude Code keeps per-project servers under projects.<path>.mcpServers
    if client == "claude-code" and isinstance(data.get("projects"), dict):
        for proj, pdata in data["projects"].items():
            if isinstance(pdata, dict):
                out.extend(_servers_from(pdata.get("mcpServers"), client, str(path), proj))
    return out


def discover(home: Path, projects: list[Path] = ()) -> list[ServerDef]:
    found = []
    for client, rel, key in HOME_CONFIGS:
        p = Path(home) / rel
        if p.is_file():
            found.extend(load_config(p, client, key))
    for proj in projects:
        for client, rel, key in PROJECT_CONFIGS:
            p = Path(proj) / rel
            if p.is_file():
                found.extend(load_config(p, client, key))
    return found
