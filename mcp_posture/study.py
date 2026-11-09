"""Measure the dependency posture of npm-distributed servers in the official MCP Registry.

    python -m mcp_posture.study --sample 1000 --out results/registry_npm_sample.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .posture import assess, dumps, npm_targets, sample
from .sources import Fetcher, registry_latest


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="data/cache")
    ap.add_argument("--sample", type=int, default=1000)
    ap.add_argument("--out", required=True)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--chunk", type=int, default=250, help="packages per assess() call")
    args = ap.parse_args(argv)

    f = Fetcher(Path(args.cache), offline=args.offline)
    servers = registry_latest(f)
    targets = npm_targets(servers)
    picked = sample(targets, args.sample)
    meta = {"registry_latest_servers": len(servers), "npm_packages": len(targets), "sampled": len(picked)}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("")
    for i in range(0, len(picked), args.chunk):
        chunk = dumps(assess(f, picked[i:i + args.chunk]))
        with out.open("a") as fh:
            fh.write(chunk + "\n")
        print(f"assessed {min(i + args.chunk, len(picked))}/{len(picked)} (network calls so far {f.network_calls})", flush=True)
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
