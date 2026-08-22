#!/usr/bin/env python3
"""POC-only Coppice activity monitor for a running local Z3 regtest stack."""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def zebra_height(endpoint: str) -> int:
    request = urllib.request.Request(
        endpoint,
        data=b'{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}',
        headers={"content-type": "application/json", "authorization": "Basic emVicmE6emVicmE="},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.load(response)
    if "result" not in payload:
        raise RuntimeError(f"Zebra RPC failure: {payload}")
    return int(payload["result"])


def replay(cli: Path, wallet: Path, zaino: str) -> None:
    command = [
        str(cli),
        "coppice",
        "--wallet-dir",
        str(wallet),
        "watch",
        "--once",
        "--server",
        zaino,
    ]
    completed = subprocess.run(command, text=True, capture_output=True)
    if completed.returncode:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Coppice replay failed: {message}")
    for line in completed.stdout.splitlines():
        if line.startswith("["):
            print(line, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet", type=int, default=1, choices=(1, 2, 3))
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true", help="replay pending blocks once and exit")
    parser.add_argument("--zebra", default="http://127.0.0.1:29232")
    parser.add_argument("--zaino", default="127.0.0.1:28137")
    parser.add_argument(
        "--cli",
        type=Path,
        default=ROOT.parent / "coppice-cli" / "target" / "release" / "coppice-cli",
    )
    parser.add_argument(
        "--state-dir", type=Path, default=ROOT / ".coppice-regtest"
    )
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be positive")
    wallet = args.state_dir / f"wallet-{args.wallet}"
    if not args.cli.is_file():
        parser.error(f"coppice-cli not found: {args.cli}")
    if not (wallet / "keys.toml").is_file():
        parser.error(f"regtest wallet not found: {wallet}; run scripts/regtest-playground.sh start")

    # The Rust watcher owns protocol parsing, candidate detection, memo
    # decryption, and state persistence. Python only polls the local block tip.
    replay(args.cli, wallet, args.zaino)
    last_seen = zebra_height(args.zebra)
    if args.once:
        return 0
    while True:
        time.sleep(args.interval)
        tip = zebra_height(args.zebra)
        if tip <= last_seen:
            continue
        replay(args.cli, wallet, args.zaino)
        last_seen = tip


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, urllib.error.URLError) as error:
        print(f"watch-regtest: {error}", file=sys.stderr)
        raise SystemExit(1)
