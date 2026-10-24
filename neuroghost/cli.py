"""Command line: `neuroghost serve | demo | eval`."""

from __future__ import annotations

import argparse
import logging
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="neuroghost")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the firewall server and dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--config", default=None, help="folder with settings.json and directive_rules.json")

    d = sub.add_parser("demo", help="run the attack demo (unguarded vs guarded)")
    d.add_argument("--server", default=None, help="use a running server, e.g. http://127.0.0.1:8000")

    sub.add_parser("eval", help="score the fixture set and print catch rate, false alarms and latency")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.cmd == "serve":
        if args.config:
            os.environ["NEUROGHOST_CONFIG_DIR"] = args.config
        import uvicorn
        uvicorn.run("neuroghost.server:app", host=args.host, port=args.port)
        return 0
    if args.cmd == "demo":
        from demo.run_attack_simulation import main as demo_main
        return demo_main(["--server", args.server] if args.server else [])
    if args.cmd == "eval":
        from scripts.evaluate import main as eval_main
        return eval_main([])
    return 1


if __name__ == "__main__":
    sys.exit(main())
