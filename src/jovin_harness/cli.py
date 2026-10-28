"""Command line: serve the MCP tools, prepare and check the sandbox, run checks by hand, inspect receipts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError
from .receipts import ReceiptError
from .sandbox import SandboxUnavailable
from .tools import Harness, ToolError


def _print(value) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="jovin-harness", description=__doc__)
    root.add_argument("--version", action="version", version=f"jovin-harness {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="serve the MCP tools (stdio by default)")
    serve.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--auth", choices=("bearer", "path-secret"), default="bearer",
                       help="bearer: clients send the token header; path-secret: the URL itself is the credential")
    serve.add_argument("--allowed-host", action="append", default=[], metavar="HOST",
                       help="public Host header to accept, for example when behind a tunnel (repeatable)")
    serve.add_argument("--allow-remote", action="store_true", help="permit binding to a non-loopback address")

    doctor = commands.add_parser("doctor", help="check that the sandbox is ready; nothing is executed")
    doctor.add_argument("--sweep", action="store_true", help="also remove containers left by earlier runs")

    image = commands.add_parser("image", help="manage the sandbox image")
    image.add_subparsers(dest="image_command", required=True).add_parser(
        "build", help="build the sandbox image locally and pin its ID")

    verify = commands.add_parser("verify", help="verify a code file against a tests file")
    verify.add_argument("code")
    verify.add_argument("--tests", required=True)
    verify.add_argument("--timeout", type=int)
    verify.add_argument("--isolation", choices=("process", "shared"), default="process",
                        help="process: tests and code in separate processes (default); shared: one process")

    run = commands.add_parser("run", help="run a Python file in the sandbox")
    run.add_argument("code")
    run.add_argument("--stdin", help="file whose contents are passed on standard input")
    run.add_argument("--timeout", type=int)

    receipts = commands.add_parser("receipts", help="inspect the receipt chain")
    which = receipts.add_subparsers(dest="receipts_command", required=True)
    which.add_parser("head", help="print the chain head (export it somewhere you trust)")
    which.add_parser("checkpoint", help="print the signed head checkpoint (signed stores only)")
    check = which.add_parser("verify", help="verify one receipt, or the whole chain")
    check.add_argument("receipt_id", nargs="?")
    show = which.add_parser("show", help="print a receipt")
    show.add_argument("receipt_id")

    token = commands.add_parser("http-token", help="print the HTTP credential (creating it if needed)")
    token.add_argument("--path-secret", action="store_true", help="print the path-secret URL path instead")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        harness = Harness.from_environment()
        if args.command == "serve":
            from .server import serve_http, serve_stdio

            if args.transport == "stdio":
                serve_stdio(harness)
            else:
                serve_http(harness, host=args.host, port=args.port, auth=args.auth,
                           allowed_hosts=args.allowed_host, allow_remote=args.allow_remote)
            return 0
        if args.command == "doctor":
            report = harness.sandbox_status()
            if args.sweep:
                sweep = harness.sandbox.sweep()
                report.update(swept=sweep["swept"], sweep_skipped=sweep["skipped"], sweep_failed=sweep["failed"])
                if sweep["skipped"] or sweep["failed"]:
                    report["ready"] = False
            _print(report)
            return 0 if report["ready"] else 1
        if args.command == "image":
            image = harness.sandbox.build_image()
            _print({"image": image, "pinned_in": str(harness.settings.config_file)})
            return 0
        if args.command == "verify":
            result = harness.verify_python(_read(args.code), _read(args.tests), args.timeout, args.isolation)
            _print(result)
            return 0 if result["passed"] else 1
        if args.command == "run":
            stdin = _read(args.stdin) if args.stdin else None
            result = harness.run_python(_read(args.code), stdin, args.timeout)
            _print(result)
            return 0 if result["status"] == "completed" and result["exit_code"] == 0 else 1
        if args.command == "receipts":
            if args.receipts_command == "head":
                _print(harness.store.head())
                return 0
            if args.receipts_command == "checkpoint":
                _print(harness.store.checkpoint())
                return 0
            if args.receipts_command == "show":
                _print(harness.get_receipt(args.receipt_id))
                return 0
            report = (harness.verify_receipt(receipt_id=args.receipt_id) if args.receipt_id
                      else harness.store.verify_chain())
            _print(report)
            return 0 if report["valid"] else 1
        if args.command == "http-token":
            from .server import http_token, path_secret

            print(f"/mcp/{path_secret(harness)}" if args.path_secret else http_token(harness))
            return 0
    except (ConfigError, ToolError, SandboxUnavailable, ReceiptError, OSError, ValueError) as error:
        print(f"jovin-harness: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
