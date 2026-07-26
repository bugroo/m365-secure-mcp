"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from pydantic import ValidationError

from .config import Settings
from .diagnostics import doctor_report, permission_report
from .server import create_server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-secure-mcp",
        description="Secure-by-default Microsoft 365 MCP server",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--check-config",
        action="store_true",
        help="validate environment configuration and print a secret-free summary",
    )
    actions.add_argument(
        "--list-tools",
        action="store_true",
        help="validate configuration and list the exposed tools without signing in",
    )
    actions.add_argument(
        "--doctor",
        nargs="?",
        choices=("offline", "live"),
        const="offline",
        help="audit the effective deployment; use '--doctor live' for a read-only Graph check",
    )
    actions.add_argument(
        "--explain-permissions",
        action="store_true",
        help="print the exact delegated scopes and the module or action requiring each one",
    )
    actions.add_argument(
        "--print-policy",
        action="store_true",
        help="print the effective secret-free policy and its stable digest",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        settings = Settings()  # type: ignore[call-arg]  # Loaded from the environment.
    except ValidationError as exc:
        print(f"Configuration error:\n{exc}", file=sys.stderr)
        raise SystemExit(2) from None

    if args.check_config:
        print(json.dumps(settings.public_summary(), indent=2))
        return
    if args.explain_permissions:
        print(json.dumps(asyncio.run(permission_report(settings)), indent=2))
        return
    if args.print_policy:
        print(
            json.dumps(
                {
                    **settings.public_summary(),
                    "policy_digest": settings.policy_digest,
                },
                indent=2,
            )
        )
        return
    if args.doctor:
        report = asyncio.run(doctor_report(settings, live=args.doctor == "live"))
        print(json.dumps(report, indent=2))
        if report["overall"] != "pass":
            raise SystemExit(1)
        return

    server = create_server(settings)
    if args.list_tools:
        for tool in asyncio.run(server.list_tools()):
            print(tool.name)
        return
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
