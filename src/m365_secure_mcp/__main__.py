"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .config import Settings
from .diagnostics import doctor_report, permission_report
from .discovery import DISCOVERY_KINDS, discover_resources
from .policy_file import export_private_policy, load_private_policy
from .security import PrivateStateError
from .server import create_server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-secure-mcp",
        description="Secure-by-default Microsoft 365 MCP server",
    )
    parser.add_argument(
        "--policy-file",
        type=str,
        help=(
            "load all M365 settings from an owner-only JSON policy file instead "
            "of environment variables"
        ),
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
        help="print the operator-only effective policy and its stable digest",
    )
    actions.add_argument(
        "--export-policy",
        metavar="PATH",
        help=(
            "create a new owner-only JSON policy from the validated environment; "
            "existing files are never overwritten"
        ),
    )
    actions.add_argument(
        "--discover-resources",
        nargs="+",
        choices=sorted(DISCOVERY_KINDS),
        metavar="KIND",
        help=(
            "read-only operator discovery for selected M365/Entra resources; "
            "never changes the active allowlists"
        ),
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.policy_file:
            settings = load_private_policy(Path(args.policy_file))
        else:
            settings = Settings()  # type: ignore[call-arg]  # Loaded from the environment.
    except (ValidationError, PrivateStateError) as exc:
        print(f"Configuration error:\n{exc}", file=sys.stderr)
        raise SystemExit(2) from None

    if args.export_policy:
        if args.policy_file:
            print(
                "Configuration error:\n"
                "--export-policy cannot be combined with --policy-file",
                file=sys.stderr,
            )
            raise SystemExit(2)
        try:
            output_path = Path(args.export_policy).expanduser()
            export_private_policy(settings, output_path)
        except PrivateStateError as exc:
            print(f"Configuration error:\n{exc}", file=sys.stderr)
            raise SystemExit(2) from None
        print(
            json.dumps(
                {
                    "status": "created",
                    "path": str(output_path),
                    "policy_digest": settings.policy_digest,
                    "contains_tokens_or_client_secret": False,
                },
                indent=2,
            )
        )
        return
    if args.discover_resources:
        report = asyncio.run(
            discover_resources(
                settings,
                frozenset(args.discover_resources),
            )
        )
        print(json.dumps(report, indent=2))
        return

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
