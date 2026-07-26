"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys

from pydantic import ValidationError

from .config import Settings
from .server import create_server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-secure-mcp",
        description="Secure-by-default Microsoft 365 MCP server",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate environment configuration and print a secret-free summary",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="validate configuration and list the exposed tools without signing in",
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
        import json

        print(json.dumps(settings.public_summary(), indent=2))
        return

    server = create_server(settings)
    if args.list_tools:
        for tool in asyncio.run(server.list_tools()):
            print(tool.name)
        return
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
