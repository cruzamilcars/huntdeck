"""Service API key management CLI.

Generate, list and revoke service API keys for the API. Keys are stored
hashed (SHA-256) in the local durable store; the plaintext is printed exactly
once at creation time.

Usage:
    python -m app.cli apikey create --name ci-bot --org o1
    python -m app.cli apikey list
    python -m app.cli apikey revoke --id 1
"""

import argparse
import secrets
import sys

from app.core.config import get_settings
from app.core.security import hash_api_key
from app.infrastructure.store import SqliteStore


def _store() -> SqliteStore:
    return SqliteStore(get_settings().database_path)


def cmd_create(args: argparse.Namespace) -> int:
    store = _store()
    plaintext = "hd_" + secrets.token_urlsafe(32)
    key_id = store.create_api_key(args.name, args.org, hash_api_key(plaintext))
    print(f"Created API key #{key_id} for org '{args.org}'.")
    print(f"Key (shown once): {plaintext}")
    print("Use it as:  X-API-Key: <key>")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = _store()
    rows = store.list_api_keys()
    if not rows:
        print("No API keys.")
        return 0
    for row in rows:
        state = "enabled" if row["enabled"] else "revoked"
        print(
            f"#{row['id']} {row['name']} org={row['org_id']} [{state}] created={row['created_at']}"
        )
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    store = _store()
    if store.revoke_api_key(args.id):
        print(f"Revoked API key #{args.id}.")
        return 0
    print(f"API key #{args.id} not found or already revoked.", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="huntdeck", description="HuntDeck API tooling")
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_parser = subparsers.add_parser("apikey", help="manage service API keys")
    key_subparsers = key_parser.add_subparsers(dest="action", required=True)

    create_parser = key_subparsers.add_parser("create", help="create a new service API key")
    create_parser.add_argument("--name", required=True, help="key label, e.g. ci-bot")
    create_parser.add_argument("--org", default="dev-org", help="org id the key is bound to")
    create_parser.set_defaults(handler=cmd_create)

    key_subparsers.add_parser("list", help="list service API keys").set_defaults(handler=cmd_list)

    revoke_parser = key_subparsers.add_parser("revoke", help="revoke a service API key")
    revoke_parser.add_argument("--id", required=True, type=int, help="key id from 'apikey list'")
    revoke_parser.set_defaults(handler=cmd_revoke)

    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
