#!/usr/bin/env python3
"""
Add an admin to AgentDNA Dashboard.
Directly inserts into the DB and registers with the agent admin server.

Usage: python3 scripts/add_admin.py

Dependencies: pip install requests psycopg2-binary
"""

import uuid
import requests
import psycopg2

# ── Fill in these details ─────────────────────────────────────────────────────
USERNAME    = "admin"
EMAIL       = "admin@yourorg.com"
PASSWORD    = "YourStrongPassword123!"
ORG_ID      = "your-org-id"

DATABASE_URL        = "postgresql://user:password@localhost:5435/dbname"
ADMIN_SERVER_URL    = "http://localhost:8080/"   # CREATE_AGENT_ENDPOINT value
# ─────────────────────────────────────────────────────────────────────────────


def register_with_admin_server() -> str:
    """Call the agent admin server to register the admin and get a DID."""
    url = ADMIN_SERVER_URL.rstrip("/") + "/agent-admin/v1/register-admin"
    payload = {
        "username": USERNAME,
        "org":      ORG_ID,
        "email":    EMAIL,
        "password": PASSWORD,
    }
    res = requests.post(url, json=payload)
    data = res.json()
    if not data.get("status"):
        raise SystemExit(f"Admin server registration failed: {data.get('message')}")
    did = data.get("message", "")
    if not did:
        raise SystemExit(f"No DID returned from admin server: {data}")
    return did


def save_to_db(did: str):
    """Insert the admin record directly into new_admins."""
    api_key       = str(uuid.uuid4())

    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO new_admins (did, organization_id, api_key, email)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (did) DO NOTHING
            """, (did, ORG_ID, api_key, EMAIL))
        conn.commit()
    finally:
        conn.close()

    return api_key


def main():
    print(f"Registering admin '{USERNAME}' ({EMAIL}) for org '{ORG_ID}' ...")

    print("  [1/2] Calling agent admin server ...")
    did = register_with_admin_server()
    print(f"        DID: {did}")

    print("  [2/2] Saving to database ...")
    api_key = save_to_db(did)

    print("Done!")
    print(f"  Username : {USERNAME}")
    print(f"  Email    : {EMAIL}")
    print(f"  Org ID   : {ORG_ID}")
    print(f"  DID      : {did}")
    print(f"  API Key  : {api_key}")


if __name__ == "__main__":
    main()
