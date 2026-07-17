#!/usr/bin/env python3
"""
Add an admin to AgentDNA Dashboard.
Usage: python3 scripts/add_admin.py
"""

import requests

API_BASE = "http://localhost:9000/dashboard/v1"

# ── Fill in these details ─────────────────────────────────────────────────────
USERNAME = "admin"
EMAIL    = "admin@yourorg.com"
PASSWORD = "YourStrongPassword123!"
ORG_ID   = "your-org-id"
# ─────────────────────────────────────────────────────────────────────────────


def create_admin():
    url = f"{API_BASE}/create-admin"
    payload = {
        "username": USERNAME,
        "email":    EMAIL,
        "password": PASSWORD,
        "orgID":    ORG_ID,
        "otp":      "",
    }
    res = requests.post(url, json=payload)
    data = res.json()

    if not res.ok:
        raise SystemExit(f"create-admin failed: {data}")

    did = data.get("did") or (data.get("data") or {}).get("did", "")
    if not did:
        raise SystemExit(f"No DID in response: {data}")
    return did


def main():
    print(f"Adding admin '{USERNAME}' ({EMAIL}) to org '{ORG_ID}' ...")
    did = create_admin()
    print(f"Done! Admin registered.")
    print(f"  Username : {USERNAME}")
    print(f"  Email    : {EMAIL}")
    print(f"  Org ID   : {ORG_ID}")
    print(f"  DID      : {did}")


if __name__ == "__main__":
    main()
