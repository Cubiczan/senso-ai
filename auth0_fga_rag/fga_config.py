"""Auth0 FGA configuration for Privacy-Aware RAG Bot."""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Auth0 FGA connection settings
# ---------------------------------------------------------------------------
AUTH0_FGA_API_URL: str = os.environ.get(
    "AUTH0_FGA_API_URL", "https://api.us.auth0.com"
)
AUTH0_FGA_API_TOKEN: str = os.environ.get("AUTH0_FGA_API_TOKEN", "")
AUTH0_FGA_STORE_ID: str = os.environ.get("AUTH0_FGA_STORE_ID", "")

# When no API token is configured the client falls back to an in-memory
# simulation so that the demo runs without external dependencies.
SIMULATED_MODE: bool = not bool(AUTH0_FGA_API_TOKEN)

# ---------------------------------------------------------------------------
# Authorization model relation constants
# ---------------------------------------------------------------------------
RELATION_TYPE_READER: str = "reader"
RELATION_TYPE_EDITOR: str = "editor"
RELATION_TYPE_OWNER: str = "owner"
RELATION_TYPE_MANAGER: str = "manager"

# ---------------------------------------------------------------------------
# Auth0 tenant metadata ( informational only )
# ---------------------------------------------------------------------------
AUTH0_DOMAIN: str = "dev-c3wp4h1e4gv0t64i.us.auth0.com"
