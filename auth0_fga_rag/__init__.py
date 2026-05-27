"""
Auth0 FGA Privacy-Aware RAG Bot for Senso.AI

Provides fine-grained authorization for Retrieval-Augmented Generation,
ensuring document-level access control based on user role and department.

Modules:
    fga_config          — Auth0 FGA configuration and constants
    authorization_model — FGA authorization model definition and validation
    fga_client          — Auth0 FGA API client (with simulated fallback)
    document_store      — Document database with FGA-filtered search
    rag_engine          — RAG engine with authorization-aware retrieval
    demo                — Comprehensive demonstration script
"""

from auth0_fga_rag.fga_config import (
    AUTH0_FGA_API_URL,
    AUTH0_FGA_API_TOKEN,
    AUTH0_FGA_STORE_ID,
    RELATION_TYPE_READER,
    RELATION_TYPE_EDITOR,
    RELATION_TYPE_OWNER,
    RELATION_TYPE_MANAGER,
)

__version__ = "1.0.0"
__all__ = [
    "AUTH0_FGA_API_URL",
    "AUTH0_FGA_API_TOKEN",
    "AUTH0_FGA_STORE_ID",
    "RELATION_TYPE_READER",
    "RELATION_TYPE_EDITOR",
    "RELATION_TYPE_OWNER",
    "RELATION_TYPE_MANAGER",
]
