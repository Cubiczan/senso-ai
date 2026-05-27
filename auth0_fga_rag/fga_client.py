"""Auth0 FGA Client — wraps Auth0 FGA API with a simulated fallback mode."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import requests

from auth0_fga_rag.fga_config import (
    AUTH0_FGA_API_TOKEN,
    AUTH0_FGA_API_URL,
    AUTH0_FGA_STORE_ID,
    SIMULATED_MODE,
    RELATION_TYPE_READER,
    RELATION_TYPE_EDITOR,
    RELATION_TYPE_OWNER,
    RELATION_TYPE_MANAGER,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationTuple:
    """A single relationship tuple (also called a relationship or assignment).

    Example: ``user:alice is reader of document:budget_Q4``
    """

    user: str
    relation: str
    object: str

    def __str__(self) -> str:
        return f"{self.user} is {self.relation} of {self.object}"


# ---------------------------------------------------------------------------
# FGAClient
# ---------------------------------------------------------------------------


class FGAClient:
    """Client for Auth0 Fine-Grained Authorization.

    When ``AUTH0_FGA_API_TOKEN`` is **not** set the client operates in
    *simulated mode* — all authorization tuples are held in memory and every
    check is evaluated locally.  This lets the demo run without an Auth0
    tenant.
    """

    def __init__(
        self,
        api_url: str = AUTH0_FGA_API_URL,
        api_token: str = AUTH0_FGA_API_TOKEN,
        store_id: str = AUTH0_FGA_STORE_ID,
        simulated: bool | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.store_id = store_id
        self.simulated = simulated if simulated is not None else SIMULATED_MODE

        # In-memory store for simulated mode
        self._tuples: set[AuthorizationTuple] = set()

        if self.simulated:
            logger.info("FGAClient running in SIMULATED mode (no Auth0 API calls)")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, user: str, document: str, relation: str = RELATION_TYPE_READER) -> bool:
        """Return *True* if *user* has *relation* access to *document*.

        In simulated mode this evaluates the in-memory tuple set.
        In live mode it calls the Auth0 FGA ``/check`` endpoint.
        """
        if self.simulated:
            return self._check_simulated(user, document, relation)
        return self._check_api(user, document, relation)

    def list_objects(
        self,
        user: str,
        relation: str = RELATION_TYPE_READER,
        object_type: str = "document",
    ) -> list[str]:
        """List all *object_type* objects that *user* has *relation* to."""
        if self.simulated:
            return self._list_simulated(user, relation, object_type)
        return self._list_api(user, relation, object_type)

    def write_tuples(self, tuples: list[AuthorizationTuple]) -> None:
        """Create / overwrite authorization tuples."""
        if self.simulated:
            self._tuples.update(tuples)
            for t in tuples:
                logger.debug("Wrote tuple: %s", t)
            return
        self._write_api(tuples)

    def delete_tuples(self, tuples: list[AuthorizationTuple]) -> None:
        """Remove authorization tuples."""
        if self.simulated:
            for t in tuples:
                self._tuples.discard(t)
                logger.debug("Deleted tuple: %s", t)
            return
        self._delete_api(tuples)

    def read_tuples(self) -> list[AuthorizationTuple]:
        """Return all tuples currently in the store."""
        if self.simulated:
            return sorted(self._tuples, key=str)
        return self._read_api()

    # ------------------------------------------------------------------
    # Simulated-mode helpers
    # ------------------------------------------------------------------

    def _check_simulated(self, user: str, document: str, relation: str) -> bool:
        """Evaluate access against the in-memory tuple store."""
        tuple_key = AuthorizationTuple(user=user, relation=relation, object=document)

        # Direct match
        if tuple_key in self._tuples:
            logger.info("[FGA CHECK] ALLOWED  %s", tuple_key)
            return True

        # Transitive: "reader" also includes editors, owners, and managers
        if relation == RELATION_TYPE_READER:
            for expanded in (
                RELATION_TYPE_EDITOR,
                RELATION_TYPE_OWNER,
                RELATION_TYPE_MANAGER,
            ):
                expanded_key = AuthorizationTuple(user=user, relation=expanded, object=document)
                if expanded_key in self._tuples:
                    logger.info(
                        "[FGA CHECK] ALLOWED  %s (via %s relation)",
                        tuple_key,
                        expanded,
                    )
                    return True

        logger.info("[FGA CHECK] DENIED   %s", tuple_key)
        return False

    def _list_simulated(
        self, user: str, relation: str, object_type: str
    ) -> list[str]:
        objects: list[str] = []
        for t in self._tuples:
            if t.user == user and t.relation in (relation, RELATION_TYPE_READER, RELATION_TYPE_EDITOR, RELATION_TYPE_OWNER):
                prefix = f"{object_type}:"
                if t.object.startswith(prefix):
                    objects.append(t.object)
        return sorted(set(objects))

    # ------------------------------------------------------------------
    # Live Auth0 FGA API helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    def _check_api(self, user: str, document: str, relation: str) -> bool:
        url = f"{self.api_url}/stores/{self.store_id}/check"
        payload: dict[str, Any] = {
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": document,
            }
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers(), timeout=10)
            resp.raise_for_status()
            result = resp.json().get("allowed", False)
            tag = "ALLOWED" if result else "DENIED"
            logger.info("[FGA CHECK] %s  %s → %s:%s", tag, user, relation, document)
            return result
        except Exception as exc:
            logger.error("Auth0 FGA check API error: %s", exc)
            return False

    def _list_api(self, user: str, relation: str, object_type: str) -> list[str]:
        url = f"{self.api_url}/stores/{self.store_id}/list-objects"
        payload: dict[str, Any] = {
            "authorization_model_id": "",
            "user": user,
            "relation": relation,
            "type": object_type,
        }
        try:
            resp = requests.post(url, json=payload, headers=self._headers(), timeout=10)
            resp.raise_for_status()
            return resp.json().get("objects", [])
        except Exception as exc:
            logger.error("Auth0 FGA list-objects API error: %s", exc)
            return []

    def _write_api(self, tuples: list[AuthorizationTuple]) -> None:
        url = f"{self.api_url}/stores/{self.store_id}/write"
        writes = [
            {
                "tuple_key": {
                    "user": t.user,
                    "relation": t.relation,
                    "object": t.object,
                },
                "operation": "write",
            }
            for t in tuples
        ]
        try:
            resp = requests.post(url, json={"writes": writes}, headers=self._headers(), timeout=10)
            resp.raise_for_status()
            logger.info("Wrote %d tuple(s) to Auth0 FGA", len(tuples))
        except Exception as exc:
            logger.error("Auth0 FGA write API error: %s", exc)

    def _delete_api(self, tuples: list[AuthorizationTuple]) -> None:
        url = f"{self.api_url}/stores/{self.store_id}/write"
        deletes = [
            {
                "tuple_key": {
                    "user": t.user,
                    "relation": t.relation,
                    "object": t.object,
                },
                "operation": "delete",
            }
            for t in tuples
        ]
        try:
            resp = requests.post(url, json={"deletes": deletes}, headers=self._headers(), timeout=10)
            resp.raise_for_status()
            logger.info("Deleted %d tuple(s) from Auth0 FGA", len(tuples))
        except Exception as exc:
            logger.error("Auth0 FGA delete API error: %s", exc)

    def _read_api(self) -> list[AuthorizationTuple]:
        url = f"{self.api_url}/stores/{self.store_id}/read"
        try:
            resp = requests.post(url, json={}, headers=self._headers(), timeout=10)
            resp.raise_for_status()
            result: list[AuthorizationTuple] = []
            for item in resp.json().get("tuple_keys", []):
                tk = item.get("tuple_key", {})
                result.append(
                    AuthorizationTuple(
                        user=tk.get("user", ""),
                        relation=tk.get("relation", ""),
                        object=tk.get("object", ""),
                    )
                )
            return result
        except Exception as exc:
            logger.error("Auth0 FGA read API error: %s", exc)
            return []
