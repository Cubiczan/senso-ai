"""RAG Engine with Auth0 FGA authorization filtering.

This module ties together the document store, FGA client, and a simulated
LLM to demonstrate *privacy-aware retrieval*.  The key insight: even though
the RAG index contains sensitive documents, the FGA check prevents them
from entering the LLM context for unauthorized users.
"""

from __future__ import annotations

import hashlib
import logging
import textwrap
from dataclasses import dataclass, field

from auth0_fga_rag.document_store import DocumentStore, Document, SAMPLE_DOCUMENTS
from auth0_fga_rag.fga_client import FGAClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass
class RetrievalResult:
    """Result of a single FGA-filtered RAG retrieval pass."""

    query: str
    user_id: str
    retrieved: list[tuple[Document, float]]
    filtered_out: list[tuple[str, float]]  # (doc_id, score) of blocked docs


@dataclass
class GenerationResult:
    """Result of an LLM generation pass."""

    user_id: str
    query: str
    context_documents: list[Document]
    response: str
    access_denied_count: int


# ---------------------------------------------------------------------------
# RAGEngine
# ---------------------------------------------------------------------------


class RAGEngine:
    """Retrieval-Augmented Generation engine with Auth0 FGA guardrails.

    Workflow per query:
    1. **Retrieve** — keyword-search the document store.
    2. **Filter** — pass every candidate through ``FGAClient.check``.
    3. **Generate** — build an LLM prompt from authorized documents only.
    """

    def __init__(
        self,
        document_store: DocumentStore | None = None,
        fga_client: FGAClient | None = None,
    ) -> None:
        self.store = document_store or DocumentStore(SAMPLE_DOCUMENTS)
        self.fga = fga_client or FGAClient()

    # ------------------------------------------------------------------
    # Embedding simulation
    # ------------------------------------------------------------------

    @staticmethod
    def embed(text: str, dim: int = 64) -> list[float]:
        """Deterministic pseudo-embedding from a hash (demo only).

        In a production system this would call an embedding model
        (e.g. ``text-embedding-3-small``) but for the demo a
        deterministic hash-vector is sufficient.
        """
        digest = hashlib.sha256(text.encode()).digest()
        values: list[float] = []
        for i in range(dim):
            byte_idx = i % len(digest)
            values.append((digest[byte_idx] / 255.0) - 0.5)
        return values

    # ------------------------------------------------------------------
    # Retrieve (with FGA filtering)
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        user_id: str,
        top_k: int = 5,
    ) -> RetrievalResult:
        """Retrieve documents filtered by Auth0 FGA access control."""
        # Step 1: Search the store
        allowed = self.store.search(query, user_id, self.fga, top_k=top_k)

        # Step 2: Determine what was filtered out (search all, compare)
        all_candidates = self.store._keyword_search(query, top_k=top_k * 3)
        allowed_ids = {doc.doc_id for doc, _ in allowed}
        filtered_out = [
            (doc.doc_id, score)
            for doc, score in all_candidates
            if doc.doc_id not in allowed_ids
        ]

        return RetrievalResult(
            query=query,
            user_id=user_id,
            retrieved=allowed,
            filtered_out=filtered_out,
        )

    # ------------------------------------------------------------------
    # Generate
    # ------------------------------------------------------------------

    def generate(
        self,
        user_id: str,
        query: str,
        top_k: int = 5,
    ) -> GenerationResult:
        """Full RAG pipeline: retrieve → filter → generate."""
        result = self.retrieve(query, user_id, top_k=top_k)
        context_docs = [doc for doc, _ in result.retrieved]

        # Build the simulated LLM response
        if not context_docs:
            response = (
                f"I'm sorry, I don't have any documents that I'm authorized "
                f"to share regarding '{query}' for your account ({user_id}). "
                f"Please contact your manager or the IT team if you believe "
                f"you should have access."
            )
        else:
            context_text = "\n\n".join(
                f"[{doc.title}]\n{doc.content}" for doc in context_docs
            )
            response = self._simulate_llm_response(
                query=query,
                context=context_text,
                user_id=user_id,
            )

        return GenerationResult(
            user_id=user_id,
            query=query,
            context_documents=context_docs,
            response=response,
            access_denied_count=len(result.filtered_out),
        )

    # ------------------------------------------------------------------
    # Simulated LLM response
    # ------------------------------------------------------------------

    @staticmethod
    def _simulate_llm_response(
        query: str,
        context: str,
        user_id: str,
    ) -> str:
        """Build a deterministic summary from the authorized context.

        In production this would call the LLM API (OpenAI, Claude, etc.)
        with the filtered context.  For the demo we construct a response
        that makes it clear *which* documents were consulted.
        """
        # Extract document titles from context
        lines = context.split("\n")
        doc_titles: list[str] = []
        for line in lines:
            if line.startswith("[") and line.endswith("]"):
                doc_titles.append(line.strip("[]"))

        title_list = ", ".join(doc_titles) if doc_titles else "none"
        snippet = context[:600].replace("\n", " ")

        return (
            f"Based on the documents I'm authorized to share with {user_id}, "
            f"here is what I found:\n\n"
            f"**Sources consulted**: {title_list}\n\n"
            f"{snippet}{'...' if len(context) > 600 else ''}\n\n"
            f"[This response was generated from {len(doc_titles)} authorized "
            f"document(s) out of the full knowledge base. Some documents "
            f"may have been filtered by access control.]"
        )

    # ------------------------------------------------------------------
    # Pretty-printing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def print_retrieval_result(result: RetrievalResult, width: int = 70) -> None:
        """Print a formatted retrieval result to stdout."""
        border = "=" * width
        sep = "-" * width

        print(f"\n{border}")
        print(f"  RAG RETRIEVAL  |  user: {result.user_id}  |  query: {result.query}")
        print(sep)

        if result.retrieved:
            print(f"  ✅ AUTHORIZED DOCUMENTS ({len(result.retrieved)}):")
            for doc, score in result.retrieved:
                meta = f"[{doc.department}] [{doc.sensitivity}]"
                print(f"     • {doc.doc_id}: {doc.title}")
                print(f"       {meta}  score={score:.4f}")
        else:
            print("  ⚠️  No authorized documents found.")

        if result.filtered_out:
            print(f"\n  🚫 BLOCKED BY FGA ({len(result.filtered_out)}):")
            for doc_id, score in result.filtered_out:
                print(f"     ✗ {doc_id}  score={score:.4f}  — access denied")

        print(f"{border}\n")

    @staticmethod
    def print_generation_result(result: GenerationResult, width: int = 70) -> None:
        """Print a formatted generation result to stdout."""
        border = "=" * width

        print(f"\n{border}")
        print(f"  RAG GENERATION  |  user: {result.user_id}  |  query: {result.query}")
        print(f"  Docs used: {len(result.context_documents)}  |  Docs blocked: {result.access_denied_count}")
        print(f"{border}")
        print(textwrap.indent(result.response, "  "))
        print(f"{border}\n")
