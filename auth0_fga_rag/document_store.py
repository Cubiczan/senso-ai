"""Document store with Auth0 FGA access-control filtering.

All documents live in a single in-memory collection.  Every ``search()`` call
runs candidate retrieval **then** passes each candidate through the FGA
client so that only authorized documents are returned to the caller (and
ultimately to the LLM context window).
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any

from auth0_fga_rag.fga_client import FGAClient, AuthorizationTuple
from auth0_fga_rag.fga_config import RELATION_TYPE_READER, RELATION_TYPE_EDITOR, RELATION_TYPE_OWNER, RELATION_TYPE_MANAGER

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Document data class
# ---------------------------------------------------------------------------


@dataclass
class Document:
    """A single document in the knowledge base."""

    doc_id: str
    title: str
    content: str
    department: str
    sensitivity: str  # "public" | "internal" | "confidential" | "restricted"
    owner: str
    tags: list[str] = field(default_factory=list)

    @property
    def fga_object_id(self) -> str:
        return f"document:{self.doc_id}"


# ---------------------------------------------------------------------------
# Sample documents drawn from the Senso.AI knowledge base
# ---------------------------------------------------------------------------

SAMPLE_DOCUMENTS: list[Document] = [
    # ---- Finance ----
    Document(
        doc_id="budget_Q4_2025",
        title="Q4 2025 Budget Overview",
        content=(
            "The Q4 2025 budget allocates $4.2M across departments. "
            "Engineering receives $1.8M (43%), Product receives $1.1M (26%), "
            "Operations $800K (19%), and G&A $500K (12%). "
            "Key initiatives include the AI Platform migration ($600K), "
            "security hardening ($250K), and hiring 5 senior engineers ($400K). "
            "Revenue target: $6.1M with 31% gross margin."
        ),
        department="Finance",
        sensitivity="confidential",
        owner="user:alice",
        tags=["budget", "finance", "quarterly", "2025"],
    ),
    Document(
        doc_id="revenue_forecast_2025",
        title="2025 Revenue Forecast",
        content=(
            "Based on current pipeline, 2025 projected revenue is $23.4M, "
            "up 18% YoY. SaaS subscriptions contribute $18.2M, "
            "professional services $3.8M, and marketplace fees $1.4M. "
            "Net retention rate stands at 112%. Key risk factors include "
            "three enterprise contracts up for renewal in Q3."
        ),
        department="Finance",
        sensitivity="confidential",
        owner="user:alice",
        tags=["revenue", "forecast", "finance", "2025"],
    ),
    Document(
        doc_id="salary_band_guide",
        title="Employee Salary Band Guide FY2025",
        content=(
            "Salary bands for FY2025: L1 ($85-105K), L2 ($105-135K), "
            "L3 ($135-170K), L4 ($170-210K), L5 ($210-260K). "
            "Equity refresh grants: L3+ eligible. Sign-on bonus cap: "
            "$25K for L4+. Performance bonus multiplier: 0.8x-1.5x "
            "based on rating. Restricted to HR managers and above."
        ),
        department="HR",
        sensitivity="restricted",
        owner="user:hr_director",
        tags=["salary", "compensation", "bands", "HR"],
    ),
    Document(
        doc_id="executive_comp_report",
        title="Executive Compensation Report 2025",
        content=(
            "C-suite total compensation: CEO ($890K base + $1.2M equity), "
            "CTO ($780K + $1.0M equity), CFO ($750K + $900K equity). "
            "Board approved 15% increase in long-term incentive pool. "
            "Clawback provisions updated for regulatory compliance."
        ),
        department="HR",
        sensitivity="restricted",
        owner="user:dave",
        tags=["executive", "compensation", "C-suite", "restricted"],
    ),
    Document(
        doc_id="performance_reviews_Q4",
        title="Q4 2024 Performance Review Summary",
        content=(
            "45% of employees rated 'Exceeds Expectations', 38% 'Meets', "
            "12% 'Developing', 5% 'Below'. Promotion pipeline: 8 engineers "
            "recommended for L3→L4, 3 for L4→L5. Calibration sessions "
            "completed across all departments. Exit interview theme: "
            "career growth visibility."
        ),
        department="HR",
        sensitivity="confidential",
        owner="user:hr_director",
        tags=["performance", "reviews", "HR", "Q4"],
    ),
    # ---- Engineering ----
    Document(
        doc_id="architecture_v3",
        title="Platform Architecture v3 — Microservices Migration",
        content=(
            "Architecture v3 migrates the monolith to 12 microservices: "
            "auth-gateway, user-service, billing, notification, search, "
            "document-store, analytics, ingestion, export, scheduling, "
            "audit-log, config-service. Tech stack: Python 3.11+, FastAPI, "
            "PostgreSQL 16, Redis 7, Kafka. Target completion: Q2 2025. "
            "Estimated engineering effort: 2,400 person-hours."
        ),
        department="Engineering",
        sensitivity="internal",
        owner="user:carol",
        tags=["architecture", "microservices", "migration", "engineering"],
    ),
    Document(
        doc_id="code_review_standards",
        title="Code Review Standards & Best Practices",
        content=(
            "All PRs require 2 approvals for production, 1 for staging. "
            "Auto-formatting with ruff and black. Required checks: "
            "mypy strict, pytest 90%+ coverage, no critical SAST findings. "
            "Review SLA: 24h for hotfixes, 48h for features. "
            "Use 'request changes' for logic errors, 'comment' for suggestions."
        ),
        department="Engineering",
        sensitivity="internal",
        owner="user:carol",
        tags=["code-review", "standards", "engineering", "best-practices"],
    ),
    Document(
        doc_id="incident_postmortem_2024_12",
        title="Incident Postmortem — Dec 2024 Database Outage",
        content=(
            "On Dec 15 2024, primary PostgreSQL cluster experienced a 47-minute "
            "partial outage during planned failover. Root cause: incorrect "
            "WAL shipping configuration on standby node. Impact: 12% of "
            "API requests returned 503. Resolution: fixed pg_hba.conf, "
            "added automated failover testing to CI pipeline."
        ),
        department="Engineering",
        sensitivity="internal",
        owner="user:carol",
        tags=["incident", "postmortem", "database", "outage"],
    ),
    # ---- Executive / Strategy ----
    Document(
        doc_id="ma_strategy_2025",
        title="M&A Strategy — Acquisition Targets 2025",
        content=(
            "Three acquisition targets identified: (1) DataSync Labs "
            "($12M ARR, real-time ETL, 35 engineers), (2) SecureVault AI "
            "($8M ARR, AI-powered data governance), (3) QueryForge "
            "($5M ARR, natural-language query engine). Budget: $80M total. "
            "Board approval target: Q1 2025. Due diligence teams assembled."
        ),
        department="Executive",
        sensitivity="restricted",
        owner="user:dave",
        tags=["M&A", "strategy", "acquisition", "executive"],
    ),
    Document(
        doc_id="company_strategy_2025",
        title="2025 Strategic Plan — Executive Summary",
        content=(
            "Vision: Become the #1 AI-native data platform for mid-market. "
            "Three strategic pillars: (1) AI-Powered Analytics — embed LLM "
            "into every workflow, (2) Enterprise Security — SOC 2 Type II "
            "and ISO 27001, (3) Global Expansion — EMEA launch Q2 2025, "
            "APAC Q4 2025. Headcount target: 120 (from 85). Revenue target: "
            "$23.4M. IPO readiness assessment: Q3 2025."
        ),
        department="Executive",
        sensitivity="restricted",
        owner="user:dave",
        tags=["strategy", "2025", "executive", "plan"],
    ),
    Document(
        doc_id="board_deck_Q4",
        title="Q4 2024 Board of Directors Presentation",
        content=(
            "Key metrics: ARR $19.8M (+22% YoY), NRR 118%, gross margin 74%. "
            "Customer count: 340 (+62 net new). Key wins: Fortune 500 bank "
            "($2.4M ACV), government agency ($1.8M). Burn rate: $1.3M/month. "
            "Runway: 28 months. Board approved $15M secondary offering."
        ),
        department="Executive",
        sensitivity="restricted",
        owner="user:dave",
        tags=["board", "metrics", "Q4", "executive"],
    ),
    # ---- Public ----
    Document(
        doc_id="company_handbook",
        title="Senso.AI Employee Handbook",
        content=(
            "Welcome to Senso.AI! We build AI-native data platforms for the "
            "mid-market. Core values: Ownership, Transparency, Speed, Quality. "
            "Benefits: unlimited PTO, $5K learning budget, 401(k) 4% match, "
            "health/dental/vision 100% employer-paid. Remote-first with "
            "quarterly offsites. Working hours: flexible, core overlap 10am-2pm ET. "
            "Open-door policy — DM anyone on Slack."
        ),
        department="Public",
        sensitivity="public",
        owner="user:hr_director",
        tags=["handbook", "public", "company", "policies"],
    ),
    Document(
        doc_id="org_chart",
        title="Senso.AI Organizational Chart",
        content=(
            "CEO: Dave (Executive)\n"
            "  CTO: — (Engineering)\n"
            "  CFO: — (Finance)\n"
            "  VP HR: — (HR)\n"
            "Engineering teams: Platform (12), AI/ML (8), Frontend (6), "
            "Infrastructure (4), Security (3). Total headcount: 85. "
            "Reporting structure: flat to L4, skip-levels monthly."
        ),
        department="Public",
        sensitivity="public",
        owner="user:hr_director",
        tags=["org-chart", "public", "organization"],
    ),
    Document(
        doc_id="engineering_tech_stack",
        title="Engineering Tech Stack Overview",
        content=(
            "Backend: Python 3.11+, FastAPI, SQLAlchemy 2.0, Alembic, Celery. "
            "Frontend: Next.js 16, TypeScript, Tailwind CSS 4, shadcn/ui. "
            "Data: PostgreSQL 16, Redis 7, Apache Kafka. ML: PyTorch, "
            "sentence-transformers, OpenAI API. Infrastructure: AWS EKS, "
            "Terraform, ArgoCD. Monitoring: Datadog, Sentry. CI/CD: GitHub Actions."
        ),
        department="Public",
        sensitivity="public",
        owner="user:carol",
        tags=["tech-stack", "engineering", "public"],
    ),
]


# ---------------------------------------------------------------------------
# DocumentStore
# ---------------------------------------------------------------------------


class DocumentStore:
    """In-memory document store with FGA-aware search.

    The ``search`` method performs keyword matching **and** Auth0 FGA
    authorization checks in sequence, so that the caller only receives
    documents they are authorized to read.
    """

    def __init__(self, documents: list[Document] | None = None) -> None:
        self._documents: dict[str, Document] = {}
        for doc in (documents or []):
            self._documents[doc.doc_id] = doc

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_document(
        self,
        doc_id: str,
        title: str,
        content: str,
        department: str,
        sensitivity: str,
        owner: str,
        tags: list[str] | None = None,
    ) -> Document:
        doc = Document(
            doc_id=doc_id,
            title=title,
            content=content,
            department=department,
            sensitivity=sensitivity,
            owner=owner,
            tags=tags or [],
        )
        self._documents[doc.doc_id] = doc
        return doc

    def get_document(self, doc_id: str) -> Document | None:
        return self._documents.get(doc_id)

    def list_all_documents(self) -> list[Document]:
        return list(self._documents.values())

    def list_by_department(self, department: str) -> list[Document]:
        return [d for d in self._documents.values() if d.department == department]

    # ------------------------------------------------------------------
    # Search with FGA filtering
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        user_id: str,
        fga_client: FGAClient,
        top_k: int = 10,
    ) -> list[tuple[Document, float]]:
        """Keyword-search the store and filter results through Auth0 FGA.

        Returns a list of ``(document, relevance_score)`` pairs sorted by
        descending relevance.  Documents that fail the FGA check are
        silently dropped — the user never sees them, not even in the
        RAG context sent to the LLM.
        """
        candidates = self._keyword_search(query, top_k=top_k * 3)  # over-fetch
        allowed: list[tuple[Document, float]] = []
        denied_count = 0

        logger.info("=" * 60)
        logger.info("SEARCH  query=%r  user=%s  candidates=%d", query, user_id, len(candidates))
        logger.info("-" * 60)

        for doc, score in candidates:
            obj_id = doc.fga_object_id
            if fga_client.check(user_id, obj_id, RELATION_TYPE_READER):
                allowed.append((doc, score))
                logger.info("  ✅ ALLOWED  %s  (score=%.3f)", obj_id, score)
            else:
                denied_count += 1
                logger.info("  🚫 DENIED   %s  (score=%.3f) — FGA check failed", obj_id, score)

        logger.info("-" * 60)
        logger.info(
            "RESULT  user=%s  allowed=%d  denied=%d",
            user_id, len(allowed), denied_count,
        )
        logger.info("=" * 60)

        return sorted(allowed, key=lambda pair: pair[1], reverse=True)[:top_k]

    # ------------------------------------------------------------------
    # Internal: keyword search (TF-IDF-ish scoring)
    # ------------------------------------------------------------------

    def _keyword_search(
        self, query: str, top_k: int = 10
    ) -> list[tuple[Document, float]]:
        """Simple BM25-ish keyword scorer over title + content + tags."""
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        scored: list[tuple[Document, float]] = []
        for doc in self._documents.values():
            text = f"{doc.title} {doc.title} {doc.content} {' '.join(doc.tags)}"
            doc_tokens = self._tokenize(text)
            if not doc_tokens:
                continue
            score = self._bm25_score(query_tokens, doc_tokens)
            if score > 0:
                scored.append((doc, score))

        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"\w+", text.lower())

    @staticmethod
    def _bm25_score(query_tokens: list[str], doc_tokens: list[str], k1: float = 1.5, b: float = 0.75) -> float:
        """Simplified BM25 scoring."""
        doc_len = len(doc_tokens)
        avg_dl = max(doc_len, 1)  # approximate
        score = 0.0
        doc_freq = Counter(doc_tokens)
        for qt in query_tokens:
            tf = doc_freq.get(qt, 0)
            if tf == 0:
                continue
            idf = 1.0  # simplified — no corpus-level IDF
            numerator = tf * (k1 + 1)
            denominator = tf + k1 * (1 - b + b * (doc_len / avg_dl))
            score += idf * (numerator / denominator)
        return score


# Need Counter for BM25
from collections import Counter  # noqa: E402
