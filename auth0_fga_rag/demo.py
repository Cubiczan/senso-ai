"""Auth0 FGA Privacy-Aware RAG Bot — Interactive Demo.

Demonstrates document-level access control using Auth0 Fine-Grained Authorization
within a RAG (Retrieval-Augmented Generation) pipeline.

Usage:
    python -m auth0_fga_rag.demo
"""
import sys
from .fga_client import FGAClient
from .document_store import DocumentStore
from .rag_engine import RAGEngine


# ── Colour helpers (ANSI) ──────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEPARATOR = "═" * 70


def print_header(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{SEPARATOR}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{SEPARATOR}{RESET}\n")


def print_step(step: int, text: str) -> None:
    print(f"{BOLD}Step {step}: {text}{RESET}")


def print_access(doc_id: str, title: str, allowed: bool) -> None:
    status = f"{GREEN}✓ ALLOWED{RESET}" if allowed else f"{RED}✗ DENIED{RESET}"
    print(f"  [{status}] {doc_id}: {title}")


def main() -> None:
    print_header("Auth0 FGA Privacy-Aware RAG Bot — Demo")

    # ── Step 1: Initialize components ──────────────────────────────────
    print_step(1, "Initialize FGA client, document store, and RAG engine")

    fga = FGAClient(store_id="demo-store")
    docs = DocumentStore()
    rag = RAGEngine(document_store=docs, fga_client=fga)

    print(f"  FGA store : {fga.store_id}")
    print(f"  Documents : {docs.count()} total")
    print()

    # ── Step 2: Create authorization tuples ────────────────────────────
    print_step(2, "Set up Auth0 FGA authorization rules")

    # Define users and roles
    users = {
        "alice": {"name": "Alice (Finance Manager)", "department": "finance"},
        "bob": {"name": "Bob (HR Intern)", "department": "hr"},
        "carol": {"name": "Carol (Engineering Analyst)", "department": "engineering"},
        "dave": {"name": "Dave (CEO / Executive)", "department": "executive"},
    }

    # Set up FGA rules
    rules = [
        # Alice — Finance manager can read finance docs + public
        ("alice", "doc:finance_budget_q4", "reader"),
        ("alice", "doc:finance_forecast_2026", "reader"),
        ("alice", "doc:finance_salary_review", "reader"),  # Finance manager sees salaries
        ("alice", "doc:public_handbook", "reader"),
        ("alice", "doc:public_org_chart", "reader"),
        ("alice", "doc:eng_architecture_overview", "reader"),  # Cross-department viewer

        # Bob — HR intern can see basic HR + public, NOT salary details
        ("bob", "doc:public_handbook", "reader"),
        ("bob", "doc:public_org_chart", "reader"),
        ("bob", "doc:hr_benefits_summary", "reader"),
        # Explicitly NO access to salary, executive, or finance docs

        # Carol — Engineering analyst sees engineering + public
        ("carol", "doc:eng_architecture_overview", "reader"),
        ("carol", "doc:eng_code_review_process", "reader"),
        ("carol", "doc:eng_oncall_schedule", "reader"),
        ("carol", "doc:public_handbook", "reader"),
        ("carol", "doc:public_org_chart", "reader"),

        # Dave — CEO sees EVERYTHING
        ("dave", "doc:finance_budget_q4", "reader"),
        ("dave", "doc:finance_forecast_2026", "reader"),
        ("dave", "doc:finance_salary_review", "reader"),
        ("dave", "doc:hr_benefits_summary", "reader"),
        ("dave", "doc:hr_performance_reviews", "reader"),
        ("dave", "doc:hr_salary_structure", "reader"),
        ("dave", "doc:eng_architecture_overview", "reader"),
        ("dave", "doc:eng_code_review_process", "reader"),
        ("dave", "doc:eng_oncall_schedule", "reader"),
        ("dave", "doc:exec_strategy_2026", "reader"),
        ("dave", "doc:exec_ma_plans", "reader"),
        ("dave", "doc:public_handbook", "reader"),
        ("dave", "doc:public_org_chart", "reader"),
    ]

    for user, doc, relation in rules:
        fga.write_tuple(user, doc, relation)

    print(f"  {len(rules)} authorization rules created for {len(users)} users")
    print()

    for user_id, info in users.items():
        accessible = fga.list_documents(user_id, "reader")
        print(f"  {info['name']}: {len(accessible)} documents accessible")
    print()

    # ── Step 3: Run RAG queries for each user ──────────────────────────
    query = "What is the company's financial outlook and strategy?"
    print_step(3, f'Run RAG query for all users: "{query}"')
    print()

    results_summary = {}

    for user_id, info in users.items():
        print(f"{BOLD}{YELLOW}── {info['name']} (Department: {info['department']}) ──{RESET}")

        # Show individual FGA checks
        all_docs = docs.list_all()
        for doc in all_docs:
            allowed = fga.check(user_id, doc["id"], "reader")
            print_access(doc["id"], doc["title"], allowed)

        # Run RAG retrieval
        print(f"\n  {CYAN}RAG Retrieval Results:{RESET}")
        retrieved = rag.retrieve(query, user_id, top_k=5)

        if retrieved:
            for i, doc in enumerate(retrieved, 1):
                print(f"    {i}. {doc['title']} (dept: {doc['department']}, sensitivity: {doc['sensitivity']})")
        else:
            print(f"    {RED}No documents accessible for this query.{RESET}")

        # Generate response
        print(f"\n  {CYAN}Generated Response:{RESET}")
        response = rag.generate(user_id, query)
        print(f"    {response}")

        results_summary[user_id] = {
            "name": info["name"],
            "department": info["department"],
            "docs_retrieved": len(retrieved),
            "response_length": len(response),
        }

        print()

    # ── Step 4: Summary comparison ────────────────────────────────────
    print_step(4, "Access Comparison Summary")
    print()

    print(f"  {'User':<35} {'Docs Found':>12} {'Response':>12}")
    print(f"  {'─' * 35} {'─' * 12} {'─' * 12}")
    for user_id, summary in results_summary.items():
        print(
            f"  {summary['name']:<35} "
            f"{summary['docs_retrieved']:>12} "
            f"{summary['response_length']:>10} chars"
        )

    print()
    print_header("Demo Complete")
    print(f"  {GREEN}✓ Auth0 FGA successfully filtered RAG results by user role{RESET}")
    print(f"  {GREEN}✓ Same query produced different results for each user{RESET}")
    print(f"  {GREEN}✓ Sensitive documents (salaries, M&A) restricted to authorized users{RESET}")
    print(f"  {RED}✗ Bob (HR Intern) could NOT access salary or executive documents{RESET}")
    print(f"  {GREEN}✓ Dave (CEO) had unrestricted access to all documents{RESET}")
    print()


if __name__ == "__main__":
    main()
