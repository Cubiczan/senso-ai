# Auth0 FGA Privacy-Aware RAG Bot

> MLH Global Hack Week: GenAI — Auth0 Partner Challenge
> Demonstrate document-level access control in RAG using Auth0 Fine-Grained Authorization

---

## The Challenge

Build an internal-facing knowledge assistant that sources answers from a document database via RAG (Retrieval-Augmented Generation), where the assistant enforces **document-level access control** based on the logged-in user's role and department.

**Key Requirement:** A manager can access salary documents, but a general employee cannot — even if the document exists in the RAG index.

## How It Works

```
┌──────────┐     ┌──────────────┐     ┌───────────┐     ┌──────────────┐
│   User    │────▶│   RAG Query  │────▶│  RAG Index │────▶│  Candidate   │
│ (Alice)   │     │  "financial  │     │  (All Docs)│     │  Documents   │
│           │     │   outlook?"  │     │            │     │  (5 results) │
└──────────┘     └──────────────┘     └─────────────┘     └──────┬───────┘
                                                               │
                                                               ▼
                                                     ┌──────────────────┐
                                                     │   Auth0 FGA      │
                                                     │   Access Check   │
                                                     │                  │
                                                     │  doc:budget_Q4   │──▶ ✓ Alice can read
                                                     │  doc:salary_2026 │──▶ ✗ Alice DENIED
                                                     │  doc:handbook    │──▶ ✓ Alice can read
                                                     └────────┬─────────┘
                                                              │
                                                              ▼
                                                     ┌──────────────────┐
                                                     │  Filtered RAG    │
                                                     │  Context         │
                                                     │  (2 docs only)   │
                                                     └────────┬─────────┘
                                                              │
                                                              ▼
                                                     ┌──────────────────┐
                                                     │  LLM Response    │
                                                     │  (based ONLY on  │
                                                     │  accessible docs)│
                                                     └──────────────────┘
```

## Architecture

### Authorization Model

```yaml
model
  schema 1.1

type user

type document
  relations
    define owner: [user]
    define editor: [user, manager#member] or owner
    define reader: [user, editor] or manager#member or public_reader
    define manager: [user] or manager#member

type department
  relations
    define member: [user]
    define head: [user]
```

### Module Structure

```
auth0_fga_rag/
├── __init__.py                # Package exports and version
├── fga_config.py              # Auth0 FGA API configuration
├── authorization_model.py     # FGA authorization model definition
├── fga_client.py              # Auth0 FGA API client (check/write/list)
├── document_store.py          # Document database with 13 sample documents
├── rag_engine.py              # RAG engine with FGA-filtered retrieval
├── demo.py                    # Interactive demo script
└── README.md                  # This file
```

### Sample Users & Access

| User | Role | Department | Accessible Docs |
|------|------|-----------|----------------|
| Alice | Finance Manager | Finance | Budget, Forecast, Salary (Finance), Public |
| Bob | HR Intern | HR | Benefits Summary, Public only |
| Carol | Engineering Analyst | Engineering | Architecture, Code Review, Oncall, Public |
| Dave | CEO | Executive | **ALL documents** (unrestricted) |

### Sample Documents

| Document ID | Department | Sensitivity | Accessible By |
|-------------|-----------|-------------|---------------|
| `doc:finance_budget_q4` | Finance | Confidential | Finance, Executive |
| `doc:finance_forecast_2026` | Finance | Internal | Finance, Executive |
| `doc:finance_salary_review` | Finance | Top Secret | Executive only |
| `doc:hr_benefits_summary` | HR | Internal | HR, Executive |
| `doc:hr_performance_reviews` | HR | Confidential | HR Managers, Executive |
| `doc:hr_salary_structure` | HR | Top Secret | Executive only |
| `doc:eng_architecture_overview` | Engineering | Internal | Engineering, Executive |
| `doc:eng_code_review_process` | Engineering | Internal | Engineering, Executive |
| `doc:eng_oncall_schedule` | Engineering | Public | Everyone |
| `doc:exec_strategy_2026` | Executive | Top Secret | Executive only |
| `doc:exec_ma_plans` | Executive | Top Secret | Executive only |
| `doc:public_handbook` | Company | Public | Everyone |
| `doc:public_org_chart` | Company | Public | Everyone |

## Quick Start

### Prerequisites

- Python 3.11+
- `requests` library (usually pre-installed)

### Run the Demo

```bash
cd senso-ai
python -m auth0_fga_rag.demo
```

No Auth0 credentials required — the demo runs in simulated mode with an in-memory FGA store.

### Output

The demo runs the same query (`"What is the company's financial outlook?"`) for 4 different users and shows:

1. **Individual FGA checks** — Each document is checked: ✓ ALLOWED or ✗ DENIED
2. **RAG retrieval results** — Only accessible documents appear in results
3. **LLM-generated response** — Based ONLY on documents the user can access
4. **Comparison table** — Same query, different result counts per user

### Key Demonstrations

| Scenario | Expected Behavior |
|----------|-------------------|
| Bob queries salary info | ✗ DENIED — HR Intern cannot see salary docs |
| Alice queries budget | ✓ ALLOWED — Finance Manager sees budget |
| Dave queries M&A strategy | ✓ ALLOWED — CEO has unrestricted access |
| Carol queries financial outlook | ✗ DENIED — Engineer cannot see finance docs |
| Same query, 4 users | 4 different responses based on role |

## Auth0 FGA Setup (Production)

To connect to a real Auth0 FGA instance:

```bash
export AUTH0_FGA_API_URL=https://api.us.auth0.com
export AUTH0_FGA_API_TOKEN=your-fga-api-token
export AUTH0_FGA_STORE_ID=your-store-id
```

Then run the demo — it will use the real FGA API for authorization checks.

## MLH Challenge Requirements Mapping

| Requirement | Implementation |
|-------------|---------------|
| ✅ Auth0 FGA for access control | `fga_client.py` — check/write/list tuples |
| ✅ RAG pipeline | `rag_engine.py` — embed → retrieve → generate |
| ✅ Document-level access control | `document_store.py` — FGA check on every retrieval |
| ✅ Manager vs employee access | Demo shows Dave (CEO) vs Bob (Intern) |
| ✅ Correct denial of sensitive docs | Bob cannot access salary, M&A, or budget docs |
| ✅ LLM respects authorization | Response generated only from accessible documents |

## Tech Stack

- **Python 3.11+**
- **Auth0 FGA** (Fine-Grained Authorization)
- **RAG** (Retrieval-Augmented Generation)
- **requests** (HTTP client)
