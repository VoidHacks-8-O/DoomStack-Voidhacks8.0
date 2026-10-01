# 🛡️ ANVITRACE

> **Offline cyber-forensics and financial transaction investigation platform.**

---

## Purpose

ANVITRACE is a fully offline platform designed for cyber-forensic analysis of financial transactions and money-mule investigation. It enables investigators to ingest large transaction datasets, trace multi-hop money trails, detect mule networks, assess risk, analyse recovery potential, and generate court-ready evidence — all without any cloud dependency.

---

## Backend Stack

| Layer            | Technology                              |
| ---------------- | --------------------------------------- |
| Language         | Python 3.12+                            |
| Web Framework    | FastAPI + Uvicorn                       |
| Database         | DuckDB                                  |
| Data Processing  | Pandas · NumPy · Polars · Apache Arrow  |
| Validation       | Pydantic                                |
| Templating       | Jinja2                                  |
| Report Generation| ReportLab                               |
| Testing          | Pytest                                  |
| Linting          | Ruff                                    |

---

## Core Workflow

```
Dataset
  → Ingestion
    → Indexing
      → Victim Search
        → Four-Hop Money Trail
          → Amount Lineage
            → Mule Detection
              → Risk Analysis
                → Recovery Analysis
                  → Cross-Victim Analysis
                    → Evidence
                      → Reports
```

---

## Project Status

> **Backend Foundation / Initialization Phase**
>
> The project structure, dependencies, and configuration scaffolding have been established.
> Core business logic, algorithms, and API endpoints will be implemented in subsequent phases.

---

## Quick Start

```bash
# 1. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy environment config
copy .env.example .env        # Windows
# cp .env.example .env        # Linux / macOS

# 4. Run the development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## Directory Structure

```
backend/
├── app/                  # Application source code
│   ├── config/           # Settings and constants
│   ├── database/         # DuckDB connection and schema
│   ├── models/           # Domain models
│   ├── schemas/          # Pydantic request/response schemas
│   ├── routers/          # API route handlers
│   ├── services/         # Business logic services
│   ├── algorithms/       # Forensic algorithms
│   ├── indexes/          # Indexing engine
│   ├── evidence/         # Evidence packaging
│   ├── documents/        # Report / document generation
│   └── utils/            # Shared utilities
├── data/                 # Runtime data (git-ignored)
├── tests/                # Test suites
├── benchmarks/           # Performance benchmarks
├── scripts/              # Utility scripts
├── requirements.txt
├── pyproject.toml
└── .env.example
```

---

## License

MIT
