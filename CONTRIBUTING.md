# Contributing

Thanks for helping with OSINT MCP Hub. The project is a community MVP: a
Next.js frontend, a FastAPI orchestrator and a Supabase data layer, all wired
through MCP clients.

## Development setup

Prerequisites: Node.js 22+, Python 3.11+, npm, a terminal.

```bash
# Web deps (repo root uses npm workspaces)
npm ci

# API deps (Python)
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # Linux/macOS
pip install -e "apps/api[dev]"
```

Optional: copy `.env.example` to `.env` with your values.

### Run locally

```bash
# Terminal 1 - API
npm run dev:api

# Terminal 2 - Web
npm run dev:web
```

Open http://localhost:3000. Without Supabase env vars the system runs in
anonymous dev mode with mock MCP providers.

## Checks before opening a PR

```bash
# Backend
cd apps/api
ruff check app tests
ruff format --check app tests
pytest -q

# Frontend
npm run lint
npm run build:web
```

The CI workflow (`.github/workflows/ci.yml`) runs exactly these checks.

## Guidelines

- Keep the backend the only MCP orchestrator. Never hand provider secrets to
  the frontend.
- Follow the tactical JSON contract in `docs/architecture.md` when changing
  response shapes.
- Add a unit test for every parser/quota/orchestrator change and an integration
  test for HTTP behavior changes.
- Write SQL migrations under `supabase/migrations/` with `create table if not
  exists` and explicit RLS policies; never disable RLS.
- Match the established formatting (ruff for Python, Prettier-compatible style
  for the web app; the repo lints with `--max-warnings=0`).

## Project board

Work is tracked in `docs/execution-plan.md` as sprints. Mark a sprint
"completado" only when its verification steps pass locally.