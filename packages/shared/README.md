# @huntdeck/shared

Canonical frontend copy of the HuntDeck tactical-report contract.

- Source of truth for TypeScript: `src/contract.ts`.
- Mirrors the backend Pydantic models in
  `apps/api/app/schemas/investigation.py` (+ `ParsedIoc` from
  `app/domain/ioc/types.py`).
- The web app consumes it via the `@huntdeck/shared` path alias (see
  `apps/web/tsconfig.json`); `apps/web/src/lib/api/types.ts` re-exports it
  for backwards-compatible imports.

When the backend contract changes, update `contract.ts` in the same commit.
