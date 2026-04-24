# Agent Coordination Platform

Full-stack platform for coordinating, monitoring, and evolving multi-agent AI systems.

## Architecture

**Monorepo (pnpm workspaces)**

```
artifacts/
  platform/          # React + Vite frontend (port via $PORT)
  api-server/        # Express 5 backend (port 8080)
  mockup-sandbox/    # Component preview server (Canvas)
lib/
  db/                # Drizzle ORM + PostgreSQL schema
  api-spec/          # OpenAPI 3.1 spec + Orval codegen
  api-client-react/  # Generated React Query hooks
  api-zod/           # Generated Zod validation schemas
scripts/
  seed.mjs           # Seed via live API
  seed-threats.mjs   # Seed threat events directly via pg
  github-push.mjs    # Initial GitHub push
  github-update.mjs  # Delta GitHub push
```

## Stack

- **Frontend**: React + Vite + shadcn/ui + recharts + wouter + TailwindCSS (dark-mode)
- **Backend**: Express 5 + Drizzle ORM + PostgreSQL
- **API Contract**: OpenAPI 3.1 spec → Orval codegen (React Query hooks + Zod schemas)
- **Monorepo**: pnpm workspaces with TypeScript project references

## Modules (8)

1. **A2A Protocol** — Agent session management, message routing, UCAN claim generation
2. **A2A Security** — Threat rules (T104–T108), event detection, severity stats
3. **Recovery Router** — Work item queuing, claim/complete lifecycle, recovery event bus
4. **Cross-Model Router** — Role-to-provider mappings, performance learning records
5. **Proposal Engine** — Failure pattern clustering, agent capability proposals, lifecycle
6. **Context Router + Shapley** — Knowledge domains, Shapley value attribution, diversity stats
7. **Coordination Tournament** — Hierarchical/debate/parallel variant scoring, winner patterns
8. **Meta-Learner** — Strategy lifecycle (ingest→propose→lint→active), learning curve, lint validation

## Frontend Pages

- `/` — Dashboard: live platform stats (agents, sessions, threats, work items, strategies)
- `/agents` — Agent Registry: register agents, toggle status, view capabilities
- `/sessions` — A2A Sessions: session list, message drill-down, send messages
- `/threats` — Security Center: threat rules + events + severity chart
- `/recovery` — Recovery Router: kanban work queue, recovery event bus
- `/routing` — Cross-Model Router: mapping table, performance records
- `/proposals` — Proposal Engine: proposal cards, failure pattern table
- `/context` — Context & Shapley: domains, Shapley values, diversity stats + top contributors chart
- `/tournaments` — Coordination Tournaments: variant scoring, winner patterns
- `/strategies` — Meta-Learner: strategy lifecycle, lint results, learning curve chart

## API Endpoints (80+)

All endpoints under `/api/...` — full OpenAPI spec at `lib/api-spec/openapi.yaml`.

## Database

PostgreSQL via Drizzle ORM. Tables:
- agents, sessions, messages
- threat_rules, threat_events
- work_items, recovery_events
- routing_mappings, routing_performance
- proposals, failure_patterns
- context_domains, shapley_values
- tournaments, tournament_variants
- strategies

## GitHub Repository

https://github.com/w1123581321345589/agent-coordination-platform

## Development

```bash
# Install dependencies
pnpm install

# Run codegen (OpenAPI → React Query hooks + Zod schemas)
pnpm --filter @workspace/api-spec run codegen

# Push DB schema
pnpm --filter @workspace/db run push

# Start API server
pnpm --filter @workspace/api-server run dev

# Start frontend
pnpm --filter @workspace/platform run dev
```

## Environment Variables

- `DATABASE_URL` — PostgreSQL connection string (auto-provisioned by Replit)
- `SESSION_SECRET` — Session secret (set in Replit secrets)
- `PORT` — Port for frontend (set by Replit per artifact)
