# Agent Coordination Platform

Full-stack platform for coordinating multi-agent AI systems.

## Modules
- **A2A Protocol** — Agent-to-agent session management and message routing
- **A2A Security** — Threat detection, rule enforcement, and event resolution
- **Recovery Router** — Work item queue with automatic failover and redistribution
- **Cross-Model Router** — Dynamic role-to-provider routing with performance learning
- **Agent Proposal Engine** — Failure-pattern clustering and agent capability proposals
- **Context Router + Shapley** — Knowledge domain management and Shapley value attribution
- **Coordination Tournament** — Hierarchical/debate/parallel variant scoring
- **Meta-Learner** — Strategy lifecycle management with lint validation and learning curves

## Stack
- **Frontend**: React + Vite + shadcn/ui + recharts + wouter
- **Backend**: Express 5 + Drizzle ORM + PostgreSQL
- **API**: OpenAPI 3.1 spec with Orval codegen (React Query hooks + Zod schemas)
- **Monorepo**: pnpm workspaces
