# Coordination Platform - Setup Guide

## What This Is

8 Python modules that add multi-agent coordination verification, security,
and self-improvement to the existing Aiglos + Forge stack.

## Project Structure

```
coordination-platform/
  coordination/
    __init__.py              # Core types (AgentIdentity, CoordinationClaim, etc.)
    api.py                   # FastAPI server, 25 endpoints
    protocols/
      a2a.py                 # A2A protocol gateway
    security/
      a2a_interceptor.py     # A2A security (T104-T107, T111)
    engine/
      recovery_router.py     # Threat -> pause -> redistribute
      model_router.py        # Cross-model diversity routing
      context_router.py      # Shapley-value knowledge routing
      tournament.py          # Multi-variant strategy testing
    intelligence/
      agent_proposal.py      # Autonomy gap -> new agent proposals
      meta_learner.py        # INGEST/PROPOSE/LINT/EVOLVE lifecycle
  tests/
    test_coordination.py     # 65 tests
  integrations/
    aiglos/                  # Drop-in replacements for Aiglos repo files
      threat_engine_v2.py    # Replaces aiglos/core/threat_engine_v2.py
      __init__.py            # Replaces aiglos/__init__.py
      conftest.py            # Replaces tests/conftest.py
      test_a2a_security.py   # New file: tests/test_a2a_security.py
    forge/
      012_coordination_claims.sql  # New migration for forge/migrations/
```

## How to Run

### Standalone (coordination platform only):

```bash
pip install pydantic fastapi uvicorn
cd coordination-platform
python -m pytest tests/ -v          # 65 tests
uvicorn coordination.api:app --port 8420  # API server
```

### Integrating with Aiglos:

Copy these files into your Aiglos repo:
- `integrations/aiglos/threat_engine_v2.py` -> `aiglos/core/threat_engine_v2.py`
- `integrations/aiglos/__init__.py` -> `aiglos/__init__.py`
- `integrations/aiglos/conftest.py` -> `tests/conftest.py`
- `integrations/aiglos/test_a2a_security.py` -> `tests/test_a2a_security.py`

Then run: `python -m pytest tests/test_a2a_security.py -v`  (33 tests)

### Integrating with Forge:

Copy migration:
- `integrations/forge/012_coordination_claims.sql` -> `forge/migrations/012_coordination_claims.sql`

Then run: `psql $DATABASE_URL -f forge/migrations/012_coordination_claims.sql`

## API Endpoints

### Health
- `GET /health` - System health dashboard

### A2A Surface (inter-agent communication)
- `POST /a2a/register` - Register agent capabilities
- `POST /a2a/send` - Send A2A message (with security interception)
- `GET /a2a/discover` - Discover agents by capability/domain
- `GET /a2a/threats` - List detected threats
- `GET /a2a/stats` - Interceptor statistics

### Engine Surface (coordination)
- `POST /engine/recover` - Trigger recovery from compromised agent
- `POST /engine/tournament` - Run coordination strategy tournament
- `GET /engine/model-route` - Get optimal model for a role
- `GET /engine/pattern-win-rates` - Which patterns win most often

### Intelligence Surface (learning)
- `POST /intel/ingest` - Submit coordination record
- `POST /intel/propose` - Generate strategy proposals
- `POST /intel/approve/{id}` - Approve a proposal
- `GET /intel/lint` - Quality check the strategy registry
- `GET /intel/strategies` - List all learned strategies
- `GET /intel/learning-curve` - Coordination improvement over time
- `POST /intel/gap` - Record an autonomy gap
- `POST /intel/agent-proposals` - Generate new agent type proposals
- `POST /intel/shapley` - Compute agent contribution scores
- `GET /intel/redundant-agents` - Find low-contribution agents
- `GET /intel/top-contributors` - Ranked agent contributions

## Test Counts
- Coordination platform: 65 tests
- Aiglos A2A integration: 33 tests
- Aiglos core (no regressions): 151 tests
- Total: 249 tests, all passing
