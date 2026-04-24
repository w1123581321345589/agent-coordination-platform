-- Forge migration 012: coordination claims and meta-learner
--
-- Extends the intent graph from single-agent behavioral units to
-- multi-agent coordination claims. Adds the data model for the
-- coordination meta-learner (INGEST/PROPOSE/LINT/EVOLVE lifecycle).
--
-- Tables:
--   coordination_claims    -- multi-agent behavioral claims (extends BUs)
--   coordination_records   -- completed coordination sessions (meta-learner INGEST)
--   coordination_strategies -- learned optimal strategies (meta-learner registry)
--   strategy_proposals     -- proposed strategy changes (PROPOSE lifecycle)
--   agent_contributions    -- per-agent Shapley value contributions

-- ─── Coordination Claims ─────────────────────────────────────────────────────
-- A behavioral claim about how agents should coordinate.
-- References the intent graph: each claim can depend on BUs or other claims.

CREATE TABLE IF NOT EXISTS coordination_claims (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  description           TEXT NOT NULL,
  pattern               TEXT NOT NULL DEFAULT 'hierarchical'
                        CHECK (pattern IN ('hierarchical', 'debate', 'parallel_merge', 'pipeline', 'swarm')),
  participating_agents  TEXT[] NOT NULL DEFAULT '{}',
  max_duration_seconds  NUMERIC,
  max_escalations       INTEGER,
  success_criteria      JSONB NOT NULL DEFAULT '{}',
  -- Intent graph integration
  bu_id                 UUID REFERENCES behavioral_units(id) ON DELETE SET NULL,
  depends_on            UUID[] DEFAULT '{}',         -- other claim IDs
  active                BOOLEAN NOT NULL DEFAULT true,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cc_pattern_idx ON coordination_claims (pattern) WHERE active = true;
CREATE INDEX IF NOT EXISTS cc_active_idx ON coordination_claims (active, created_at DESC);

CREATE OR REPLACE TRIGGER coordination_claims_updated_at
  BEFORE UPDATE ON coordination_claims
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Coordination Records ────────────────────────────────────────────────────
-- Immutable record of a completed coordination session.
-- The meta-learner INGESTs these to learn optimal strategies.

CREATE TABLE IF NOT EXISTS coordination_records (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id              UUID REFERENCES coordination_claims(id) ON DELETE SET NULL,
  pattern_used          TEXT NOT NULL,
  task_type             TEXT NOT NULL DEFAULT '',
  domain                TEXT NOT NULL DEFAULT 'general',
  agents                JSONB NOT NULL DEFAULT '[]',   -- array of agent identities
  started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at          TIMESTAMPTZ,
  duration_seconds      NUMERIC NOT NULL DEFAULT 0,
  token_cost            INTEGER NOT NULL DEFAULT 0,
  escalation_count      INTEGER NOT NULL DEFAULT 0,
  claim_satisfied       BOOLEAN NOT NULL DEFAULT false,
  outcome_score         NUMERIC(4,3) NOT NULL DEFAULT 0,
  model_providers_used  TEXT[] DEFAULT '{}',
  metadata              JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS cr_task_domain_idx
  ON coordination_records (task_type, domain);
CREATE INDEX IF NOT EXISTS cr_pattern_idx
  ON coordination_records (pattern_used);
CREATE INDEX IF NOT EXISTS cr_started_idx
  ON coordination_records (started_at DESC);

-- ─── Agent Contributions (Shapley Values) ────────────────────────────────────
-- Per-agent marginal contribution for each coordination session.

CREATE TABLE IF NOT EXISTS agent_contributions (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id             UUID NOT NULL REFERENCES coordination_records(id) ON DELETE CASCADE,
  agent_id              TEXT NOT NULL,
  marginal_value        NUMERIC(6,4) NOT NULL DEFAULT 0,
  actions_taken         INTEGER NOT NULL DEFAULT 0,
  tokens_consumed       INTEGER NOT NULL DEFAULT 0,
  escalations_caused    INTEGER NOT NULL DEFAULT 0,
  knowledge_contributed INTEGER NOT NULL DEFAULT 0,
  computed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ac_agent_idx ON agent_contributions (agent_id);
CREATE INDEX IF NOT EXISTS ac_record_idx ON agent_contributions (record_id);

-- ─── Coordination Strategies (Meta-Learner Registry) ─────────────────────────
-- Learned optimal coordination strategies per task-domain combination.

CREATE TABLE IF NOT EXISTS coordination_strategies (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_type                 TEXT NOT NULL,
  domain                    TEXT NOT NULL DEFAULT 'general',
  recommended_pattern       TEXT NOT NULL DEFAULT 'hierarchical',
  recommended_agent_count   INTEGER NOT NULL DEFAULT 3,
  recommended_models        JSONB DEFAULT '{}',        -- role -> model mapping
  confidence                NUMERIC(3,2) NOT NULL DEFAULT 0
                            CHECK (confidence BETWEEN 0 AND 1),
  sample_size               INTEGER NOT NULL DEFAULT 0,
  avg_outcome_score         NUMERIC(4,3) DEFAULT 0,
  avg_duration_seconds      NUMERIC DEFAULT 0,
  avg_token_cost            NUMERIC DEFAULT 0,
  avg_escalations           NUMERIC DEFAULT 0,
  notes                     TEXT DEFAULT '',
  active                    BOOLEAN NOT NULL DEFAULT true,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (task_type, domain)
);

CREATE OR REPLACE TRIGGER coordination_strategies_updated_at
  BEFORE UPDATE ON coordination_strategies
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Strategy Proposals (PROPOSE Lifecycle) ──────────────────────────────────
-- Proposed changes to coordination strategies.
-- Same lifecycle as Aiglos policy proposals: pending -> approved/rejected -> expired/rolled_back.

CREATE TABLE IF NOT EXISTS strategy_proposals (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  proposal_type         TEXT NOT NULL,                 -- SWITCH_PATTERN, CHANGE_AGENT_COUNT, CHANGE_MODEL
  description           TEXT NOT NULL,
  evidence              JSONB NOT NULL DEFAULT '[]',
  evidence_strength     NUMERIC(3,2) DEFAULT 0,
  current_strategy      JSONB DEFAULT '{}',
  proposed_strategy     JSONB DEFAULT '{}',
  status                TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'rolled_back')),
  strategy_id           UUID REFERENCES coordination_strategies(id) ON DELETE SET NULL,
  reviewed_by           TEXT,
  review_notes          TEXT DEFAULT '',
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at            TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')
);

CREATE INDEX IF NOT EXISTS sp_status_idx
  ON strategy_proposals (status, created_at DESC)
  WHERE status = 'pending';

-- ─── Tournament Results ──────────────────────────────────────────────────────
-- Records of coordination tournament runs (multi-variant strategy testing).

CREATE TABLE IF NOT EXISTS tournament_results (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id              UUID REFERENCES coordination_claims(id) ON DELETE SET NULL,
  variants              JSONB NOT NULL DEFAULT '[]',   -- array of variant configs
  results               JSONB NOT NULL DEFAULT '[]',   -- array of variant results
  winner_variant_id     TEXT,
  winning_pattern       TEXT,
  margin                NUMERIC(4,3) DEFAULT 0,
  started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at          TIMESTAMPTZ
);

-- ─── Recovery Events ─────────────────────────────────────────────────────────
-- Records of automated recovery from compromised/failing agents.

CREATE TABLE IF NOT EXISTS recovery_events (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id                  TEXT NOT NULL,
  threat_rule_id            TEXT,                      -- e.g. T25, T104
  threat_description        TEXT,
  work_items_redistributed  INTEGER NOT NULL DEFAULT 0,
  recovery_claim_id         UUID REFERENCES coordination_claims(id) ON DELETE SET NULL,
  annotation_id             UUID REFERENCES domain_annotations(id) ON DELETE SET NULL,
  resolved                  BOOLEAN NOT NULL DEFAULT false,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS re_agent_idx ON recovery_events (agent_id, created_at DESC);

-- ─── Views ───────────────────────────────────────────────────────────────────

-- Pattern performance summary for the meta-learner
CREATE OR REPLACE VIEW v_pattern_performance AS
SELECT
  pattern_used,
  task_type,
  domain,
  COUNT(*) as session_count,
  AVG(outcome_score) as avg_score,
  AVG(duration_seconds) as avg_duration,
  AVG(token_cost) as avg_cost,
  AVG(escalation_count) as avg_escalations,
  SUM(CASE WHEN claim_satisfied THEN 1 ELSE 0 END)::NUMERIC / COUNT(*) as satisfaction_rate
FROM coordination_records
GROUP BY pattern_used, task_type, domain;

-- Agent contribution leaderboard
CREATE OR REPLACE VIEW v_agent_leaderboard AS
SELECT
  agent_id,
  COUNT(*) as sessions,
  AVG(marginal_value) as avg_contribution,
  SUM(tokens_consumed) as total_tokens,
  SUM(escalations_caused) as total_escalations,
  SUM(knowledge_contributed) as total_knowledge
FROM agent_contributions
GROUP BY agent_id
ORDER BY avg_contribution DESC;

-- Coordination health dashboard
CREATE OR REPLACE VIEW v_coordination_health AS
SELECT
  domain,
  COUNT(DISTINCT cr.id) as total_sessions,
  AVG(cr.outcome_score) as avg_score,
  COUNT(DISTINCT re.id) as recovery_events,
  COUNT(DISTINCT sp.id) FILTER (WHERE sp.status = 'pending') as pending_proposals,
  MAX(cr.started_at) as last_session
FROM coordination_records cr
LEFT JOIN recovery_events re ON re.created_at > NOW() - INTERVAL '30 days'
  AND re.agent_id = ANY(
    SELECT jsonb_array_elements_text(cr.agents::jsonb)
  )
LEFT JOIN strategy_proposals sp ON sp.proposed_strategy->>'domain' = cr.domain
GROUP BY domain;
