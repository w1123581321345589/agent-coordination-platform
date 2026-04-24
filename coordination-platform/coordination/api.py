"""
Coordination Platform API Server

FastAPI wrapper that exposes the coordination platform's
capabilities over HTTP. Three surface areas:

1. /a2a/*     -- A2A protocol gateway with security interception
2. /engine/*  -- Coordination engine (tournaments, recovery, routing)
3. /intel/*   -- Intelligence layer (meta-learner, proposals, Shapley)

Deployment: uvicorn coordination.api:app --host 0.0.0.0 --port 8420
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class A2AMessageRequest(BaseModel):
    sender_id: str
    receiver_id: str
    message_type: str = "task/delegate"
    payload: dict[str, Any] = {}
    session_id: str = ""

class A2AMessageResponse(BaseModel):
    message_id: str = ""
    delivered: bool = False
    blocked: bool = False
    threats: list[dict] = []

class AgentRegisterRequest(BaseModel):
    agent_id: str
    name: str = ""
    capabilities: list[str] = []
    domain_tags: list[str] = []

class CoordinationRecordRequest(BaseModel):
    task_type: str
    domain: str = "general"
    pattern_used: str = "hierarchical"
    agents: list[str] = []
    outcome_score: float = 0.0
    duration_seconds: float = 0.0
    token_cost: int = 0
    escalation_count: int = 0
    claim_satisfied: bool = False

class ThreatRequest(BaseModel):
    rule_id: str
    agent_id: str
    severity: str = "medium"
    description: str = ""

class GapRequest(BaseModel):
    agent_id: str = ""
    agent_role: str = ""
    gap_type: str = ""
    domain: str = ""
    task_description: str = ""
    human_resolution: str = ""
    tools_needed: list[str] = []

class ShapleyRequest(BaseModel):
    session_agents: list[str]
    outcome_score: float
    individual_scores: dict[str, float]

class HealthResponse(BaseModel):
    status: str = "healthy"
    total_messages: int = 0
    threats_detected: int = 0
    active_sessions: int = 0
    registered_agents: int = 0
    coordination_records: int = 0
    strategy_registry_size: int = 0
    pending_proposals: int = 0
    recoveries: int = 0
    uptime_seconds: float = 0.0


# ---------------------------------------------------------------------------
# App Factory
# ---------------------------------------------------------------------------

def create_app():
    """Create and configure the FastAPI application."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        raise ImportError(
            "FastAPI required. Install with: pip install fastapi uvicorn"
        )

    from coordination import (
        A2AMessage, A2AMessageType, AgentIdentity,
        CoordinationPattern, CoordinationRecord,
        ThreatEvent, ThreatSeverity,
    )
    from coordination.protocols.a2a import A2AGateway, AgentCard
    from coordination.security.a2a_interceptor import A2AInterceptor
    from coordination.engine.recovery_router import RecoveryRouter, WorkItem
    from coordination.engine.model_router import ModelRouter
    from coordination.engine.context_router import ContextRouter, ContextItem, AgentScope
    from coordination.engine.tournament import CoordinationTournament
    from coordination.intelligence.agent_proposal import AgentProposalEngine, AutonomyGap
    from coordination.intelligence.meta_learner import CoordinationMetaLearner
    from coordination import CoordinationClaim

    # ── Initialize all subsystems ────────────────────────────────────────
    app = FastAPI(
        title="Coordination Platform",
        description="Verified, secured, self-improving coordination for multi-agent systems",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    start_time = time.time()

    gateway = A2AGateway()
    interceptor = A2AInterceptor()
    gateway.add_interceptor(interceptor.intercept)

    recovery = RecoveryRouter()
    model_router = ModelRouter()
    context_router = ContextRouter()
    tournament = CoordinationTournament()
    proposal_engine = AgentProposalEngine(cluster_threshold=3)
    meta_learner = CoordinationMetaLearner(min_samples_for_proposal=3)

    # ── Health ───────────────────────────────────────────────────────────

    @app.get("/health", response_model=HealthResponse)
    def health():
        return HealthResponse(
            total_messages=gateway.total_messages,
            threats_detected=len(interceptor.get_threats()),
            active_sessions=gateway.active_sessions,
            registered_agents=gateway.registered_agents,
            coordination_records=meta_learner.total_records,
            strategy_registry_size=meta_learner.registry_size,
            pending_proposals=len(meta_learner.pending_proposals),
            recoveries=recovery.total_recoveries,
            uptime_seconds=time.time() - start_time,
        )

    # ── A2A Surface ──────────────────────────────────────────────────────

    @app.post("/a2a/register")
    def register_agent(req: AgentRegisterRequest):
        card = AgentCard(
            agent_id=req.agent_id, name=req.name,
            capabilities=req.capabilities,
            domain_tags=req.domain_tags,
        )
        gateway.register_agent(card)
        interceptor.register_agent(req.agent_id, req.capabilities)
        agent = AgentIdentity(
            agent_id=req.agent_id, name=req.name,
            domain_tags=req.domain_tags,
            tool_scope=req.capabilities,
        )
        recovery.register_agent(agent)
        context_router.register_from_identity(agent)
        return {"registered": req.agent_id}

    @app.post("/a2a/send", response_model=A2AMessageResponse)
    def send_a2a_message(req: A2AMessageRequest):
        msg_type = A2AMessageType.TASK_DELEGATE
        for mt in A2AMessageType:
            if mt.value == req.message_type:
                msg_type = mt
                break

        msg = A2AMessage(
            message_type=msg_type,
            sender_id=req.sender_id,
            receiver_id=req.receiver_id,
            payload=req.payload,
            session_id=req.session_id or "",
        )
        result = gateway.send_message(msg)
        threats = interceptor.get_threats(since=time.time() - 1)

        return A2AMessageResponse(
            message_id=msg.message_id,
            delivered=result is not None,
            blocked=result is None,
            threats=[{
                "rule_id": t.rule_id,
                "severity": t.severity.value,
                "description": t.description,
            } for t in threats],
        )

    @app.get("/a2a/discover")
    def discover_agents(capability: str = "", domain: str = ""):
        cards = gateway.discover_agents(
            capability=capability or None,
            domain_tag=domain or None,
        )
        return [c.to_json() for c in cards]

    @app.get("/a2a/threats")
    def get_threats(since: float = 0):
        threats = interceptor.get_threats(since=since or None)
        return [{
            "event_id": t.event_id,
            "rule_id": t.rule_id,
            "severity": t.severity.value,
            "agent_id": t.agent_id,
            "description": t.description,
            "timestamp": t.timestamp,
        } for t in threats]

    @app.get("/a2a/stats")
    def interceptor_stats():
        return interceptor.stats

    # ── Engine Surface ───────────────────────────────────────────────────

    @app.post("/engine/recover")
    def trigger_recovery(req: ThreatRequest):
        severity_map = {
            "low": ThreatSeverity.LOW, "medium": ThreatSeverity.MEDIUM,
            "high": ThreatSeverity.HIGH, "critical": ThreatSeverity.CRITICAL,
        }
        threat = ThreatEvent(
            rule_id=req.rule_id, agent_id=req.agent_id,
            severity=severity_map.get(req.severity, ThreatSeverity.MEDIUM),
            description=req.description,
        )
        event = recovery.handle_threat(threat)
        return {
            "event_id": event.event_id,
            "agent_id": event.agent_id,
            "work_items_redistributed": len(event.work_items_redistributed),
            "recovery_claim_id": event.recovery_claim_id,
        }

    @app.post("/engine/tournament")
    def run_tournament(task_type: str = "", domain: str = "general"):
        claim = CoordinationClaim(
            description=f"Tournament for {task_type} in {domain}",
            success_criteria={"domain": domain, "task_type": task_type},
        )
        agents = [AgentIdentity(agent_id=f"agent-{i}") for i in range(3)]
        result = tournament.run(claim, agents)
        return {
            "tournament_id": result.tournament_id,
            "winner_pattern": result.winning_pattern.value,
            "margin": result.margin,
            "variants_tested": len(result.variants),
        }

    @app.get("/engine/model-route")
    def get_model_route(role: str):
        agent = AgentIdentity(role=role)
        model = model_router.route(agent)
        cross_verify = model_router.should_cross_verify(agent)
        return {
            "role": role,
            "provider": model.provider.value,
            "model": model.model_name,
            "cross_verify_with": cross_verify,
        }

    @app.get("/engine/pattern-win-rates")
    def pattern_win_rates():
        return tournament.get_pattern_win_rates()

    # ── Intelligence Surface ─────────────────────────────────────────────

    @app.post("/intel/ingest")
    def ingest_record(req: CoordinationRecordRequest):
        pattern_map = {
            "hierarchical": CoordinationPattern.HIERARCHICAL,
            "debate": CoordinationPattern.DEBATE,
            "parallel_merge": CoordinationPattern.PARALLEL_MERGE,
            "pipeline": CoordinationPattern.PIPELINE,
            "swarm": CoordinationPattern.SWARM,
        }
        record = CoordinationRecord(
            task_type=req.task_type, domain=req.domain,
            pattern_used=pattern_map.get(req.pattern_used, CoordinationPattern.HIERARCHICAL),
            agents=[AgentIdentity(agent_id=a) for a in req.agents],
            outcome_score=req.outcome_score,
            duration_seconds=req.duration_seconds,
            token_cost=req.token_cost,
            escalation_count=req.escalation_count,
            claim_satisfied=req.claim_satisfied,
        )
        meta_learner.ingest(record)
        return {"ingested": True, "total_records": meta_learner.total_records}

    @app.post("/intel/propose")
    def generate_proposals():
        proposals = meta_learner.propose()
        return [{
            "proposal_id": p.proposal_id,
            "type": p.proposal_type,
            "description": p.description,
            "evidence_strength": p.evidence_strength,
        } for p in proposals]

    @app.post("/intel/approve/{proposal_id}")
    def approve_proposal(proposal_id: str):
        entry = meta_learner.approve_proposal(proposal_id)
        if not entry:
            raise HTTPException(404, "Proposal not found")
        return {
            "approved": True,
            "strategy": {
                "task_type": entry.task_type,
                "domain": entry.domain,
                "pattern": entry.recommended_pattern.value,
                "confidence": float(entry.confidence),
            },
        }

    @app.get("/intel/lint")
    def lint_registry():
        report = meta_learner.lint()
        return {
            "health_score": report.health_score,
            "entries_checked": report.entries_checked,
            "findings": [{
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "recommendation": f.recommendation,
            } for f in report.findings],
        }

    @app.get("/intel/strategies")
    def list_strategies():
        strategies = meta_learner.get_all_strategies()
        return {k: {
            "pattern": v.recommended_pattern.value,
            "agent_count": v.recommended_agent_count,
            "confidence": float(v.confidence),
            "avg_score": float(v.avg_outcome_score),
            "sample_size": v.sample_size,
        } for k, v in strategies.items()}

    @app.get("/intel/learning-curve")
    def learning_curve():
        return meta_learner.get_learning_curve()

    @app.post("/intel/gap")
    def record_gap(req: GapRequest):
        gap = AutonomyGap(
            agent_id=req.agent_id, agent_role=req.agent_role,
            gap_type=req.gap_type, domain=req.domain,
            task_description=req.task_description,
            human_resolution=req.human_resolution,
            tools_needed=req.tools_needed,
        )
        proposal_engine.record_gap(gap)
        return {"recorded": True, "total_gaps": proposal_engine.total_gaps}

    @app.post("/intel/agent-proposals")
    def generate_agent_proposals():
        proposals = proposal_engine.generate_proposals()
        return [{
            "proposal_id": p.proposal_id,
            "name": p.name,
            "role": p.role,
            "rationale": p.rationale,
        } for p in proposals]

    @app.post("/intel/shapley")
    def compute_shapley(req: ShapleyRequest):
        results = context_router.compute_shapley(
            session_agents=req.session_agents,
            outcome_score=req.outcome_score,
            individual_scores=req.individual_scores,
        )
        return {
            agent_id: {
                "marginal_value": float(c.marginal_value),
            }
            for agent_id, c in results.items()
        }

    @app.get("/intel/redundant-agents")
    def get_redundant_agents(threshold: float = 0.05):
        return {"redundant": context_router.get_redundant_agents(threshold)}

    @app.get("/intel/top-contributors")
    def get_top_contributors(n: int = 10):
        return [{"agent_id": a, "avg_contribution": float(s)}
                for a, s in context_router.get_top_contributors(n)]

    return app


# Module-level app instance for uvicorn
try:
    app = create_app()
except ImportError:
    app = None  # FastAPI not installed, skip
