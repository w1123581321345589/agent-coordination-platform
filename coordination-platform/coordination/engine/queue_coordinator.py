"""
Queue Coordinator

The universal triage layer. Takes any work queue (GitHub issues,
support tickets, resumes, emails, leads) and coordinates agents
to process it with verification, security, and self-improvement.

This is the product surface. Everything else in the coordination
platform is infrastructure this module consumes.

Usage:
    coordinator = QueueCoordinator(domain="github_issues")
    coordinator.register_agent(scanner_agent)
    coordinator.register_agent(verifier_agent)

    for issue in github_issues:
        coordinator.submit(issue)

    results = coordinator.drain()
    # Results include: decision, confidence, evidence trail,
    # Shapley contribution per agent, threat alerts

The coordinator automatically:
- Routes items to agents based on domain scope
- Runs multi-trial tournaments on ambiguous items
- Tracks Shapley values to identify redundant agents
- Updates BLF belief states on triage strategies
- Detects hallucination cascades (T78) and overconfident closures
- Learns which triage patterns work via meta-learner
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from coordination import (
    A2AMessage,
    A2AMessageType,
    AgentIdentity,
    CoordinationClaim,
    CoordinationPattern,
    CoordinationRecord,
    ModelProvider,
    ThreatEvent,
    ThreatSeverity,
)
from coordination.engine.context_router import ContextRouter, ContextItem, AgentScope
from coordination.engine.tournament import CoordinationTournament, _loo_shrinkage
from coordination.intelligence.meta_learner import (
    CoordinationMetaLearner,
    BeliefState,
)
from coordination.security.a2a_interceptor import A2AInterceptor


# ---------------------------------------------------------------------------
# Queue Item
# ---------------------------------------------------------------------------

class TriageDecision(Enum):
    """Standard triage outcomes."""
    CLOSE = "close"
    ESCALATE = "escalate"
    ROUTE = "route"
    DEFER = "defer"
    REJECT = "reject"
    ACCEPT = "accept"
    FLAG = "flag"


@dataclass
class QueueItem:
    """A single item in any work queue."""
    item_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = ""            # "github", "email", "support", "resume", etc.
    priority: int = 0
    submitted_at: float = field(default_factory=time.time)


@dataclass
class TriageResult:
    """The coordinated triage outcome for a queue item."""
    item_id: str = ""
    decision: TriageDecision = TriageDecision.DEFER
    confidence: float = 0.0
    evidence: str = ""          # BLF linguistic evidence trail
    agent_contributions: dict[str, float] = field(default_factory=dict)
    threats_detected: list[str] = field(default_factory=list)
    pattern_used: str = ""
    agents_used: int = 0
    token_cost: int = 0
    duration_seconds: float = 0.0
    needs_human_review: bool = False
    review_reason: str = ""


# ---------------------------------------------------------------------------
# Triage Rule (domain-specific decision logic)
# ---------------------------------------------------------------------------

@dataclass
class TriageRule:
    """
    A domain-specific triage rule.
    The meta-learner proposes new rules from accumulated data.
    """
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    condition: str = ""         # natural language condition
    decision: TriageDecision = TriageDecision.DEFER
    confidence_threshold: float = 0.7
    domain: str = ""
    belief: BeliefState = field(default_factory=BeliefState)
    enabled: bool = True


# ---------------------------------------------------------------------------
# Queue Templates (pre-built for common use cases)
# ---------------------------------------------------------------------------

QUEUE_TEMPLATES: dict[str, list[TriageRule]] = {
    "github_issues": [
        TriageRule(
            name="already_implemented",
            condition="Issue describes functionality that already exists in the codebase",
            decision=TriageDecision.CLOSE,
            confidence_threshold=0.85,
            domain="github_issues",
        ),
        TriageRule(
            name="duplicate",
            condition="Issue is a duplicate of an existing open issue",
            decision=TriageDecision.CLOSE,
            confidence_threshold=0.80,
            domain="github_issues",
        ),
        TriageRule(
            name="stale_no_repro",
            condition="Issue is older than 6 months with no reproduction steps and no recent activity",
            decision=TriageDecision.CLOSE,
            confidence_threshold=0.75,
            domain="github_issues",
        ),
        TriageRule(
            name="nonsensical",
            condition="Issue is spam, bot-generated, or contains no actionable information",
            decision=TriageDecision.REJECT,
            confidence_threshold=0.90,
            domain="github_issues",
        ),
        TriageRule(
            name="valid_bug",
            condition="Issue describes a reproducible bug with clear steps",
            decision=TriageDecision.ESCALATE,
            confidence_threshold=0.70,
            domain="github_issues",
        ),
        TriageRule(
            name="feature_request",
            condition="Issue is a well-formed feature request with clear use case",
            decision=TriageDecision.ROUTE,
            confidence_threshold=0.65,
            domain="github_issues",
        ),
    ],
    "support_tickets": [
        TriageRule(name="password_reset", condition="User needs password reset",
                   decision=TriageDecision.ROUTE, confidence_threshold=0.90,
                   domain="support"),
        TriageRule(name="billing_issue", condition="User has a billing or payment issue",
                   decision=TriageDecision.ESCALATE, confidence_threshold=0.75,
                   domain="support"),
        TriageRule(name="feature_question", condition="User asking how to use a feature",
                   decision=TriageDecision.ROUTE, confidence_threshold=0.70,
                   domain="support"),
        TriageRule(name="angry_customer", condition="User is expressing frustration or threatening to churn",
                   decision=TriageDecision.ESCALATE, confidence_threshold=0.80,
                   domain="support"),
    ],
    "resume_screening": [
        TriageRule(name="strong_match", condition="Candidate has 80%+ of required qualifications",
                   decision=TriageDecision.ACCEPT, confidence_threshold=0.75,
                   domain="hiring"),
        TriageRule(name="no_match", condition="Candidate lacks core requirements (language, experience level)",
                   decision=TriageDecision.REJECT, confidence_threshold=0.85,
                   domain="hiring"),
        TriageRule(name="maybe_match", condition="Candidate has transferable skills but missing specifics",
                   decision=TriageDecision.FLAG, confidence_threshold=0.60,
                   domain="hiring"),
    ],
    "sales_leads": [
        TriageRule(name="hot_lead", condition="Lead matches ICP, has budget signal, and recent activity",
                   decision=TriageDecision.ESCALATE, confidence_threshold=0.75,
                   domain="sales"),
        TriageRule(name="nurture", condition="Lead matches ICP but no urgency signal",
                   decision=TriageDecision.ROUTE, confidence_threshold=0.65,
                   domain="sales"),
        TriageRule(name="disqualified", condition="Lead is outside target market, wrong geo, or competitor",
                   decision=TriageDecision.REJECT, confidence_threshold=0.85,
                   domain="sales"),
    ],
    "email_triage": [
        TriageRule(name="urgent_action", condition="Email requires action within 24 hours",
                   decision=TriageDecision.ESCALATE, confidence_threshold=0.80,
                   domain="email"),
        TriageRule(name="fyi_only", condition="Email is informational with no action required",
                   decision=TriageDecision.DEFER, confidence_threshold=0.70,
                   domain="email"),
        TriageRule(name="newsletter_noise", condition="Email is automated newsletter or marketing",
                   decision=TriageDecision.CLOSE, confidence_threshold=0.90,
                   domain="email"),
    ],
}


# ---------------------------------------------------------------------------
# Queue Coordinator
# ---------------------------------------------------------------------------

class QueueCoordinator:
    """
    Universal queue triage coordinator.

    Point it at any work queue. It coordinates agents to process
    items with verification, security, and self-improvement.
    """

    def __init__(
        self,
        domain: str = "general",
        template: str | None = None,
        confidence_threshold: float = 0.7,
        max_agents_per_item: int = 5,
        enable_multi_trial: bool = True,
    ) -> None:
        self.domain = domain
        self._confidence_threshold = confidence_threshold
        self._max_agents = max_agents_per_item
        self._enable_multi_trial = enable_multi_trial

        # Load template rules if specified
        self._rules: list[TriageRule] = []
        if template and template in QUEUE_TEMPLATES:
            self._rules = list(QUEUE_TEMPLATES[template])
        elif domain in QUEUE_TEMPLATES:
            self._rules = list(QUEUE_TEMPLATES[domain])

        # Subsystems
        self._agents: list[AgentIdentity] = []
        self._context_router = ContextRouter()
        self._tournament = CoordinationTournament()
        self._meta_learner = CoordinationMetaLearner(min_samples_for_proposal=5)
        self._interceptor = A2AInterceptor()

        # Queue
        self._pending: list[QueueItem] = []
        self._results: list[TriageResult] = []

        # Stats
        self._total_processed = 0
        self._total_escalated = 0
        self._total_auto_resolved = 0

    # -- Agent Registration --

    def register_agent(self, agent: AgentIdentity) -> None:
        self._agents.append(agent)
        self._interceptor.register_agent(agent.agent_id, agent.tool_scope)
        self._context_router.register_from_identity(agent)

    # -- Queue Operations --

    def submit(self, item: QueueItem) -> None:
        """Submit an item to the triage queue."""
        self._pending.append(item)

    def submit_batch(self, items: list[QueueItem]) -> int:
        self._pending.extend(items)
        return len(items)

    def process_one(self, item: QueueItem) -> TriageResult:
        """
        Process a single queue item through the full coordination stack.
        """
        start = time.time()

        # Step 1: Security check on the item content
        threats = self._check_threats(item)

        # Step 2: Match against triage rules
        matched_rule, rule_confidence = self._match_rules(item)

        # Step 3: If confident enough, auto-resolve
        if matched_rule and rule_confidence >= self._confidence_threshold:
            result = TriageResult(
                item_id=item.item_id,
                decision=matched_rule.decision,
                confidence=rule_confidence,
                evidence=f"Rule '{matched_rule.name}' matched with confidence {rule_confidence:.2f}",
                threats_detected=[t.rule_id for t in threats],
                pattern_used="rule_match",
                agents_used=1,
                duration_seconds=time.time() - start,
            )

            # Update rule belief
            matched_rule.belief.update(
                f"Auto-resolved item {item.item_id[:8]} via {matched_rule.name}",
                new_p=min(0.95, rule_confidence),
                source=f"item:{item.item_id}",
            )

            self._total_auto_resolved += 1

        # Step 4: If not confident, run tournament with multiple agents
        elif len(self._agents) >= 2:
            result = self._tournament_triage(item, threats, start)

        # Step 5: If no agents, defer for human review
        else:
            result = TriageResult(
                item_id=item.item_id,
                decision=TriageDecision.DEFER,
                confidence=0.0,
                evidence="No agents available and no rule matched",
                needs_human_review=True,
                review_reason="No agents registered",
                duration_seconds=time.time() - start,
            )

        # Step 6: Flag for human review if threats detected
        if threats:
            result.needs_human_review = True
            result.review_reason = f"Threats detected: {', '.join(t.rule_id for t in threats)}"

        # Step 7: Ingest coordination record for meta-learner
        self._record_outcome(item, result)

        self._results.append(result)
        self._total_processed += 1

        return result

    def drain(self) -> list[TriageResult]:
        """Process all pending items and return results."""
        results: list[TriageResult] = []
        while self._pending:
            item = self._pending.pop(0)
            result = self.process_one(item)
            results.append(result)
        return results

    # -- Internal Processing Steps --

    def _check_threats(self, item: QueueItem) -> list[ThreatEvent]:
        """Run item content through A2A interceptor for safety."""
        msg = A2AMessage(
            message_type=A2AMessageType.TASK_DELEGATE,
            sender_id="queue_coordinator",
            receiver_id="triage_agent",
            payload={"task": item.content, "source": item.source},
        )
        result = self._interceptor.intercept(msg)
        if result is None:
            return self._interceptor.get_threats(since=time.time() - 1)
        return []

    def _match_rules(self, item: QueueItem) -> tuple[TriageRule | None, float]:
        """
        Match item against triage rules.
        Returns best matching rule and confidence.

        In production this would use LLM classification.
        Here we use keyword matching as the skeleton.
        """
        best_rule: TriageRule | None = None
        best_confidence = 0.0
        content_lower = item.content.lower()

        for rule in self._rules:
            if not rule.enabled:
                continue

            # Simple keyword extraction from rule condition
            condition_words = set(rule.condition.lower().split())
            content_words = set(content_lower.split())
            overlap = len(condition_words & content_words)

            if overlap > 0:
                # Confidence based on word overlap ratio
                confidence = min(0.95, overlap / max(len(condition_words), 1))
                # Weight by rule's belief state
                confidence *= (0.5 + 0.5 * rule.belief.probability)

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_rule = rule

        return best_rule, best_confidence

    def _tournament_triage(
        self, item: QueueItem, threats: list[ThreatEvent], start: float,
    ) -> TriageResult:
        """Run a coordination tournament for ambiguous items."""
        claim = CoordinationClaim(
            description=f"Triage item: {item.content[:100]}",
            participating_agents=[a.agent_id for a in self._agents[:self._max_agents]],
            success_criteria={"domain": self.domain, "item_id": item.item_id},
        )

        if self._enable_multi_trial:
            tournament_result = self._tournament.multi_trial_run(
                claim, self._agents[:self._max_agents], k_trials=3,
            )
        else:
            tournament_result = self._tournament.run(
                claim, self._agents[:self._max_agents],
            )

        # Compute Shapley contributions
        agent_ids = [a.agent_id for a in self._agents[:self._max_agents]]
        individual_scores = {
            a: 0.5 for a in agent_ids  # placeholder; real system uses agent outputs
        }
        shapley = self._context_router.compute_shapley(
            session_agents=agent_ids,
            outcome_score=tournament_result.margin,
            individual_scores=individual_scores,
        )

        winner = tournament_result.winner
        self._total_escalated += 1

        return TriageResult(
            item_id=item.item_id,
            decision=TriageDecision.ESCALATE,
            confidence=tournament_result.margin,
            evidence=f"Tournament: {tournament_result.winning_pattern.value} won with margin {tournament_result.margin:.3f}",
            agent_contributions={aid: c.marginal_value for aid, c in shapley.items()},
            threats_detected=[t.rule_id for t in threats],
            pattern_used=tournament_result.winning_pattern.value,
            agents_used=len(agent_ids),
            token_cost=winner.token_cost if winner else 0,
            duration_seconds=time.time() - start,
        )

    def _record_outcome(self, item: QueueItem, result: TriageResult) -> None:
        """Feed the outcome to the meta-learner."""
        pattern_map = {
            "rule_match": CoordinationPattern.PIPELINE,
            "hierarchical": CoordinationPattern.HIERARCHICAL,
            "debate": CoordinationPattern.DEBATE,
            "parallel_merge": CoordinationPattern.PARALLEL_MERGE,
        }
        record = CoordinationRecord(
            task_type=f"triage_{self.domain}",
            domain=self.domain,
            pattern_used=pattern_map.get(result.pattern_used, CoordinationPattern.PIPELINE),
            outcome_score=result.confidence,
            duration_seconds=result.duration_seconds,
            token_cost=result.token_cost,
            escalation_count=1 if result.needs_human_review else 0,
            claim_satisfied=result.confidence >= self._confidence_threshold,
            agents=[AgentIdentity(agent_id=a) for a in result.agent_contributions],
        )
        self._meta_learner.ingest(record)

    # -- Rule Management --

    def add_rule(self, rule: TriageRule) -> None:
        self._rules.append(rule)

    def disable_rule(self, rule_id: str) -> None:
        for r in self._rules:
            if r.rule_id == rule_id:
                r.enabled = False

    def get_rule_beliefs(self) -> list[dict[str, Any]]:
        """Get BLF belief states for all triage rules."""
        return [{
            "rule_id": r.rule_id,
            "name": r.name,
            "decision": r.decision.value,
            "probability": r.belief.probability,
            "evidence_summary": r.belief.evidence_summary,
            "updates": r.belief.update_count,
            "confident": r.belief.is_confident,
        } for r in self._rules]

    # -- Analytics --

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_processed": self._total_processed,
            "auto_resolved": self._total_auto_resolved,
            "escalated": self._total_escalated,
            "auto_resolve_rate": self._total_auto_resolved / max(self._total_processed, 1),
            "pending": len(self._pending),
            "agents": len(self._agents),
            "rules": len(self._rules),
            "meta_learner_records": self._meta_learner.total_records,
            "redundant_agents": self._context_router.get_redundant_agents(),
        }

    def get_agent_efficiency(self) -> list[dict[str, Any]]:
        """Which agents are actually contributing?"""
        top = self._context_router.get_top_contributors(len(self._agents))
        redundant = set(self._context_router.get_redundant_agents())
        return [{
            "agent_id": aid,
            "avg_contribution": float(score),
            "redundant": aid in redundant,
        } for aid, score in top]

    def propose_improvements(self) -> list[dict[str, Any]]:
        """Ask the meta-learner for strategy improvements."""
        proposals = self._meta_learner.propose()
        return [{
            "proposal_id": p.proposal_id,
            "type": p.proposal_type,
            "description": p.description,
            "evidence_strength": p.evidence_strength,
        } for p in proposals]

    @property
    def optimal_agent_count(self) -> int | None:
        """
        Based on Shapley data, how many agents should you actually run?
        steipete runs 50. The answer is probably 12.
        """
        redundant = self._context_router.get_redundant_agents()
        if not redundant:
            return None
        return len(self._agents) - len(redundant)
