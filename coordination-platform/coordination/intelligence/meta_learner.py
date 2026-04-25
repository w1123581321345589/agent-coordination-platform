"""
Build 8: Coordination Meta-Learner

Applies the Karpathy wiki INGEST/PROPOSE/LINT/EVOLVE lifecycle
to coordination strategy data instead of threat intelligence.

This is the self-improving coordination layer.

The loop:
1. INGEST: coordination records accumulate after every session
2. PROPOSE: weekly analysis generates strategy proposals
3. LINT: automated quality checks on the strategy database
4. EVOLVE: approved proposals update the coordination strategy registry

Reuses:
- Wiki INGEST/PROPOSE/LINT/EVOLVE lifecycle architecture
- Policy proposal system (approve/reject/rollback)
- Regime classifier pattern (conditional strategy selection)
- Behavioral baseline (performance tracking)
- Tournament results (experimental data)

New:
- Coordination record schema
- Strategy registry
- Pattern-task-domain performance index
- Meta-coordination recommendations
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from coordination import (
    CoordinationPattern,
    CoordinationRecord,
    ProposalStatus,
    StrategyProposal,
)


# ---------------------------------------------------------------------------
# BLF: Linguistic Belief State (Murphy, UBC)
# ---------------------------------------------------------------------------

@dataclass
class BeliefState:
    """
    Semi-structured linguistic belief state (BLF pattern).
    Pairs a probability estimate with a natural-language evidence
    summary that updates at each step, approximating sequential
    Bayesian inference.
    """
    probability: float = 0.5        # p(this strategy is optimal)
    evidence_summary: str = ""      # WHY we believe this
    update_count: int = 0           # how many updates have been applied
    evidence_log: list[dict] = field(default_factory=list)  # timestamped evidence trail

    def update(self, new_evidence: str, new_p: float, source: str = "") -> None:
        """
        Bayesian-style belief update. Moves probability toward new_p
        weighted by update count (earlier updates move more).
        Appends evidence to the linguistic summary.
        """
        # Learning rate decays with evidence count (shrinkage toward stability)
        lr = 1.0 / (1.0 + self.update_count * 0.3)
        self.probability = self.probability + lr * (new_p - self.probability)
        self.probability = max(0.01, min(0.99, self.probability))

        self.update_count += 1
        self.evidence_log.append({
            "step": self.update_count,
            "p": round(self.probability, 3),
            "evidence": new_evidence,
            "source": source,
            "timestamp": time.time(),
        })

        # Rebuild linguistic summary from the last 5 evidence entries
        recent = self.evidence_log[-5:]
        parts = [f"[p={e['p']}] {e['evidence']}" for e in recent]
        self.evidence_summary = " | ".join(parts)

    @property
    def is_confident(self) -> bool:
        """Belief is confident when p > 0.75 with 5+ updates."""
        return self.probability > 0.75 and self.update_count >= 5

    @property
    def is_uncertain(self) -> bool:
        """Belief is uncertain when p is near 0.5 or few updates."""
        return 0.35 < self.probability < 0.65 or self.update_count < 3


# ---------------------------------------------------------------------------
# Strategy Registry Entry
# ---------------------------------------------------------------------------

@dataclass
class StrategyEntry:
    """
    A learned coordination strategy for a specific task-domain combination.
    The meta-learner populates and updates these entries.
    """
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: str = ""
    domain: str = ""
    recommended_pattern: CoordinationPattern = CoordinationPattern.HIERARCHICAL
    recommended_agent_count: int = 3
    recommended_models: dict[str, str] = field(default_factory=dict)  # role -> model
    confidence: float = 0.0     # 0.0 to 1.0, based on sample size + consistency
    belief: BeliefState = field(default_factory=BeliefState)  # BLF linguistic belief
    sample_size: int = 0
    avg_outcome_score: float = 0.0
    avg_duration_seconds: float = 0.0
    avg_token_cost: float = 0.0
    avg_escalations: float = 0.0
    last_updated: float = field(default_factory=time.time)
    notes: str = ""


# ---------------------------------------------------------------------------
# Lint Report
# ---------------------------------------------------------------------------

@dataclass
class LintFinding:
    """A quality issue found during the LINT phase."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: str = "warning"   # info, warning, error
    category: str = ""
    description: str = ""
    affected_entries: list[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class LintReport:
    """Output of the LINT phase."""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    findings: list[LintFinding] = field(default_factory=list)
    entries_checked: int = 0
    health_score: float = 1.0   # 0.0 to 1.0
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Coordination Meta-Learner
# ---------------------------------------------------------------------------

class CoordinationMetaLearner:
    """
    The self-improving coordination strategy engine.

    INGEST: coordination records from completed sessions
    PROPOSE: strategy recommendations from accumulated data
    LINT: quality checks on the strategy registry
    EVOLVE: approved changes update the live registry
    """

    def __init__(
        self,
        min_samples_for_proposal: int = 5,
        improvement_threshold: float = 0.15,
        stale_days: int = 30,
        proposal_expiry_days: int = 30,
    ) -> None:
        # Data stores
        self._records: list[CoordinationRecord] = []
        self._registry: dict[str, StrategyEntry] = {}  # keyed by task_type:domain
        self._proposals: list[StrategyProposal] = []
        self._lint_reports: list[LintReport] = []

        # Config
        self._min_samples = min_samples_for_proposal
        self._improvement_threshold = improvement_threshold
        self._stale_days = stale_days
        self._proposal_expiry_days = proposal_expiry_days

    # -- INGEST Phase --

    def ingest(self, record: CoordinationRecord) -> None:
        """Ingest a completed coordination record."""
        self._records.append(record)

        # BLF: Update belief on existing strategy if one exists
        key = f"{record.task_type}:{record.domain}"
        entry = self._registry.get(key)
        if entry:
            matches_strategy = record.pattern_used == entry.recommended_pattern
            if matches_strategy and record.claim_satisfied:
                entry.belief.update(
                    new_evidence=f"Session confirmed: {record.pattern_used.value} scored {record.outcome_score:.2f}",
                    new_p=min(0.95, entry.belief.probability + 0.05),
                    source=f"record:{record.record_id}",
                )
            elif matches_strategy and not record.claim_satisfied:
                entry.belief.update(
                    new_evidence=f"Session failed: {record.pattern_used.value} scored {record.outcome_score:.2f}, claim not satisfied",
                    new_p=max(0.05, entry.belief.probability - 0.1),
                    source=f"record:{record.record_id}",
                )
            elif not matches_strategy and record.outcome_score > entry.avg_outcome_score:
                entry.belief.update(
                    new_evidence=f"Alternative pattern {record.pattern_used.value} outperformed: {record.outcome_score:.2f} vs avg {entry.avg_outcome_score:.2f}",
                    new_p=max(0.1, entry.belief.probability - 0.15),
                    source=f"record:{record.record_id}",
                )

    def ingest_batch(self, records: list[CoordinationRecord]) -> int:
        """Ingest a batch of coordination records."""
        self._records.extend(records)
        return len(records)

    # -- PROPOSE Phase --

    def propose(self) -> list[StrategyProposal]:
        """
        Analyze accumulated records and generate strategy proposals.
        This is the weekly analysis loop.
        """
        new_proposals: list[StrategyProposal] = []

        # Group records by task_type + domain
        groups = self._group_records()

        for key, records in groups.items():
            if len(records) < self._min_samples:
                continue

            task_type, domain = key.split(":", 1) if ":" in key else (key, "general")

            # Analyze performance by pattern
            pattern_stats = self._analyze_patterns(records)
            if not pattern_stats:
                continue

            # Find the best-performing pattern
            best_pattern = max(
                pattern_stats,
                key=lambda p: pattern_stats[p]["avg_score"],
            )
            best_stats = pattern_stats[best_pattern]

            # Check if this is better than the current registry entry
            registry_key = f"{task_type}:{domain}"
            current = self._registry.get(registry_key)

            if current:
                improvement = best_stats["avg_score"] - current.avg_outcome_score
                if improvement < self._improvement_threshold:
                    continue  # not enough improvement to propose

            # Generate proposal
            proposal = StrategyProposal(
                proposal_type="SWITCH_PATTERN",
                description=(
                    f"Tasks of type '{task_type}' in domain '{domain}' "
                    f"complete with {best_stats['avg_score']:.1%} avg outcome score "
                    f"using {best_pattern} coordination "
                    f"(n={best_stats['count']} sessions). "
                    f"{'Current strategy uses ' + current.recommended_pattern.value + '.' if current else 'No current strategy registered.'}"
                ),
                evidence=[
                    {
                        "pattern": p,
                        "avg_score": s["avg_score"],
                        "avg_duration": s["avg_duration"],
                        "avg_cost": s["avg_cost"],
                        "avg_escalations": s["avg_escalations"],
                        "count": s["count"],
                    }
                    for p, s in pattern_stats.items()
                ],
                evidence_strength=min(1.0, best_stats["count"] / (self._min_samples * 5)),
                current_strategy={
                    "pattern": current.recommended_pattern.value if current else "none",
                    "avg_score": current.avg_outcome_score if current else 0.0,
                },
                proposed_strategy={
                    "pattern": best_pattern,
                    "avg_score": best_stats["avg_score"],
                    "task_type": task_type,
                    "domain": domain,
                    "agent_count": round(best_stats.get("avg_agents", 3)),
                },
            )
            new_proposals.append(proposal)
            self._proposals.append(proposal)

        # Agent count proposals
        count_proposals = self._propose_agent_count_changes(groups)
        new_proposals.extend(count_proposals)
        self._proposals.extend(count_proposals)

        return new_proposals

    def _group_records(self) -> dict[str, list[CoordinationRecord]]:
        groups: dict[str, list[CoordinationRecord]] = defaultdict(list)
        for r in self._records:
            key = f"{r.task_type}:{r.domain}"
            groups[key].append(r)
        return groups

    def _analyze_patterns(
        self, records: list[CoordinationRecord]
    ) -> dict[str, dict[str, float]]:
        """Compute per-pattern performance stats."""
        by_pattern: dict[str, list[CoordinationRecord]] = defaultdict(list)
        for r in records:
            by_pattern[r.pattern_used.value].append(r)

        stats: dict[str, dict[str, float]] = {}
        for pattern, recs in by_pattern.items():
            if not recs:
                continue
            stats[pattern] = {
                "avg_score": sum(r.outcome_score for r in recs) / len(recs),
                "avg_duration": sum(r.duration_seconds for r in recs) / len(recs),
                "avg_cost": sum(r.token_cost for r in recs) / len(recs),
                "avg_escalations": sum(r.escalation_count for r in recs) / len(recs),
                "avg_agents": sum(len(r.agents) for r in recs) / len(recs),
                "count": len(recs),
            }
        return stats

    def _propose_agent_count_changes(
        self, groups: dict[str, list[CoordinationRecord]]
    ) -> list[StrategyProposal]:
        """Propose agent count changes based on escalation patterns."""
        proposals: list[StrategyProposal] = []

        for key, records in groups.items():
            if len(records) < self._min_samples:
                continue

            task_type, domain = key.split(":", 1) if ":" in key else (key, "general")

            # Group by agent count
            by_count: dict[int, list[CoordinationRecord]] = defaultdict(list)
            for r in records:
                by_count[len(r.agents)].append(r)

            # Find optimal agent count
            count_scores: dict[int, float] = {}
            for count, recs in by_count.items():
                if len(recs) >= 3:
                    count_scores[count] = sum(r.outcome_score for r in recs) / len(recs)

            if len(count_scores) < 2:
                continue

            best_count = max(count_scores, key=lambda c: count_scores[c])
            current_key = f"{task_type}:{domain}"
            current = self._registry.get(current_key)

            if current and current.recommended_agent_count != best_count:
                improvement = count_scores[best_count] - count_scores.get(
                    current.recommended_agent_count, 0
                )
                if improvement >= self._improvement_threshold:
                    proposals.append(StrategyProposal(
                        proposal_type="CHANGE_AGENT_COUNT",
                        description=(
                            f"Tasks of type '{task_type}' in '{domain}' "
                            f"perform {improvement:.1%} better with "
                            f"{best_count} agents vs current {current.recommended_agent_count}."
                        ),
                        evidence=[
                            {"count": c, "avg_score": s}
                            for c, s in sorted(count_scores.items())
                        ],
                        evidence_strength=min(1.0, len(records) / 30),
                        current_strategy={"agent_count": current.recommended_agent_count},
                        proposed_strategy={"agent_count": best_count},
                    ))

        return proposals

    # -- LINT Phase --

    def lint(self) -> LintReport:
        """
        Quality checks on the strategy registry.
        Identifies stale entries, contradictions, and low-confidence strategies.
        """
        findings: list[LintFinding] = []
        now = time.time()

        for key, entry in self._registry.items():
            # Stale check
            age_days = (now - entry.last_updated) / 86400
            if age_days > self._stale_days:
                findings.append(LintFinding(
                    severity="warning",
                    category="stale",
                    description=f"Strategy '{key}' last updated {age_days:.0f} days ago",
                    affected_entries=[key],
                    recommendation="Review with fresh coordination data or archive",
                ))

            # Low confidence check
            if entry.confidence < 0.3 and entry.sample_size > 0:
                findings.append(LintFinding(
                    severity="info",
                    category="low_confidence",
                    description=f"Strategy '{key}' has low confidence ({entry.confidence:.2f}) from {entry.sample_size} samples",
                    affected_entries=[key],
                    recommendation="Collect more coordination data or run tournaments",
                ))

            # High escalation rate check
            if entry.avg_escalations > 3:
                findings.append(LintFinding(
                    severity="error",
                    category="high_escalations",
                    description=f"Strategy '{key}' averages {entry.avg_escalations:.1f} escalations per session",
                    affected_entries=[key],
                    recommendation="Consider switching pattern or adding agents",
                ))

        # Contradiction check: same domain, different patterns recommended
        domain_patterns: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for key, entry in self._registry.items():
            domain_patterns[entry.domain].append((key, entry.recommended_pattern.value))

        for domain, entries in domain_patterns.items():
            patterns = set(p for _, p in entries)
            if len(patterns) > 2:
                findings.append(LintFinding(
                    severity="warning",
                    category="contradiction",
                    description=f"Domain '{domain}' has {len(patterns)} different recommended patterns",
                    affected_entries=[k for k, _ in entries],
                    recommendation="Consolidate strategies or refine task type classification",
                ))

        # Compute health score
        error_count = sum(1 for f in findings if f.severity == "error")
        warning_count = sum(1 for f in findings if f.severity == "warning")
        total_entries = max(len(self._registry), 1)
        health = max(0.0, 1.0 - (error_count * 0.2 + warning_count * 0.05) / total_entries)

        report = LintReport(
            findings=findings,
            entries_checked=len(self._registry),
            health_score=health,
        )
        self._lint_reports.append(report)
        return report

    # -- EVOLVE Phase --

    def approve_proposal(self, proposal_id: str, reviewer: str = "") -> StrategyEntry | None:
        """
        Approve a proposal and update the strategy registry.
        Returns the new/updated registry entry.
        """
        proposal = self._find_proposal(proposal_id)
        if not proposal:
            return None

        proposal.status = ProposalStatus.APPROVED
        proposal.reviewed_by = reviewer

        # Update registry
        proposed = proposal.proposed_strategy
        task_type = proposed.get("task_type", "")
        domain = proposed.get("domain", "general")
        key = f"{task_type}:{domain}"

        entry = self._registry.get(key, StrategyEntry(task_type=task_type, domain=domain))

        if proposed.get("pattern"):
            entry.recommended_pattern = CoordinationPattern(proposed["pattern"])
        if proposed.get("agent_count"):
            entry.recommended_agent_count = proposed["agent_count"]
        if proposed.get("avg_score"):
            entry.avg_outcome_score = proposed["avg_score"]

        # Recalculate confidence from evidence
        evidence = proposal.evidence
        if evidence:
            total_samples = sum(e.get("count", 0) for e in evidence if isinstance(e, dict))
            entry.sample_size = total_samples
            entry.confidence = min(1.0, total_samples / 50)

        # BLF: Update linguistic belief state with approval evidence
        best_evidence = max(evidence, key=lambda e: e.get("avg_score", 0)) if evidence else {}
        entry.belief.update(
            new_evidence=(
                f"Strategy approved: {proposal.proposal_type}. "
                f"{proposal.description}"
            ),
            new_p=min(0.95, entry.confidence + 0.1),
            source=f"proposal:{proposal.proposal_id}",
        )

        entry.last_updated = time.time()
        self._registry[key] = entry
        return entry

    def reject_proposal(self, proposal_id: str, reviewer: str = "", notes: str = "") -> None:
        proposal = self._find_proposal(proposal_id)
        if proposal:
            proposal.status = ProposalStatus.REJECTED
            proposal.reviewed_by = reviewer
            proposal.review_notes = notes

    def rollback_proposal(self, proposal_id: str) -> None:
        """Rollback an approved proposal."""
        proposal = self._find_proposal(proposal_id)
        if proposal and proposal.status == ProposalStatus.APPROVED:
            proposal.status = ProposalStatus.ROLLED_BACK
            # Restore previous strategy from current_strategy field
            prev = proposal.current_strategy
            task_type = proposal.proposed_strategy.get("task_type", "")
            domain = proposal.proposed_strategy.get("domain", "general")
            key = f"{task_type}:{domain}"
            entry = self._registry.get(key)
            if entry and prev.get("pattern") and prev["pattern"] != "none":
                entry.recommended_pattern = CoordinationPattern(prev["pattern"])
                entry.last_updated = time.time()

    def expire_stale_proposals(self) -> int:
        now = time.time()
        expired = 0
        for p in self._proposals:
            if p.status == ProposalStatus.PENDING and now > p.expires_at:
                p.status = ProposalStatus.EXPIRED
                expired += 1
        return expired

    def _find_proposal(self, proposal_id: str) -> StrategyProposal | None:
        for p in self._proposals:
            if p.proposal_id == proposal_id:
                return p
        return None

    # -- Strategy Lookup (used by the coordination engine at runtime) --

    def get_strategy(self, task_type: str, domain: str) -> StrategyEntry | None:
        """Look up the recommended strategy for a task-domain combination."""
        key = f"{task_type}:{domain}"
        entry = self._registry.get(key)
        if entry:
            return entry
        # Try domain-only fallback
        for k, v in self._registry.items():
            if v.domain == domain:
                return v
        return None

    def get_all_strategies(self) -> dict[str, StrategyEntry]:
        return dict(self._registry)

    # -- Analytics --

    @property
    def total_records(self) -> int:
        return len(self._records)

    @property
    def registry_size(self) -> int:
        return len(self._registry)

    @property
    def pending_proposals(self) -> list[StrategyProposal]:
        return [p for p in self._proposals if p.status == ProposalStatus.PENDING]

    @property
    def registry_health(self) -> float:
        if not self._lint_reports:
            return 1.0
        return self._lint_reports[-1].health_score

    def get_learning_curve(self) -> list[dict[str, float]]:
        """
        Track how coordination outcomes improve over time.
        Returns time-bucketed average scores.
        """
        if not self._records:
            return []

        # Bucket by week
        buckets: dict[int, list[float]] = defaultdict(list)
        for r in self._records:
            week = int(r.started_at // (7 * 86400))
            buckets[week].append(r.outcome_score)

        return [
            {
                "week": week,
                "avg_score": sum(scores) / len(scores),
                "count": len(scores),
            }
            for week, scores in sorted(buckets.items())
        ]
