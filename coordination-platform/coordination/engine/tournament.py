"""
Build 7: Coordination Tournament

Extends Forge's implementation tournament from testing implementation
variants to testing coordination strategy variants.

For a complex multi-agent task, instead of using a fixed coordination
pattern, generate 2-3 strategy variants and run them. Measure outcomes
against the coordination claim's acceptance criteria. Record which
variant won and why.

Reuses:
- Tournament infrastructure (multi-variant execution)
- Verification runtime (claim satisfaction measurement)
- Autonomy gaps table (failure recording)
- Behavioral baseline (agent performance tracking)
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from coordination import (
    AgentIdentity,
    CoordinationClaim,
    CoordinationPattern,
    CoordinationRecord,
)


# ---------------------------------------------------------------------------
# Tournament Variant
# ---------------------------------------------------------------------------

@dataclass
class CoordinationVariant:
    """A specific coordination strategy to test."""
    variant_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern: CoordinationPattern = CoordinationPattern.HIERARCHICAL
    agent_count: int = 3
    agent_roles: list[str] = field(default_factory=list)
    model_assignments: dict[str, str] = field(default_factory=dict)  # role -> model
    parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass
class VariantResult:
    """Result of running a single coordination variant."""
    variant_id: str = ""
    record: CoordinationRecord | None = None
    claim_satisfied: bool = False
    outcome_score: float = 0.0
    duration_seconds: float = 0.0
    token_cost: int = 0
    escalation_count: int = 0
    error: str | None = None


@dataclass
class TournamentResult:
    """Result of a complete tournament across all variants."""
    tournament_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim: CoordinationClaim | None = None
    variants: list[CoordinationVariant] = field(default_factory=list)
    results: list[VariantResult] = field(default_factory=list)
    winner_id: str = ""
    winning_pattern: CoordinationPattern = CoordinationPattern.HIERARCHICAL
    margin: float = 0.0         # score difference between 1st and 2nd
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    @property
    def winner(self) -> VariantResult | None:
        for r in self.results:
            if r.variant_id == self.winner_id:
                return r
        return None


# ---------------------------------------------------------------------------
# Variant Generator
# ---------------------------------------------------------------------------

class VariantGenerator:
    """
    Generates coordination strategy variants for a given claim.
    Each variant represents a different approach to the same task.
    """

    def generate(
        self,
        claim: CoordinationClaim,
        available_agents: list[AgentIdentity],
        max_variants: int = 3,
    ) -> list[CoordinationVariant]:
        """
        Generate coordination variants for a claim.
        Returns up to max_variants different approaches.
        """
        variants: list[CoordinationVariant] = []
        agent_count = len(claim.participating_agents) or min(len(available_agents), 5)

        # Variant 1: Hierarchical delegation (one coordinator, N-1 workers)
        variants.append(CoordinationVariant(
            pattern=CoordinationPattern.HIERARCHICAL,
            agent_count=agent_count,
            agent_roles=["coordinator"] + ["worker"] * (agent_count - 1),
            description="Single coordinator delegates subtasks to workers",
            parameters={"delegation_style": "top_down"},
        ))

        # Variant 2: Debate (all agents propose, vote on best)
        if max_variants >= 2:
            variants.append(CoordinationVariant(
                pattern=CoordinationPattern.DEBATE,
                agent_count=agent_count,
                agent_roles=["debater"] * agent_count,
                description="All agents propose solutions, evaluate each other, converge",
                parameters={"rounds": 3, "voting": "ranked_choice"},
            ))

        # Variant 3: Parallel merge (independent work, synthesize)
        if max_variants >= 3:
            variants.append(CoordinationVariant(
                pattern=CoordinationPattern.PARALLEL_MERGE,
                agent_count=agent_count,
                agent_roles=["independent"] * (agent_count - 1) + ["synthesizer"],
                description="Agents work independently, synthesizer merges results",
                parameters={"merge_strategy": "best_of_n"},
            ))

        return variants[:max_variants]


# ---------------------------------------------------------------------------
# Coordination Tournament
# ---------------------------------------------------------------------------

class CoordinationTournament:
    """
    Runs multiple coordination variants against the same claim
    and selects the winner based on outcome metrics.
    """

    def __init__(
        self,
        variant_generator: VariantGenerator | None = None,
        executor: Callable[[CoordinationVariant, CoordinationClaim], VariantResult] | None = None,
    ) -> None:
        self._generator = variant_generator or VariantGenerator()
        self._executor = executor or self._default_executor
        self._history: list[TournamentResult] = []

    def run(
        self,
        claim: CoordinationClaim,
        available_agents: list[AgentIdentity],
        max_variants: int = 3,
    ) -> TournamentResult:
        """
        Execute a tournament for a coordination claim.
        Generates variants, runs them, selects the winner.
        """
        # Generate variants
        variants = self._generator.generate(claim, available_agents, max_variants)

        # Execute each variant
        results: list[VariantResult] = []
        for variant in variants:
            result = self._executor(variant, claim)
            result.variant_id = variant.variant_id
            results.append(result)

        # Select winner
        winner_id, margin = self._select_winner(results)
        winning_variant = next(
            (v for v in variants if v.variant_id == winner_id),
            variants[0] if variants else None,
        )

        tournament = TournamentResult(
            claim=claim,
            variants=variants,
            results=results,
            winner_id=winner_id,
            winning_pattern=winning_variant.pattern if winning_variant else CoordinationPattern.HIERARCHICAL,
            margin=margin,
            completed_at=time.time(),
        )
        self._history.append(tournament)
        return tournament

    def _select_winner(self, results: list[VariantResult]) -> tuple[str, float]:
        """
        Select the winning variant based on a composite score.
        Weighted: outcome quality (60%), efficiency (20%), cost (20%).
        """
        if not results:
            return "", 0.0

        scored: list[tuple[str, float]] = []
        for r in results:
            if r.error:
                scored.append((r.variant_id, 0.0))
                continue

            # Normalize metrics
            quality = r.outcome_score  # 0.0 to 1.0
            # Efficiency: fewer escalations = better (inverse, capped)
            efficiency = 1.0 / (1.0 + r.escalation_count)
            # Cost: lower tokens = better (inverse, normalized)
            cost_score = 1.0 / (1.0 + r.token_cost / 10000)

            composite = quality * 0.6 + efficiency * 0.2 + cost_score * 0.2
            scored.append((r.variant_id, composite))

        scored.sort(key=lambda x: -x[1])

        winner = scored[0]
        margin = winner[1] - scored[1][1] if len(scored) > 1 else winner[1]
        return winner[0], margin

    @staticmethod
    def _default_executor(
        variant: CoordinationVariant, claim: CoordinationClaim
    ) -> VariantResult:
        """
        Default executor for testing. In production, this is replaced
        with the actual coordination execution engine.
        """
        return VariantResult(
            variant_id=variant.variant_id,
            claim_satisfied=True,
            outcome_score=0.5,
            duration_seconds=1.0,
            token_cost=1000,
            escalation_count=0,
        )

    # -- Analytics --

    def get_pattern_win_rates(self) -> dict[str, float]:
        """Which coordination patterns win most often?"""
        pattern_wins: dict[str, int] = {}
        pattern_runs: dict[str, int] = {}

        for tournament in self._history:
            for variant in tournament.variants:
                key = variant.pattern.value
                pattern_runs[key] = pattern_runs.get(key, 0) + 1
                if variant.variant_id == tournament.winner_id:
                    pattern_wins[key] = pattern_wins.get(key, 0) + 1

        return {
            p: pattern_wins.get(p, 0) / max(pattern_runs.get(p, 1), 1)
            for p in pattern_runs
        }

    def get_best_pattern_for_domain(self, domain: str) -> CoordinationPattern | None:
        """Based on tournament history, which pattern works best for a domain?"""
        domain_tournaments = [
            t for t in self._history
            if t.claim and domain in (t.claim.success_criteria.get("domain", "") or "")
        ]
        if not domain_tournaments:
            return None

        pattern_scores: dict[str, list[float]] = {}
        for t in domain_tournaments:
            winner = t.winner
            if winner:
                winning_variant = next(
                    (v for v in t.variants if v.variant_id == t.winner_id), None
                )
                if winning_variant:
                    key = winning_variant.pattern.value
                    pattern_scores.setdefault(key, []).append(winner.outcome_score)

        if not pattern_scores:
            return None

        best = max(
            pattern_scores,
            key=lambda p: sum(pattern_scores[p]) / len(pattern_scores[p]),
        )
        return CoordinationPattern(best)

    @property
    def total_tournaments(self) -> int:
        return len(self._history)

    @property
    def avg_margin(self) -> float:
        if not self._history:
            return 0.0
        return sum(t.margin for t in self._history) / len(self._history)
