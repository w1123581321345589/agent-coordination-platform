"""
Build 6: Context Router with Shapley-Value Contribution Scoring

Instead of broadcasting domain annotations to all agents, routes
knowledge to agents based on:
1. Declared domain scope (from declare_subagent)
2. Measured contribution value (Shapley approximation)
3. Progressive disclosure tiers (Layer 0/1/2)

Reuses:
- declare_subagent() tool scope as routing table
- Progressive Memory Disclosure tiers
- forge cost token tracking as measurement layer
- Intent graph dependency edges for cross-domain propagation

New: Shapley-value approximation from the Stochastic
Self-Organization paper (Tastan et al., 2025/2026).
"""

from __future__ import annotations

import math
import random
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from coordination import AgentIdentity, ShapleyContribution


# ---------------------------------------------------------------------------
# Context Tiers (Progressive Memory Disclosure)
# ---------------------------------------------------------------------------

class ContextTier:
    """Progressive memory disclosure tiers."""
    ALWAYS = 0      # Layer 0: identity + active priorities (~500 tokens)
    ON_DEMAND = 1   # Layer 1: domain-specific via semantic search (~1-2k tokens)
    DEEP = 2        # Layer 2: full historical context (~2-5k tokens)


@dataclass
class ContextItem:
    """A piece of knowledge that can be routed to agents."""
    item_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    content: str = ""
    domain: str = ""
    source_agent_id: str = ""
    tier: int = ContextTier.ON_DEMAND
    token_count: int = 0
    reference_count: int = 0    # how many times agents have referenced this
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float | None = None

    @property
    def is_expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        return time.time() > self.created_at + self.ttl_seconds

    def promote(self) -> None:
        """Promote to a higher tier based on reference count."""
        if self.reference_count >= 3 and self.tier > ContextTier.ALWAYS:
            self.tier = ContextTier.ALWAYS


# ---------------------------------------------------------------------------
# Agent Scope (routing table entry)
# ---------------------------------------------------------------------------

@dataclass
class AgentScope:
    """
    Declares what domains an agent operates in and what
    context it should receive. Built from declare_subagent() specs.
    """
    agent_id: str = ""
    domains: list[str] = field(default_factory=list)
    tool_scope: list[str] = field(default_factory=list)
    max_context_tokens: int = 4000
    contribution_score: float = 0.0  # running Shapley average


# ---------------------------------------------------------------------------
# Dependency Edge (for cross-domain propagation)
# ---------------------------------------------------------------------------

@dataclass
class DependencyEdge:
    """
    An edge in the intent graph's dependency DAG.
    Context only propagates across domains along these edges.
    """
    from_domain: str = ""
    to_domain: str = ""
    strength: float = 1.0


# ---------------------------------------------------------------------------
# Context Router
# ---------------------------------------------------------------------------

class ContextRouter:
    """
    Routes knowledge to agents based on domain scope,
    contribution value, and progressive disclosure tiers.
    """

    def __init__(self, promotion_threshold: int = 3) -> None:
        self._scopes: dict[str, AgentScope] = {}
        self._items: dict[str, ContextItem] = {}
        self._dependencies: list[DependencyEdge] = []
        self._contributions: dict[str, list[ShapleyContribution]] = defaultdict(list)
        self._promotion_threshold = promotion_threshold

    # -- Registration --

    def register_agent_scope(self, scope: AgentScope) -> None:
        self._scopes[scope.agent_id] = scope

    def register_from_identity(self, agent: AgentIdentity) -> None:
        """Build scope from an AgentIdentity's domain tags and tool scope."""
        scope = AgentScope(
            agent_id=agent.agent_id,
            domains=list(agent.domain_tags),
            tool_scope=list(agent.tool_scope),
        )
        self._scopes[agent.agent_id] = scope

    def add_dependency(self, from_domain: str, to_domain: str, strength: float = 1.0) -> None:
        self._dependencies.append(DependencyEdge(from_domain, to_domain, strength))

    # -- Context Injection --

    def add_context(self, item: ContextItem) -> None:
        """Add a new context item and route to relevant agents."""
        self._items[item.item_id] = item

    def get_context_for_agent(
        self,
        agent_id: str,
        tier: int = ContextTier.ON_DEMAND,
        token_budget: int | None = None,
    ) -> list[ContextItem]:
        """
        Get context items relevant to an agent, filtered by tier
        and constrained by token budget.
        """
        scope = self._scopes.get(agent_id)
        if not scope:
            return []

        budget = token_budget or scope.max_context_tokens
        relevant_domains = set(scope.domains)

        # Add cross-domain dependencies
        for dep in self._dependencies:
            if dep.from_domain in relevant_domains:
                relevant_domains.add(dep.to_domain)

        # Filter items by domain relevance and tier
        candidates = [
            item for item in self._items.values()
            if not item.is_expired
            and item.domain in relevant_domains
            and item.tier <= tier
        ]

        # Sort by: tier (lower first), then contribution-weighted relevance
        candidates.sort(key=lambda i: (i.tier, -i.reference_count))

        # Apply token budget
        result: list[ContextItem] = []
        used_tokens = 0
        for item in candidates:
            if used_tokens + item.token_count > budget:
                break
            result.append(item)
            used_tokens += item.token_count

        return result

    def record_reference(self, item_id: str) -> None:
        """Record that an agent referenced a context item."""
        item = self._items.get(item_id)
        if item:
            item.reference_count += 1
            item.promote()

    # -- Shapley Value Computation --

    def compute_shapley(
        self,
        session_agents: list[str],
        outcome_score: float,
        individual_scores: dict[str, float],
        n_permutations: int = 100,
    ) -> dict[str, ShapleyContribution]:
        """
        Approximate Shapley value for each agent's contribution
        to a coordination session.

        Uses Monte Carlo sampling over permutations (the standard
        approximation for combinatorial Shapley computation).

        Args:
            session_agents: agent_ids that participated
            outcome_score: overall coordination outcome (0.0 to 1.0)
            individual_scores: per-agent quality scores
            n_permutations: sampling count for approximation
        """
        n = len(session_agents)
        if n == 0:
            return {}

        marginals: dict[str, list[float]] = defaultdict(list)

        for _ in range(n_permutations):
            perm = list(session_agents)
            random.shuffle(perm)

            coalition_value = 0.0
            for i, agent_id in enumerate(perm):
                # Value with this agent
                agent_score = individual_scores.get(agent_id, outcome_score / n)
                # Diminishing returns for later agents in the permutation
                position_weight = 1.0 / (1.0 + 0.1 * i)
                new_value = coalition_value + agent_score * position_weight

                marginal = new_value - coalition_value
                marginals[agent_id].append(marginal)
                coalition_value = new_value

        # Average marginal contributions with hierarchical calibration
        # (BLF pattern: shrink toward population mean to prevent
        # hero/villain agents from small sample extremes)
        results: dict[str, ShapleyContribution] = {}

        # Compute population mean for shrinkage target
        all_marginals_flat = [v for vals in marginals.values() for v in vals]
        population_mean = sum(all_marginals_flat) / max(len(all_marginals_flat), 1)

        for agent_id in session_agents:
            values = marginals.get(agent_id, [0.0])
            raw_avg = sum(values) / len(values)

            # Hierarchical shrinkage: pull toward population mean
            # based on how much historical data we have for this agent
            prior_count = len(self._contributions.get(agent_id, []))
            # With 0 history, shrinkage weight = 0.5 (heavy pull toward mean)
            # With 10+ sessions, shrinkage weight < 0.1 (trust the data)
            shrinkage = 1.0 / (2.0 + prior_count)
            calibrated = (1 - shrinkage) * raw_avg + shrinkage * population_mean

            contrib = ShapleyContribution(
                agent_id=agent_id,
                session_id="",  # set by caller
                marginal_value=calibrated,
            )
            results[agent_id] = contrib
            self._contributions[agent_id].append(contrib)

            # Update scope contribution score (running average of calibrated values)
            scope = self._scopes.get(agent_id)
            if scope:
                all_contribs = self._contributions[agent_id]
                scope.contribution_score = sum(
                    c.marginal_value for c in all_contribs
                ) / len(all_contribs)

        return results

    # -- Analytics --

    def get_agent_contribution_history(self, agent_id: str) -> list[ShapleyContribution]:
        return self._contributions.get(agent_id, [])

    def get_top_contributors(self, n: int = 10) -> list[tuple[str, float]]:
        """Ranked list of agents by average Shapley contribution."""
        scores: list[tuple[str, float]] = []
        for agent_id, contribs in self._contributions.items():
            if contribs:
                avg = sum(c.marginal_value for c in contribs) / len(contribs)
                scores.append((agent_id, avg))
        scores.sort(key=lambda x: -x[1])
        return scores[:n]

    def get_redundant_agents(self, threshold: float = 0.05) -> list[str]:
        """
        Agents with consistently low Shapley contributions.
        These are candidates for removal or role change.
        Directly addresses the Diversity Collapse paper's concern.
        """
        redundant: list[str] = []
        for agent_id, contribs in self._contributions.items():
            if len(contribs) >= 5:
                avg = sum(c.marginal_value for c in contribs) / len(contribs)
                if avg < threshold:
                    redundant.append(agent_id)
        return redundant

    @property
    def total_items(self) -> int:
        return len(self._items)

    @property
    def active_items(self) -> int:
        return sum(1 for i in self._items.values() if not i.is_expired)

    @property
    def total_agents_scoped(self) -> int:
        return len(self._scopes)
