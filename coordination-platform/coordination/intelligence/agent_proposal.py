"""
Build 5: Agent Proposal Engine

Wires autonomy_gaps sensor -> pattern registry -> policy proposal lifecycle.

When agents repeatedly get stuck on the same type of task in the same domain,
the engine clusters those failures and proposes a new specialist agent type.
The proposal goes through the existing policy proposal lifecycle
(evidence threshold, human review, approve/reject/rollback, 30-day auto-expiry).

Components reused:
- autonomy_gaps table (sensor)
- autoresearch loop pattern (proposal generation)
- policy proposal lifecycle (approval workflow)
- pattern registry YAML (destination)
"""

from __future__ import annotations

import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from coordination import AgentProposal, ProposalStatus


# ---------------------------------------------------------------------------
# Autonomy Gap Record
# ---------------------------------------------------------------------------

@dataclass
class AutonomyGap:
    """
    Records every time an agent gets stuck and needs human intervention.
    Direct analog to the autonomy_gaps table in Forge.
    """
    gap_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    agent_role: str = ""
    gap_type: str = ""          # domain_knowledge, ambiguous_spec, tool_limitation, etc.
    domain: str = ""
    task_description: str = ""
    human_resolution: str = ""  # what the human did to resolve it
    tools_attempted: list[str] = field(default_factory=list)
    tools_needed: list[str] = field(default_factory=list)  # what tools would have helped
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Gap Cluster (intermediate analysis artifact)
# ---------------------------------------------------------------------------

@dataclass
class GapCluster:
    """A cluster of related autonomy gaps that may warrant a new agent type."""
    cluster_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    gap_type: str = ""
    gaps: list[AutonomyGap] = field(default_factory=list)
    common_tools_needed: list[str] = field(default_factory=list)
    common_resolution_patterns: list[str] = field(default_factory=list)
    strength: float = 0.0       # 0.0 to 1.0, how strong the signal is

    @property
    def size(self) -> int:
        return len(self.gaps)


# ---------------------------------------------------------------------------
# Agent Proposal Engine
# ---------------------------------------------------------------------------

class AgentProposalEngine:
    """
    Observes autonomy gaps. Clusters them. Proposes new agent types.

    The loop:
    1. INGEST: autonomy gaps accumulate from coordination sessions
    2. CLUSTER: weekly analysis groups gaps by domain + gap_type
    3. PROPOSE: clusters above threshold generate agent proposals
    4. REVIEW: proposals enter policy lifecycle (human approve/reject)
    5. DEPLOY: approved proposals become pattern registry entries
    """

    def __init__(
        self,
        cluster_threshold: int = 5,
        window_days: int = 30,
        auto_expire_days: int = 30,
    ) -> None:
        self._gaps: list[AutonomyGap] = []
        self._clusters: list[GapCluster] = []
        self._proposals: list[AgentProposal] = []
        self._cluster_threshold = cluster_threshold
        self._window_days = window_days
        self._auto_expire_days = auto_expire_days

    # -- Gap Ingestion --

    def record_gap(self, gap: AutonomyGap) -> None:
        """Record a new autonomy gap from a coordination session."""
        self._gaps.append(gap)

    def record_gaps(self, gaps: list[AutonomyGap]) -> None:
        self._gaps.extend(gaps)

    # -- Clustering --

    def analyze(self) -> list[GapCluster]:
        """
        Cluster recent gaps by domain + gap_type.
        Returns clusters that exceed the threshold.
        """
        cutoff = time.time() - (self._window_days * 86400)
        recent = [g for g in self._gaps if g.timestamp >= cutoff]

        # Group by (domain, gap_type)
        groups: dict[tuple[str, str], list[AutonomyGap]] = defaultdict(list)
        for gap in recent:
            key = (gap.domain, gap.gap_type)
            groups[key].append(gap)

        clusters: list[GapCluster] = []
        for (domain, gap_type), gaps in groups.items():
            if len(gaps) >= self._cluster_threshold:
                cluster = self._build_cluster(domain, gap_type, gaps)
                clusters.append(cluster)

        self._clusters = clusters
        return clusters

    def _build_cluster(
        self, domain: str, gap_type: str, gaps: list[AutonomyGap]
    ) -> GapCluster:
        """Build a cluster from a group of gaps, extracting common patterns."""
        # Find common tools needed
        tool_counter: Counter[str] = Counter()
        for gap in gaps:
            tool_counter.update(gap.tools_needed)
        common_tools = [t for t, count in tool_counter.most_common(10) if count >= 2]

        # Find common resolution patterns
        resolution_counter: Counter[str] = Counter()
        for gap in gaps:
            if gap.human_resolution:
                # Simple keyword extraction from resolutions
                words = gap.human_resolution.lower().split()
                key_phrases = [
                    " ".join(words[i : i + 3])
                    for i in range(len(words) - 2)
                ]
                resolution_counter.update(key_phrases)
        common_resolutions = [
            r for r, count in resolution_counter.most_common(5) if count >= 2
        ]

        strength = min(1.0, len(gaps) / (self._cluster_threshold * 3))

        return GapCluster(
            domain=domain,
            gap_type=gap_type,
            gaps=gaps,
            common_tools_needed=common_tools,
            common_resolution_patterns=common_resolutions,
            strength=strength,
        )

    # -- Proposal Generation --

    def generate_proposals(self) -> list[AgentProposal]:
        """
        Generate agent proposals from clusters.
        Each cluster above threshold produces one proposal.
        """
        if not self._clusters:
            self.analyze()

        new_proposals: list[AgentProposal] = []
        for cluster in self._clusters:
            # Skip if we already have a pending proposal for this domain+type
            existing = any(
                p.status == ProposalStatus.PENDING
                and any(
                    g.get("domain") == cluster.domain
                    and g.get("gap_type") == cluster.gap_type
                    for g in p.gap_cluster
                )
                for p in self._proposals
            )
            if existing:
                continue

            proposal = self._cluster_to_proposal(cluster)
            new_proposals.append(proposal)
            self._proposals.append(proposal)

        return new_proposals

    def _cluster_to_proposal(self, cluster: GapCluster) -> AgentProposal:
        """Convert a gap cluster into an agent proposal."""
        name = f"{cluster.domain}_{cluster.gap_type}_specialist"
        role = f"Specialist agent for {cluster.gap_type} tasks in {cluster.domain}"

        # Build prompt template from resolution patterns
        resolution_context = "\n".join(
            f"- {r}" for r in cluster.common_resolution_patterns[:5]
        )

        prompt_template = (
            f"You are a specialist agent for {cluster.domain}.\n"
            f"Your primary function is handling {cluster.gap_type} situations.\n"
            f"Common resolution patterns from human operators:\n"
            f"{resolution_context}\n"
            f"Apply these patterns autonomously when possible.\n"
            f"Escalate only when the situation doesn't match known patterns."
        )

        # Serialize gap data for the proposal record
        gap_data = [
            {
                "gap_id": g.gap_id,
                "domain": g.domain,
                "gap_type": g.gap_type,
                "task": g.task_description,
                "resolution": g.human_resolution,
            }
            for g in cluster.gaps
        ]

        return AgentProposal(
            name=name,
            role=role,
            rationale=(
                f"Detected {len(cluster.gaps)} autonomy gaps of type "
                f"'{cluster.gap_type}' in domain '{cluster.domain}' "
                f"within the last {self._window_days} days. "
                f"Cluster strength: {cluster.strength:.2f}. "
                f"Common tools needed: {', '.join(cluster.common_tools_needed[:5])}."
            ),
            gap_cluster=gap_data,
            suggested_tool_scope=cluster.common_tools_needed,
            suggested_domain_tags=[cluster.domain],
            prompt_template=prompt_template,
        )

    # -- Proposal Lifecycle --

    def approve_proposal(self, proposal_id: str, reviewer: str = "", notes: str = "") -> AgentProposal | None:
        """Approve a proposal. Returns the pattern registry entry."""
        proposal = self._find_proposal(proposal_id)
        if proposal:
            proposal.status = ProposalStatus.APPROVED
        return proposal

    def reject_proposal(self, proposal_id: str, reviewer: str = "", notes: str = "") -> None:
        proposal = self._find_proposal(proposal_id)
        if proposal:
            proposal.status = ProposalStatus.REJECTED

    def expire_stale_proposals(self) -> int:
        """Auto-expire proposals older than the expiry window."""
        now = time.time()
        expired = 0
        for p in self._proposals:
            if p.status == ProposalStatus.PENDING:
                age_days = (now - p.created_at) / 86400
                if age_days > self._auto_expire_days:
                    p.status = ProposalStatus.EXPIRED
                    expired += 1
        return expired

    def _find_proposal(self, proposal_id: str) -> AgentProposal | None:
        for p in self._proposals:
            if p.proposal_id == proposal_id:
                return p
        return None

    # -- Export to Pattern Registry --

    def to_pattern_yaml(self, proposal: AgentProposal) -> dict[str, Any]:
        """
        Export an approved proposal as a Pattern Engine registry entry.
        This is the YAML that goes into registry.yaml.
        """
        return {
            "name": proposal.name,
            "role": proposal.role,
            "triggers": [
                f"{tag} {proposal.gap_cluster[0].get('gap_type', '')}"
                for tag in proposal.suggested_domain_tags
            ] if proposal.gap_cluster else [],
            "context": {
                "bootstrap": [f"context/bootstrap/{proposal.name}.md"],
                "reference": [],
            },
            "tools": {
                "allowed": proposal.suggested_tool_scope,
                "banned": proposal.suggested_hard_bans,
            },
            "model": proposal.suggested_model or "claude-sonnet-4-6",
            "prompt_template": proposal.prompt_template,
            "domain_tags": proposal.suggested_domain_tags,
            "auto_generated": True,
            "source_cluster": proposal.proposal_id,
        }

    # -- Analytics --

    @property
    def total_gaps(self) -> int:
        return len(self._gaps)

    @property
    def active_clusters(self) -> int:
        return len(self._clusters)

    @property
    def pending_proposals(self) -> list[AgentProposal]:
        return [p for p in self._proposals if p.status == ProposalStatus.PENDING]

    @property
    def approved_proposals(self) -> list[AgentProposal]:
        return [p for p in self._proposals if p.status == ProposalStatus.APPROVED]
