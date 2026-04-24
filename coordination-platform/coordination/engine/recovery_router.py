"""
Build 3: Recovery Router

Wires four existing systems via an event bus:
1. Aiglos Tier 3 GATED pause (detection)
2. Agent Pool Coordinator work queue (redistribution)
3. Domain annotations (context injection)
4. Intent graph cascade (dependency propagation)

When an agent is compromised or failing, the recovery router:
- Pauses the agent
- Returns its active work items to the pool
- Injects context about why the previous agent was paused
- Reassigns to a healthy agent
- Flags dependent coordination claims
- Generates a recovery verification claim
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from coordination import (
    AgentIdentity,
    AgentStatus,
    CoordinationClaim,
    CoordinationPattern,
    ThreatEvent,
    ThreatSeverity,
)


# ---------------------------------------------------------------------------
# Work Item (the unit of redistribution)
# ---------------------------------------------------------------------------

@dataclass
class WorkItem:
    """A task assigned to an agent that can be redistributed."""
    item_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_id: str = ""
    assigned_to: str = ""       # agent_id
    task_description: str = ""
    domain: str = ""
    priority: int = 0           # higher = more urgent
    context: dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    status: str = "active"      # active, queued, completed, failed

    @property
    def retriable(self) -> bool:
        return self.retry_count < self.max_retries


# ---------------------------------------------------------------------------
# Domain Annotation (cross-agent knowledge injection)
# ---------------------------------------------------------------------------

@dataclass
class DomainAnnotation:
    """
    Knowledge that propagates across agents.
    When a recovery event happens, the annotation carries
    context about WHY the previous agent was paused.
    """
    annotation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    domain: str = ""
    content: str = ""
    source_agent_id: str = ""
    severity: str = "info"      # info, warning, critical
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 3600   # 1 hour default


# ---------------------------------------------------------------------------
# Recovery Event (the trigger)
# ---------------------------------------------------------------------------

@dataclass
class RecoveryEvent:
    """Emitted when an agent needs recovery."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    threat_event: ThreatEvent | None = None
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    work_items_redistributed: list[str] = field(default_factory=list)
    recovery_claim_id: str = ""


# ---------------------------------------------------------------------------
# Recovery Router
# ---------------------------------------------------------------------------

class RecoveryRouter:
    """
    Event bus that connects Aiglos detection to Forge recovery.

    Architecture:
    ThreatEvent -> pause agent -> collect work items ->
    inject domain annotation -> redistribute to healthy agents ->
    cascade to dependent claims -> generate verification claim
    """

    def __init__(self) -> None:
        # Agent registry
        self._agents: dict[str, AgentIdentity] = {}
        self._agent_status: dict[str, AgentStatus] = {}

        # Work queue
        self._work_queue: list[WorkItem] = []
        self._active_assignments: dict[str, list[WorkItem]] = defaultdict(list)

        # Domain annotations
        self._annotations: list[DomainAnnotation] = []

        # Event log
        self._recovery_events: list[RecoveryEvent] = []

        # Coordination claims for verification
        self._recovery_claims: list[CoordinationClaim] = []

        # Callbacks
        self._on_recovery: list[Callable[[RecoveryEvent], None]] = []

    # -- Agent Management --

    def register_agent(self, agent: AgentIdentity) -> None:
        self._agents[agent.agent_id] = agent
        self._agent_status[agent.agent_id] = AgentStatus.HEALTHY

    def get_healthy_agents(self, domain: str | None = None) -> list[AgentIdentity]:
        """Get all healthy agents, optionally filtered by domain."""
        healthy = [
            self._agents[aid]
            for aid, status in self._agent_status.items()
            if status == AgentStatus.HEALTHY and aid in self._agents
        ]
        if domain:
            healthy = [
                a for a in healthy
                if domain in a.domain_tags or not a.domain_tags
            ]
        return healthy

    # -- Work Assignment --

    def assign_work(self, item: WorkItem, agent_id: str) -> None:
        item.assigned_to = agent_id
        item.status = "active"
        self._active_assignments[agent_id].append(item)

    def complete_work(self, item_id: str) -> None:
        for agent_id, items in self._active_assignments.items():
            for item in items:
                if item.item_id == item_id:
                    item.status = "completed"
                    items.remove(item)
                    return

    # -- The Core Recovery Flow --

    def handle_threat(self, threat: ThreatEvent) -> RecoveryEvent:
        """
        Main entry point. Called when Aiglos detects a threat.
        Executes the full recovery flow.
        """
        agent_id = threat.agent_id

        # Step 1: Pause the compromised agent
        self._pause_agent(agent_id)

        # Step 2: Collect active work items from the paused agent
        work_items = self._collect_work_items(agent_id)

        # Step 3: Inject domain annotation about the pause
        annotation = self._inject_recovery_annotation(agent_id, threat)

        # Step 4: Redistribute work items to healthy agents
        redistributed = self._redistribute_work(work_items, annotation)

        # Step 5: Generate a recovery verification claim
        recovery_claim = self._generate_recovery_claim(agent_id, work_items, threat)

        # Step 6: Build the recovery event
        event = RecoveryEvent(
            agent_id=agent_id,
            threat_event=threat,
            reason=f"Recovery triggered by {threat.rule_id}: {threat.description}",
            work_items_redistributed=[w.item_id for w in redistributed],
            recovery_claim_id=recovery_claim.claim_id,
        )
        self._recovery_events.append(event)

        # Step 7: Notify listeners
        for callback in self._on_recovery:
            callback(event)

        return event

    def on_recovery(self, callback: Callable[[RecoveryEvent], None]) -> None:
        """Register a callback for recovery events."""
        self._on_recovery.append(callback)

    # -- Internal Recovery Steps --

    def _pause_agent(self, agent_id: str) -> None:
        """Step 1: Tier 3 GATED pause."""
        self._agent_status[agent_id] = AgentStatus.PAUSED

    def _collect_work_items(self, agent_id: str) -> list[WorkItem]:
        """Step 2: Return active work to queue."""
        items = self._active_assignments.pop(agent_id, [])
        for item in items:
            item.status = "queued"
            item.assigned_to = ""
            item.retry_count += 1
        return items

    def _inject_recovery_annotation(
        self, agent_id: str, threat: ThreatEvent
    ) -> DomainAnnotation:
        """Step 3: Create domain annotation with recovery context."""
        annotation = DomainAnnotation(
            domain=self._agents.get(agent_id, AgentIdentity()).domain_tags[0]
            if self._agents.get(agent_id) and self._agents[agent_id].domain_tags
            else "general",
            content=(
                f"Agent {agent_id} was paused for {threat.rule_id} "
                f"({threat.description}). Work items from this agent may "
                f"contain adversarial content. Approach with elevated scrutiny."
            ),
            source_agent_id="recovery_router",
            severity="critical",
        )
        self._annotations.append(annotation)
        return annotation

    def _redistribute_work(
        self,
        items: list[WorkItem],
        annotation: DomainAnnotation,
    ) -> list[WorkItem]:
        """Step 4: Assign work to healthy agents with recovery context."""
        redistributed: list[WorkItem] = []

        for item in items:
            if not item.retriable:
                item.status = "failed"
                continue

            # Find a healthy agent in the same domain
            candidates = self.get_healthy_agents(domain=item.domain)
            if not candidates:
                # Fall back to any healthy agent
                candidates = self.get_healthy_agents()

            if not candidates:
                # No healthy agents available, re-queue
                self._work_queue.append(item)
                continue

            # Select agent with fewest active assignments (load balance)
            selected = min(
                candidates,
                key=lambda a: len(self._active_assignments.get(a.agent_id, [])),
            )

            # Inject recovery context into work item
            item.context["recovery_annotation"] = annotation.content
            item.context["previous_agent_paused"] = True

            self.assign_work(item, selected.agent_id)
            redistributed.append(item)

        return redistributed

    def _generate_recovery_claim(
        self,
        failed_agent_id: str,
        work_items: list[WorkItem],
        threat: ThreatEvent,
    ) -> CoordinationClaim:
        """
        Step 5: Generate a verification claim for the recovery.
        'Verify that the paused agent's partial work is consistent
        with the original coordination claim.'
        """
        claim = CoordinationClaim(
            description=(
                f"Recovery verification: validate work items from paused agent "
                f"{failed_agent_id} (paused for {threat.rule_id}). "
                f"{len(work_items)} items redistributed."
            ),
            participating_agents=[
                w.assigned_to for w in work_items if w.assigned_to
            ],
            pattern=CoordinationPattern.PIPELINE,
            success_criteria={
                "all_items_verified": True,
                "no_tainted_outputs": True,
            },
        )
        self._recovery_claims.append(claim)
        return claim

    # -- Analytics --

    @property
    def total_recoveries(self) -> int:
        return len(self._recovery_events)

    @property
    def items_in_queue(self) -> int:
        return len(self._work_queue)

    @property
    def paused_agents(self) -> list[str]:
        return [
            aid for aid, status in self._agent_status.items()
            if status == AgentStatus.PAUSED
        ]

    def resume_agent(self, agent_id: str) -> None:
        """Resume a previously paused agent after investigation."""
        if self._agent_status.get(agent_id) == AgentStatus.PAUSED:
            self._agent_status[agent_id] = AgentStatus.HEALTHY
