"""
Coordination Platform -- Core Types

Data models shared across all modules. Every coordination session,
agent interaction, and strategy decision is typed here.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CoordinationPattern(Enum):
    """Known coordination strategies the system can select from."""
    HIERARCHICAL = "hierarchical"       # one coordinator, N workers
    DEBATE = "debate"                   # agents argue, vote on winner
    PARALLEL_MERGE = "parallel_merge"   # independent work, synthesize
    PIPELINE = "pipeline"              # sequential handoff
    SWARM = "swarm"                    # stigmergic, no explicit coordinator


class AgentStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"
    PAUSED = "paused"
    TERMINATED = "terminated"


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProposalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    ROLLED_BACK = "rolled_back"


class ModelProvider(Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    LOCAL = "local"


class A2AMessageType(Enum):
    TASK_DELEGATE = "task/delegate"
    TASK_ACCEPT = "task/accept"
    TASK_REJECT = "task/reject"
    TASK_RESULT = "task/result"
    TASK_CANCEL = "task/cancel"
    CAPABILITY_QUERY = "capability/query"
    CAPABILITY_RESPONSE = "capability/response"
    HEARTBEAT = "heartbeat"
    CONTEXT_SHARE = "context/share"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------

@dataclass
class AgentIdentity:
    """Unique identity for an agent in the coordination system."""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    role: str = ""
    model_provider: ModelProvider = ModelProvider.ANTHROPIC
    model_name: str = "claude-sonnet-4-20250514"
    tool_scope: list[str] = field(default_factory=list)
    hard_bans: list[str] = field(default_factory=list)
    domain_tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        """Stable hash for behavioral baseline comparisons."""
        raw = f"{self.name}:{self.role}:{self.model_provider.value}:{','.join(sorted(self.tool_scope))}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class CoordinationClaim:
    """
    A behavioral claim about how agents should coordinate.
    Extends the Forge intent graph from single-agent BUs to
    multi-agent coordination claims.
    """
    claim_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    participating_agents: list[str] = field(default_factory=list)
    pattern: CoordinationPattern = CoordinationPattern.HIERARCHICAL
    max_duration_seconds: float | None = None
    max_escalations: int | None = None
    success_criteria: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)  # other claim_ids
    active: bool = True

    def to_bu(self) -> dict:
        """Export as a Forge-compatible behavioral unit."""
        return {
            "id": self.claim_id,
            "type": "coordination_claim",
            "description": self.description,
            "agents": self.participating_agents,
            "pattern": self.pattern.value,
            "constraints": {
                "max_duration_seconds": self.max_duration_seconds,
                "max_escalations": self.max_escalations,
            },
            "success_criteria": self.success_criteria,
            "dependencies": self.depends_on,
        }


@dataclass
class CoordinationRecord:
    """
    Immutable record of a completed coordination session.
    The meta-learner INGESTs these to learn optimal strategies.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_id: str = ""
    pattern_used: CoordinationPattern = CoordinationPattern.HIERARCHICAL
    agents: list[AgentIdentity] = field(default_factory=list)
    task_type: str = ""
    domain: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    duration_seconds: float = 0.0
    token_cost: int = 0
    escalation_count: int = 0
    claim_satisfied: bool = False
    agent_contributions: dict[str, float] = field(default_factory=dict)  # agent_id -> shapley value
    outcome_score: float = 0.0
    model_providers_used: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class A2AMessage:
    """
    An Agent-to-Agent protocol message.
    JSON-RPC 2.0 over HTTP, per the A2A spec.
    """
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    message_type: A2AMessageType = A2AMessageType.TASK_DELEGATE
    sender_id: str = ""
    receiver_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    parent_message_id: str | None = None

    def to_jsonrpc(self) -> dict:
        """Serialize to JSON-RPC 2.0 format per A2A spec."""
        return {
            "jsonrpc": "2.0",
            "method": self.message_type.value,
            "params": {
                "message_id": self.message_id,
                "sender": self.sender_id,
                "receiver": self.receiver_id,
                "payload": self.payload,
                "session_id": self.session_id,
                "parent_message_id": self.parent_message_id,
            },
            "id": self.message_id,
        }

    @property
    def content_fingerprint(self) -> str:
        """Hash of payload for dedup and integrity checks."""
        import json
        raw = json.dumps(self.payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class ThreatEvent:
    """A detected threat in coordination traffic."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""           # e.g. "T25", "T39", "T83"
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    agent_id: str = ""
    message_id: str | None = None
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    recommended_action: str = ""


@dataclass
class StrategyProposal:
    """
    A proposed change to coordination strategy, surfaced
    through the policy proposal lifecycle.
    """
    proposal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    proposal_type: str = ""     # e.g. "SWITCH_PATTERN", "ADD_AGENT", "CHANGE_MODEL"
    description: str = ""
    evidence: list[dict] = field(default_factory=list)
    evidence_strength: float = 0.0  # 0.0 to 1.0
    current_strategy: dict[str, Any] = field(default_factory=dict)
    proposed_strategy: dict[str, Any] = field(default_factory=dict)
    status: ProposalStatus = ProposalStatus.PENDING
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 30 * 86400)  # 30-day auto-expiry
    reviewed_by: str | None = None
    review_notes: str = ""


@dataclass
class AgentProposal:
    """
    A proposal for a new agent type, generated from autonomy
    gap clustering.
    """
    proposal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    role: str = ""
    rationale: str = ""
    gap_cluster: list[dict] = field(default_factory=list)  # the autonomy_gaps that triggered this
    suggested_tool_scope: list[str] = field(default_factory=list)
    suggested_hard_bans: list[str] = field(default_factory=list)
    suggested_domain_tags: list[str] = field(default_factory=list)
    suggested_model: str = ""
    prompt_template: str = ""
    status: ProposalStatus = ProposalStatus.PENDING
    created_at: float = field(default_factory=time.time)


@dataclass
class ShapleyContribution:
    """Per-agent contribution score for a coordination session."""
    agent_id: str = ""
    session_id: str = ""
    marginal_value: float = 0.0     # Shapley approximation
    actions_taken: int = 0
    tokens_consumed: int = 0
    escalations_caused: int = 0
    knowledge_contributed: int = 0  # domain annotations generated
    computed_at: float = field(default_factory=time.time)


@dataclass
class CoordinationAttestation:
    """
    Signed audit record for a coordination session.
    C3PAO-ready for NDAA Section 1513.
    """
    attestation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    record: CoordinationRecord | None = None
    threats_detected: list[ThreatEvent] = field(default_factory=list)
    agents_involved: list[AgentIdentity] = field(default_factory=list)
    pattern_used: CoordinationPattern = CoordinationPattern.HIERARCHICAL
    claim_results: dict[str, bool] = field(default_factory=dict)
    signature: str = ""  # RSA-2048 signature of the attestation payload
    created_at: float = field(default_factory=time.time)
