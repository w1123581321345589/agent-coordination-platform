"""
Build 1: A2A Protocol Support

Implements Google's Agent-to-Agent protocol (JSON-RPC 2.0 over HTTP)
for inter-agent communication. Maps A2A task delegations to Forge-
compatible coordination claims in the intent graph.

Ref: https://a2a-protocol.org/latest/
Ref: https://github.com/a2aproject/A2A

This module handles:
- Agent capability advertisement (Agent Card)
- Task delegation and acceptance
- Context sharing between agents
- Message serialization/deserialization
- Coordination claim generation from A2A task flows
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from coordination import (
    A2AMessage,
    A2AMessageType,
    AgentIdentity,
    CoordinationClaim,
    CoordinationPattern,
)


# ---------------------------------------------------------------------------
# Agent Card (A2A Capability Advertisement)
# ---------------------------------------------------------------------------

@dataclass
class AgentCard:
    """
    A2A Agent Card: advertises what this agent can do.
    Other agents discover capabilities through this card.
    Maps directly to declare_subagent() tool scope declarations.
    """
    agent_id: str = ""
    name: str = ""
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    accepted_input_types: list[str] = field(default_factory=list)
    output_types: list[str] = field(default_factory=list)
    domain_tags: list[str] = field(default_factory=list)
    endpoint_url: str = ""
    version: str = "1.0"

    @classmethod
    def from_agent_identity(cls, agent: AgentIdentity, endpoint: str = "") -> AgentCard:
        """Build an A2A Agent Card from an existing AgentIdentity."""
        return cls(
            agent_id=agent.agent_id,
            name=agent.name,
            description=f"{agent.role} agent",
            capabilities=list(agent.tool_scope),
            domain_tags=list(agent.domain_tags),
            endpoint_url=endpoint,
        )

    def to_json(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities,
            "accepted_input_types": self.accepted_input_types,
            "output_types": self.output_types,
            "domain_tags": self.domain_tags,
            "endpoint": self.endpoint_url,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# A2A Session (tracks a multi-turn agent-to-agent conversation)
# ---------------------------------------------------------------------------

@dataclass
class A2ASession:
    """Tracks state for a multi-turn A2A conversation."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    initiator_id: str = ""
    participants: list[str] = field(default_factory=list)
    messages: list[A2AMessage] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    closed: bool = False
    coordination_claims: list[CoordinationClaim] = field(default_factory=list)

    def add_message(self, msg: A2AMessage) -> None:
        msg.session_id = self.session_id
        self.messages.append(msg)
        if msg.sender_id not in self.participants:
            self.participants.append(msg.sender_id)
        if msg.receiver_id not in self.participants:
            self.participants.append(msg.receiver_id)

    @property
    def message_count(self) -> int:
        return len(self.messages)

    @property
    def duration_seconds(self) -> float:
        if not self.messages:
            return 0.0
        return self.messages[-1].timestamp - self.messages[0].timestamp


# ---------------------------------------------------------------------------
# A2A Gateway (message routing + claim generation)
# ---------------------------------------------------------------------------

class A2AGateway:
    """
    Central gateway for A2A protocol traffic.
    Routes messages between agents. Generates coordination claims
    from task delegation flows. Provides the hook point for
    Aiglos A2A security interception (Build 2).
    """

    def __init__(self) -> None:
        self._registry: dict[str, AgentCard] = {}
        self._sessions: dict[str, A2ASession] = {}
        self._interceptors: list[Callable[[A2AMessage], A2AMessage | None]] = []
        self._message_log: list[A2AMessage] = []

    # -- Agent Registry --

    def register_agent(self, card: AgentCard) -> None:
        """Register an agent's capabilities with the gateway."""
        self._registry[card.agent_id] = card

    def deregister_agent(self, agent_id: str) -> None:
        self._registry.pop(agent_id, None)

    def discover_agents(
        self,
        capability: str | None = None,
        domain_tag: str | None = None,
    ) -> list[AgentCard]:
        """
        A2A capability discovery. Find agents that can handle
        a given capability or domain.
        """
        results = list(self._registry.values())
        if capability:
            results = [
                c for c in results
                if any(capability.lower() in cap.lower() for cap in c.capabilities)
            ]
        if domain_tag:
            results = [
                c for c in results
                if domain_tag.lower() in [t.lower() for t in c.domain_tags]
            ]
        return results

    # -- Interceptor Chain (hook for Aiglos Build 2) --

    def add_interceptor(self, interceptor: Callable[[A2AMessage], A2AMessage | None]) -> None:
        """
        Add a message interceptor. Interceptors run in order.
        Return None to block the message. Return the message
        (possibly modified) to allow it through.

        This is the hook point for Build 2 (A2A Security).
        """
        self._interceptors.append(interceptor)

    def _run_interceptors(self, msg: A2AMessage) -> A2AMessage | None:
        current = msg
        for interceptor in self._interceptors:
            result = interceptor(current)
            if result is None:
                return None  # blocked
            current = result
        return current

    # -- Message Routing --

    def send_message(self, msg: A2AMessage) -> A2AMessage | None:
        """
        Route an A2A message. Runs through interceptor chain first.
        Returns the message if delivered, None if blocked.
        """
        # Run through interceptor chain (Aiglos hooks here)
        processed = self._run_interceptors(msg)
        if processed is None:
            return None

        self._message_log.append(processed)

        # Track in session
        if processed.session_id:
            session = self._sessions.get(processed.session_id)
            if session:
                session.add_message(processed)

        # Generate coordination claims from task delegations
        if processed.message_type == A2AMessageType.TASK_DELEGATE:
            self._generate_delegation_claim(processed)

        return processed

    def create_session(self, initiator_id: str) -> A2ASession:
        """Start a new A2A session."""
        session = A2ASession(initiator_id=initiator_id)
        self._sessions[session.session_id] = session
        return session

    def close_session(self, session_id: str) -> A2ASession | None:
        session = self._sessions.get(session_id)
        if session:
            session.closed = True
        return session

    def get_session(self, session_id: str) -> A2ASession | None:
        return self._sessions.get(session_id)

    # -- Coordination Claim Generation --

    def _generate_delegation_claim(self, msg: A2AMessage) -> CoordinationClaim:
        """
        When Agent A delegates a task to Agent B via A2A,
        generate a coordination claim that the intent graph
        can track and verify.
        """
        claim = CoordinationClaim(
            description=f"A2A delegation: {msg.sender_id} -> {msg.receiver_id}: {msg.payload.get('task', 'unknown')}",
            participating_agents=[msg.sender_id, msg.receiver_id],
            pattern=CoordinationPattern.HIERARCHICAL,
            max_duration_seconds=msg.payload.get("timeout", 300),
            success_criteria=msg.payload.get("acceptance_criteria", {}),
        )

        session = self._sessions.get(msg.session_id)
        if session:
            session.coordination_claims.append(claim)

        return claim

    # -- Task Delegation Helpers --

    def delegate_task(
        self,
        sender: AgentIdentity,
        receiver_id: str,
        task: str,
        payload: dict[str, Any] | None = None,
        timeout: float = 300,
        session_id: str | None = None,
    ) -> A2AMessage | None:
        """
        High-level task delegation. Creates the A2A message,
        routes it through interceptors, and tracks the session.
        """
        if session_id is None:
            sess = self.create_session(sender.agent_id)
            session_id = sess.session_id

        msg = A2AMessage(
            message_type=A2AMessageType.TASK_DELEGATE,
            sender_id=sender.agent_id,
            receiver_id=receiver_id,
            payload={
                "task": task,
                "timeout": timeout,
                **(payload or {}),
            },
            session_id=session_id,
        )
        return self.send_message(msg)

    def respond_to_task(
        self,
        original_message: A2AMessage,
        sender: AgentIdentity,
        result: dict[str, Any],
        accepted: bool = True,
    ) -> A2AMessage | None:
        """Respond to a task delegation with a result."""
        msg_type = A2AMessageType.TASK_RESULT if accepted else A2AMessageType.TASK_REJECT
        msg = A2AMessage(
            message_type=msg_type,
            sender_id=sender.agent_id,
            receiver_id=original_message.sender_id,
            payload=result,
            session_id=original_message.session_id,
            parent_message_id=original_message.message_id,
        )
        return self.send_message(msg)

    # -- Analytics --

    @property
    def total_messages(self) -> int:
        return len(self._message_log)

    @property
    def active_sessions(self) -> int:
        return sum(1 for s in self._sessions.values() if not s.closed)

    @property
    def registered_agents(self) -> int:
        return len(self._registry)

    def get_agent_message_count(self, agent_id: str) -> int:
        return sum(
            1 for m in self._message_log
            if m.sender_id == agent_id or m.receiver_id == agent_id
        )
