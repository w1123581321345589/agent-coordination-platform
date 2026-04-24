"""
Build 2: A2A Security Interceptor

Fourth interception surface for Aiglos (alongside MCP, HTTP, subprocess).
Inspects every A2A message for threats using the existing T-rule taxonomy.

Directly applicable threat rules:
  T25 AGENT_IMPERSONATE  -- agent identity spoofing in A2A
  T26 TRUST_CHAIN        -- broken trust chain in A2A delegations
  T38 AGENT_SPAWN        -- unauthorized agent spawning via A2A
  T39 ORCHESTRATION      -- multi-agent orchestration abuse
  T78 HALLUCINATION_CASCADE -- confidence amplification across A2A hops
  T83 INTER_AGENT_PROTOCOL_SPOOF -- A2A message tampering
  T84 IP_TRANSFORM_EXFIL -- IP exfiltration via A2A context sharing

New A2A-specific rules defined here:
  T104 A2A_INJECTION        -- prompt injection in A2A payloads
  T105 A2A_CAPABILITY_SPOOF -- false capability advertisement
  T106 A2A_CONTEXT_POISON   -- malicious context in A2A shares
  T107 A2A_DELEGATION_LOOP  -- infinite delegation chains
  T111 A2A_BUDGET_EVASION   -- splitting tasks to evade per-agent budgets
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from coordination import (
    A2AMessage,
    A2AMessageType,
    AgentStatus,
    ThreatEvent,
    ThreatSeverity,
)


# ---------------------------------------------------------------------------
# Threat Rule Definitions
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore\s+(previous|prior|all)\s+(instructions?|prompts?)",
    r"you\s+are\s+now\s+",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"forget\s+(everything|all|your)\s+",
    r"override\s+(your|the)\s+(rules?|instructions?|guidelines?)",
    r"act\s+as\s+(if\s+)?you\s+(are|were)\s+",
    r"pretend\s+(to\s+be|you\s+are)\s+",
    r"jailbreak",
    r"dan\s+mode",
    r"developer\s+mode",
]

EXFIL_KEYWORDS = [
    "rewrite", "reimplementation", "clean room", "functional equivalent",
    "convert to", "translate to", "port to", "reverse engineer",
    "extract the", "copy the source", "send to external",
]

COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

@dataclass
class A2AThreatRule:
    """A single threat detection rule for A2A traffic."""
    rule_id: str
    name: str
    severity: ThreatSeverity
    description: str
    check: str = ""  # method name on A2AInterceptor


# The A2A-specific rule registry
A2A_RULES: list[A2AThreatRule] = [
    A2AThreatRule("T25", "AGENT_IMPERSONATE", ThreatSeverity.CRITICAL,
                  "Sender ID does not match registered agent identity"),
    A2AThreatRule("T26", "TRUST_CHAIN", ThreatSeverity.HIGH,
                  "A2A message from unregistered or untrusted agent"),
    A2AThreatRule("T39", "ORCHESTRATION", ThreatSeverity.HIGH,
                  "Unauthorized orchestration pattern in A2A delegation"),
    A2AThreatRule("T78", "HALLUCINATION_CASCADE", ThreatSeverity.MEDIUM,
                  "Confidence amplification across A2A delegation chain"),
    A2AThreatRule("T83", "INTER_AGENT_PROTOCOL_SPOOF", ThreatSeverity.CRITICAL,
                  "A2A message structure tampering detected"),
    A2AThreatRule("T84", "IP_TRANSFORM_EXFIL", ThreatSeverity.CRITICAL,
                  "IP exfiltration keywords in A2A context sharing"),
    A2AThreatRule("T104", "A2A_INJECTION", ThreatSeverity.CRITICAL,
                  "Prompt injection detected in A2A payload"),
    A2AThreatRule("T105", "A2A_CAPABILITY_SPOOF", ThreatSeverity.HIGH,
                  "Agent advertising capabilities beyond declared scope"),
    A2AThreatRule("T106", "A2A_CONTEXT_POISON", ThreatSeverity.CRITICAL,
                  "Malicious context injection in A2A context share"),
    A2AThreatRule("T107", "A2A_DELEGATION_LOOP", ThreatSeverity.HIGH,
                  "Circular or excessively deep delegation chain detected"),
    A2AThreatRule("T111", "A2A_BUDGET_EVASION", ThreatSeverity.MEDIUM,
                  "Task splitting pattern consistent with budget evasion"),
]


# ---------------------------------------------------------------------------
# A2A Interceptor
# ---------------------------------------------------------------------------

class A2AInterceptor:
    """
    Aiglos security interceptor for A2A protocol traffic.
    Plugs into A2AGateway.add_interceptor() to inspect every
    message before delivery.

    Implements the same pattern as MCP/HTTP/subprocess interception:
    detect, classify, gate, attest.
    """

    def __init__(
        self,
        registered_agents: set[str] | None = None,
        agent_capabilities: dict[str, list[str]] | None = None,
        max_delegation_depth: int = 10,
        budget_tracker: dict[str, float] | None = None,
    ) -> None:
        self._registered_agents = registered_agents or set()
        self._agent_capabilities = agent_capabilities or {}
        self._max_delegation_depth = max_delegation_depth
        self._budget_tracker = budget_tracker or {}
        self._delegation_chains: dict[str, list[str]] = {}  # session_id -> [agent_ids]
        self._threat_log: list[ThreatEvent] = []
        self._message_count = 0
        self._blocked_count = 0
        self._delegation_counts: dict[str, int] = {}  # agent_id -> delegation count in window
        self._window_start = time.time()
        self._window_seconds = 300  # 5-minute sliding window

    # -- Public Interface --

    def intercept(self, msg: A2AMessage) -> A2AMessage | None:
        """
        Main interception entry point. Runs all applicable rules.
        Returns the message if safe, None if blocked.

        This method is passed to A2AGateway.add_interceptor().
        """
        self._message_count += 1
        threats = self._evaluate(msg)

        if not threats:
            return msg

        # Log all threats
        self._threat_log.extend(threats)

        # Block on CRITICAL severity
        has_critical = any(t.severity == ThreatSeverity.CRITICAL for t in threats)
        if has_critical:
            self._blocked_count += 1
            return None

        # Allow with warnings for non-critical
        return msg

    def register_agent(self, agent_id: str, capabilities: list[str] | None = None) -> None:
        self._registered_agents.add(agent_id)
        if capabilities:
            self._agent_capabilities[agent_id] = capabilities

    def get_threats(self, since: float | None = None) -> list[ThreatEvent]:
        if since is None:
            return list(self._threat_log)
        return [t for t in self._threat_log if t.timestamp >= since]

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_messages": self._message_count,
            "blocked_messages": self._blocked_count,
            "threats_detected": len(self._threat_log),
            "block_rate": self._blocked_count / max(self._message_count, 1),
            "registered_agents": len(self._registered_agents),
        }

    # -- Rule Evaluation --

    def _evaluate(self, msg: A2AMessage) -> list[ThreatEvent]:
        """Run all applicable rules against a message."""
        threats: list[ThreatEvent] = []

        # T25: Agent impersonation
        t = self._check_impersonation(msg)
        if t:
            threats.append(t)

        # T26: Trust chain
        t = self._check_trust_chain(msg)
        if t:
            threats.append(t)

        # T104: Injection in payload
        t = self._check_injection(msg)
        if t:
            threats.append(t)

        # T84: IP exfiltration
        t = self._check_exfiltration(msg)
        if t:
            threats.append(t)

        # T105: Capability spoofing
        t = self._check_capability_spoof(msg)
        if t:
            threats.append(t)

        # T106: Context poisoning
        t = self._check_context_poison(msg)
        if t:
            threats.append(t)

        # T107: Delegation loops
        t = self._check_delegation_loop(msg)
        if t:
            threats.append(t)

        # T111: Budget evasion
        t = self._check_budget_evasion(msg)
        if t:
            threats.append(t)

        # T78: Hallucination cascade
        t = self._check_confidence_amplification(msg)
        if t:
            threats.append(t)

        return threats

    def _check_impersonation(self, msg: A2AMessage) -> ThreatEvent | None:
        """T25: Sender claims to be an agent that doesn't match registration."""
        if not self._registered_agents:
            return None
        if msg.sender_id and msg.sender_id not in self._registered_agents:
            return ThreatEvent(
                rule_id="T25",
                severity=ThreatSeverity.CRITICAL,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"A2A message from unregistered sender: {msg.sender_id}",
                evidence={"sender_id": msg.sender_id, "registered": list(self._registered_agents)},
                session_id=msg.session_id,
                recommended_action="BLOCK",
            )
        return None

    def _check_trust_chain(self, msg: A2AMessage) -> ThreatEvent | None:
        """T26: Message receiver is not registered."""
        if not self._registered_agents:
            return None
        if msg.receiver_id and msg.receiver_id not in self._registered_agents:
            return ThreatEvent(
                rule_id="T26",
                severity=ThreatSeverity.HIGH,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"A2A delegation to unknown agent: {msg.receiver_id}",
                evidence={"receiver_id": msg.receiver_id},
                session_id=msg.session_id,
                recommended_action="GATE",
            )
        return None

    def _check_injection(self, msg: A2AMessage) -> ThreatEvent | None:
        """T104: Scan A2A payload for prompt injection patterns."""
        payload_str = _flatten_payload(msg.payload)
        for pattern in COMPILED_INJECTION:
            match = pattern.search(payload_str)
            if match:
                return ThreatEvent(
                    rule_id="T104",
                    severity=ThreatSeverity.CRITICAL,
                    agent_id=msg.sender_id,
                    message_id=msg.message_id,
                    description=f"Prompt injection in A2A payload: '{match.group()}'",
                    evidence={"pattern": match.group(), "message_type": msg.message_type.value},
                    session_id=msg.session_id,
                    recommended_action="BLOCK",
                )
        return None

    def _check_exfiltration(self, msg: A2AMessage) -> ThreatEvent | None:
        """T84: IP exfiltration keywords in context sharing messages."""
        if msg.message_type != A2AMessageType.CONTEXT_SHARE:
            return None
        payload_str = _flatten_payload(msg.payload).lower()
        found = [kw for kw in EXFIL_KEYWORDS if kw in payload_str]
        if len(found) >= 2:  # require 2+ keywords for signal strength
            return ThreatEvent(
                rule_id="T84",
                severity=ThreatSeverity.CRITICAL,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"IP exfiltration keywords in A2A context share: {found}",
                evidence={"keywords": found},
                session_id=msg.session_id,
                recommended_action="BLOCK",
            )
        return None

    def _check_capability_spoof(self, msg: A2AMessage) -> ThreatEvent | None:
        """T105: Agent claims capabilities beyond its declared scope."""
        if msg.message_type != A2AMessageType.CAPABILITY_RESPONSE:
            return None
        declared = set(self._agent_capabilities.get(msg.sender_id, []))
        if not declared:
            return None
        advertised = set(msg.payload.get("capabilities", []))
        undeclared = advertised - declared
        if undeclared:
            return ThreatEvent(
                rule_id="T105",
                severity=ThreatSeverity.HIGH,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"Agent advertising undeclared capabilities: {undeclared}",
                evidence={"declared": list(declared), "advertised": list(advertised)},
                session_id=msg.session_id,
                recommended_action="GATE",
            )
        return None

    def _check_context_poison(self, msg: A2AMessage) -> ThreatEvent | None:
        """T106: Malicious patterns in context share payloads."""
        if msg.message_type != A2AMessageType.CONTEXT_SHARE:
            return None
        payload_str = _flatten_payload(msg.payload)
        # Check for injection in context (same patterns, different message type)
        for pattern in COMPILED_INJECTION:
            match = pattern.search(payload_str)
            if match:
                return ThreatEvent(
                    rule_id="T106",
                    severity=ThreatSeverity.CRITICAL,
                    agent_id=msg.sender_id,
                    message_id=msg.message_id,
                    description=f"Context poisoning detected: '{match.group()}'",
                    evidence={"pattern": match.group()},
                    session_id=msg.session_id,
                    recommended_action="BLOCK",
                )
        return None

    def _check_delegation_loop(self, msg: A2AMessage) -> ThreatEvent | None:
        """T107: Detect circular or excessively deep delegation chains."""
        if msg.message_type != A2AMessageType.TASK_DELEGATE:
            return None

        chain = self._delegation_chains.setdefault(msg.session_id, [])
        if not chain:
            chain.append(msg.sender_id)  # track the initiator
        chain.append(msg.receiver_id)

        # Check depth
        if len(chain) > self._max_delegation_depth:
            return ThreatEvent(
                rule_id="T107",
                severity=ThreatSeverity.HIGH,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"Delegation chain depth {len(chain)} exceeds max {self._max_delegation_depth}",
                evidence={"chain": chain, "depth": len(chain)},
                session_id=msg.session_id,
                recommended_action="BLOCK",
            )

        # Check circular
        if msg.receiver_id in chain[:-1]:
            return ThreatEvent(
                rule_id="T107",
                severity=ThreatSeverity.HIGH,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"Circular delegation detected: {msg.receiver_id} already in chain",
                evidence={"chain": chain, "circular_agent": msg.receiver_id},
                session_id=msg.session_id,
                recommended_action="BLOCK",
            )
        return None

    def _check_budget_evasion(self, msg: A2AMessage) -> ThreatEvent | None:
        """T111: Detect task splitting patterns consistent with budget evasion."""
        if msg.message_type != A2AMessageType.TASK_DELEGATE:
            return None

        # Reset window if expired
        now = time.time()
        if now - self._window_start > self._window_seconds:
            self._delegation_counts.clear()
            self._window_start = now

        count = self._delegation_counts.get(msg.sender_id, 0) + 1
        self._delegation_counts[msg.sender_id] = count

        # Flag if an agent is delegating excessively (potential task splitting)
        if count > 20:  # more than 20 delegations in 5 minutes
            return ThreatEvent(
                rule_id="T111",
                severity=ThreatSeverity.MEDIUM,
                agent_id=msg.sender_id,
                message_id=msg.message_id,
                description=f"Excessive delegation rate: {count} in {self._window_seconds}s window",
                evidence={"count": count, "window_seconds": self._window_seconds},
                session_id=msg.session_id,
                recommended_action="GATE",
            )
        return None

    def _check_confidence_amplification(self, msg: A2AMessage) -> ThreatEvent | None:
        """T78: Detect confidence scores inflating across delegation hops."""
        if msg.message_type != A2AMessageType.TASK_RESULT:
            return None
        confidence = msg.payload.get("confidence")
        parent_confidence = msg.payload.get("parent_confidence")
        if confidence is not None and parent_confidence is not None:
            if isinstance(confidence, (int, float)) and isinstance(parent_confidence, (int, float)):
                if confidence > parent_confidence * 1.5 and confidence > 0.9:
                    return ThreatEvent(
                        rule_id="T78",
                        severity=ThreatSeverity.MEDIUM,
                        agent_id=msg.sender_id,
                        message_id=msg.message_id,
                        description=f"Confidence amplified from {parent_confidence:.2f} to {confidence:.2f}",
                        evidence={"parent": parent_confidence, "child": confidence},
                        session_id=msg.session_id,
                        recommended_action="WARN",
                    )
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_payload(payload: dict[str, Any]) -> str:
    """Recursively flatten a payload dict to a searchable string."""
    parts: list[str] = []
    for v in payload.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(_flatten_payload(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(_flatten_payload(item))
    return " ".join(parts)
