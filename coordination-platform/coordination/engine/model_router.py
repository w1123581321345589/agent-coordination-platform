"""
Build 4: Cross-Model Router

Routes different agent roles to different model providers to
produce structurally diverse outputs. Directly addresses the
Diversity Collapse paper's finding that homogeneous agent
populations produce diminishing returns.

Extends the Pattern Engine's existing model tiering
(Haiku/Sonnet/Opus) to cross-provider routing
(Claude/Gemini/DeepSeek/Qwen).

The router makes three decisions:
1. Which provider for this role? (diversity routing)
2. Which model tier within that provider? (cost optimization)
3. Should this task get cross-model verification? (quality gate)
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

from coordination import AgentIdentity, CoordinationRecord, ModelProvider


# ---------------------------------------------------------------------------
# Model Configuration
# ---------------------------------------------------------------------------

@dataclass
class ModelConfig:
    """Configuration for a specific model endpoint."""
    provider: ModelProvider
    model_name: str
    cost_per_1k_tokens: float = 0.0
    max_context_window: int = 128000
    strengths: list[str] = field(default_factory=list)  # e.g. ["code", "reasoning", "creative"]
    weaknesses: list[str] = field(default_factory=list)
    latency_ms_avg: float = 1000.0
    available: bool = True


# Default model registry
DEFAULT_MODELS: dict[str, ModelConfig] = {
    "claude-opus": ModelConfig(
        ModelProvider.ANTHROPIC, "claude-opus-4-6",
        cost_per_1k_tokens=0.075, max_context_window=200000,
        strengths=["reasoning", "analysis", "writing", "code_review"],
    ),
    "claude-sonnet": ModelConfig(
        ModelProvider.ANTHROPIC, "claude-sonnet-4-6",
        cost_per_1k_tokens=0.015, max_context_window=200000,
        strengths=["code", "reasoning", "general"],
    ),
    "claude-haiku": ModelConfig(
        ModelProvider.ANTHROPIC, "claude-haiku-4-5-20251001",
        cost_per_1k_tokens=0.005, max_context_window=200000,
        strengths=["speed", "classification", "extraction"],
    ),
    "gemini-pro": ModelConfig(
        ModelProvider.GOOGLE, "gemini-2.5-pro",
        cost_per_1k_tokens=0.01, max_context_window=1000000,
        strengths=["long_context", "multimodal", "code"],
    ),
    "deepseek-v3": ModelConfig(
        ModelProvider.DEEPSEEK, "deepseek-v3",
        cost_per_1k_tokens=0.002, max_context_window=128000,
        strengths=["code", "math", "cost_efficiency"],
    ),
}


# ---------------------------------------------------------------------------
# Role-to-Model Routing Rules
# ---------------------------------------------------------------------------

@dataclass
class RoutingRule:
    """Maps an agent role to preferred model configurations."""
    role_pattern: str           # regex or exact match
    primary_model: str          # key in model registry
    fallback_model: str = ""
    cross_verify_model: str = ""  # if set, run cross-model verification
    rationale: str = ""


DEFAULT_ROUTING_RULES: list[RoutingRule] = [
    RoutingRule(
        "ceo_reviewer", "claude-opus", fallback_model="gemini-pro",
        rationale="CEO review needs strongest reasoning"
    ),
    RoutingRule(
        "paranoid_reviewer", "gemini-pro", fallback_model="claude-opus",
        cross_verify_model="claude-opus",
        rationale="Cross-provider verification catches model-specific blind spots"
    ),
    RoutingRule(
        "implementation", "claude-sonnet", fallback_model="deepseek-v3",
        rationale="Implementation needs good code at reasonable cost"
    ),
    RoutingRule(
        "qa", "deepseek-v3", fallback_model="claude-haiku",
        rationale="QA is high-volume, cost efficiency matters"
    ),
    RoutingRule(
        "research", "gemini-pro", fallback_model="claude-opus",
        rationale="Research benefits from Gemini's long context window"
    ),
    RoutingRule(
        "sentinel", "claude-haiku", fallback_model="deepseek-v3",
        rationale="Sentinels run frequently, need lowest cost"
    ),
]


# ---------------------------------------------------------------------------
# Cross-Model Verification
# ---------------------------------------------------------------------------

@dataclass
class CrossModelResult:
    """Result of running the same task through two different models."""
    task_id: str = ""
    primary_model: str = ""
    verification_model: str = ""
    primary_output_hash: str = ""
    verification_output_hash: str = ""
    agreement: bool = True
    disagreement_details: str = ""
    primary_confidence: float = 0.0
    verification_confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Model Router
# ---------------------------------------------------------------------------

class ModelRouter:
    """
    Routes agent roles to optimal model providers.
    Learns from coordination records which model-role
    combinations produce the best outcomes.
    """

    def __init__(
        self,
        models: dict[str, ModelConfig] | None = None,
        rules: list[RoutingRule] | None = None,
    ) -> None:
        self._models = models or dict(DEFAULT_MODELS)
        self._rules = rules or list(DEFAULT_ROUTING_RULES)
        self._performance_log: list[dict[str, Any]] = []
        self._cross_verifications: list[CrossModelResult] = []

    # -- Routing --

    def route(self, agent: AgentIdentity) -> ModelConfig:
        """
        Determine the optimal model for an agent based on its role.
        Falls back to the agent's current model if no rule matches.
        """
        rule = self._find_rule(agent.role)
        if rule:
            model = self._models.get(rule.primary_model)
            if model and model.available:
                return model
            # Try fallback
            fallback = self._models.get(rule.fallback_model)
            if fallback and fallback.available:
                return fallback

        # Default: keep current provider, use sonnet tier
        return self._models.get("claude-sonnet", ModelConfig(
            ModelProvider.ANTHROPIC, "claude-sonnet-4-6",
        ))

    def should_cross_verify(self, agent: AgentIdentity) -> str | None:
        """
        Check if this agent's role requires cross-model verification.
        Returns the verification model key, or None.
        """
        rule = self._find_rule(agent.role)
        if rule and rule.cross_verify_model:
            return rule.cross_verify_model
        return None

    def _find_rule(self, role: str) -> RoutingRule | None:
        role_lower = role.lower()
        for rule in self._rules:
            if rule.role_pattern.lower() in role_lower:
                return rule
        return None

    # -- Performance Learning --

    def record_outcome(
        self,
        agent_id: str,
        model_used: str,
        role: str,
        task_type: str,
        outcome_score: float,
        token_cost: int,
        duration_seconds: float,
    ) -> None:
        """
        Record the outcome of a model-role-task combination.
        The meta-learner uses this data to optimize routing rules.
        """
        self._performance_log.append({
            "agent_id": agent_id,
            "model": model_used,
            "role": role,
            "task_type": task_type,
            "outcome_score": outcome_score,
            "token_cost": token_cost,
            "duration_seconds": duration_seconds,
            "timestamp": time.time(),
        })

    def get_model_performance(self, model_key: str) -> dict[str, float]:
        """Aggregate performance stats for a model."""
        entries = [e for e in self._performance_log if e["model"] == model_key]
        if not entries:
            return {"avg_score": 0, "avg_cost": 0, "avg_duration": 0, "count": 0}
        return {
            "avg_score": sum(e["outcome_score"] for e in entries) / len(entries),
            "avg_cost": sum(e["token_cost"] for e in entries) / len(entries),
            "avg_duration": sum(e["duration_seconds"] for e in entries) / len(entries),
            "count": len(entries),
        }

    def get_best_model_for_task(self, task_type: str, role: str) -> str | None:
        """
        Based on accumulated performance data, which model
        produces the best outcomes for this task-role combination?
        """
        relevant = [
            e for e in self._performance_log
            if e["task_type"] == task_type and e["role"] == role
        ]
        if len(relevant) < 5:
            return None  # not enough data to recommend

        by_model: dict[str, list[float]] = {}
        for e in relevant:
            by_model.setdefault(e["model"], []).append(e["outcome_score"])

        best_model = max(by_model, key=lambda m: sum(by_model[m]) / len(by_model[m]))
        return best_model

    # -- Cross-Model Verification Records --

    def record_cross_verification(self, result: CrossModelResult) -> None:
        self._cross_verifications.append(result)

    @property
    def cross_verification_disagreement_rate(self) -> float:
        if not self._cross_verifications:
            return 0.0
        disagreements = sum(1 for r in self._cross_verifications if not r.agreement)
        return disagreements / len(self._cross_verifications)

    # -- Model Management --

    def add_model(self, key: str, config: ModelConfig) -> None:
        self._models[key] = config

    def set_model_available(self, key: str, available: bool) -> None:
        if key in self._models:
            self._models[key].available = available

    def add_routing_rule(self, rule: RoutingRule) -> None:
        self._rules.append(rule)

    @property
    def available_providers(self) -> list[ModelProvider]:
        return list({m.provider for m in self._models.values() if m.available})

    @property
    def diversity_score(self) -> float:
        """
        0.0 = all agents use same provider (monoculture)
        1.0 = agents evenly distributed across providers
        """
        providers = self.available_providers
        if len(providers) <= 1:
            return 0.0
        return min(1.0, len(providers) / 5.0)  # normalize to 5 providers
