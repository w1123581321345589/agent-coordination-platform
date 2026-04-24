"""
Aiglos — AI Agent Security Runtime
===================================
Protocol-agnostic runtime security for AI agents. Intercepts every agent
action before execution — MCP tool calls, direct HTTP/API calls, CLI
execution, subprocess spawning — and applies T01–T110 threat detection.

Signed session artifacts cover all three execution surfaces in a single
compliance document.

Quick start:
    import aiglos
    aiglos.attach(
        agent_name="my-agent",
        api_key=KEY,
        intercept_http=True,                    # optional: HTTP/API layer
        allow_http=["api.stripe.com"],          # optional: allow-list
        intercept_subprocess=True,              # optional: subprocess layer
        subprocess_tier3_mode="pause",          # optional: block | pause | warn
        tier3_approval_webhook="https://...",   # optional: PagerDuty / Slack
    )

    # MCP tool call inspection (manual API)
    result = aiglos.check("terminal", {"cmd": cmd})
    if result.blocked:
        raise RuntimeError(result.reason)

    aiglos.on_heartbeat()          # call at each cron/heartbeat cycle
    artifact = aiglos.close()      # signed session artifact -- all 3 surfaces

Framework integrations:
    from aiglos.integrations.openclaw import OpenClawGuard
    from aiglos.integrations.hermes   import HermesGuard
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

_CANONICAL_VERSION = "0.25.28"
try:
    from importlib.metadata import version as _pkg_version
    _v = _pkg_version("aiglos")
    import re as _re
    _parts = [int(x) for x in _re.findall(r"\d+", _v)]
    if _parts and _parts[0] == 0 and (len(_parts) < 2 or _parts[1] < 10):
        raise ValueError("stale")
    _cv = [int(x) for x in _re.findall(r"\d+", _CANONICAL_VERSION)]
    if _parts < _cv:
        raise ValueError("stale egg-info behind canonical")
    __version__: str = _v
except Exception:
    __version__ = _CANONICAL_VERSION
__author__  = "Aiglos"
__email__   = "security@aiglos.dev"
__license__ = "MIT"

log = logging.getLogger("aiglos")

# Re-export key types for external use
from aiglos.integrations.openclaw import (   # noqa: F401
    OpenClawGuard,
    SessionArtifact,
    ArtifactExtensions,
    GuardResult as CheckResult,
)
from aiglos.integrations.openclaw import (
    attach   as _oc_attach,
    check    as _oc_check,
    close    as _oc_close,
)
from aiglos.integrations.hermes import (     # noqa: F401
    HermesGuard,
)
from aiglos.integrations.multi_agent import (  # noqa: F401
    MultiAgentRegistry,
    AgentDefGuard,
    SessionIdentityChain,
    SpawnEvent,
    AgentDefViolation,
)
from aiglos.adaptive import (  # noqa: F401
    AdaptiveEngine,
    ObservationGraph,
    InspectionEngine,
    AmendmentEngine,
    PolicySerializer,
    SessionPolicy,
    CampaignAnalyzer,
    CampaignResult,
    MemoryProvenanceGraph,
    CrossSessionRisk,
    BeliefDriftReport,
)
from aiglos.integrations.memory_guard import (  # noqa: F401
    MemoryWriteGuard,
    MemoryWriteResult,
    inspect_memory_write,
    is_memory_tool,
)
from aiglos.core.threat_engine_v2 import RULES_T44_T66  # noqa: F401
from aiglos.adaptive.permission_recommender import (   # noqa: F401
    PermissionRecommender,
    PermissionRecommendation,
    ToolUsageStats,
)
from aiglos.autoresearch.atlas_coverage import ATLASCoverage  # noqa: F401
from aiglos.benchmark.govbench import (  # noqa: F401
    GovBench,
    GovBenchResult,
    DimensionResult,
)
from aiglos.cli.validate_prompt import (  # noqa: F401
    validate as validate_prompt,
    ValidationResult as PromptValidationResult,
    Finding as PromptFinding,
)
from aiglos.cli.scan_deps import (  # noqa: F401
    scan as scan_deps,
    ScanResult as ScanDepsResult,
    COMPROMISED_PACKAGES,
    TRANSITIVE_EXPOSURE,
    MALICIOUS_PTH_FILES,
    print_scan_report,
)
from aiglos.integrations.smolagents import (  # noqa: F401
    attach_for_smolagents,
    SmolagentsGuard,
)
from aiglos.core.threat_engine_v2 import (  # noqa: F401
    match_T82,
    match_T83,
    _T83_REGISTERED_CHANNELS,
    _T83_ACTIVE_ESCALATIONS,
    match_T84,
    _T84_SOURCE_EXTS,
    _T84_TARGET_EXTS,
    _T84_CIRCUMVENTION_KEYWORDS,
    match_T85,
    _T85_DENIAL_KEYWORDS,
    _T85_AUTHORSHIP_PATTERNS,
    match_T86,
    _extract_tenant_contexts,
    _T86_SESSION_READ_CONTEXTS,
    _T86_CONTEXT_PATTERNS,
    match_T87,
    match_T87_record_block,
    _T87_PROBE_THRESHOLD,
    match_T88,
    _T88_MCP_AUTH_TOOL_NAMES,
    match_T89,
    _T89_VCS_TOOL_NAMES,
    match_T90,
    _T90_REGISTRATION_TOOL_NAMES,
    match_T91,
    _T91_PIPELINE_WRITE_SESSIONS,
    match_T92,
    _T92_KNOWN_SCANNERS,
    match_T93,
    _T93_CREDENTIAL_PATTERNS,
    match_T94,
    _T94_POLICY_REJECTION_PATTERNS,
    _T94_PROVIDER_API_TOOLS,
    match_T95,
    _T95_EXECUTOR_BACKENDS,
    _T95_INJECTION_PATTERNS,
    match_T96,
    _T96_EXPLOIT_TOOLS,
    _T96_EXPLOIT_PATTERNS,
    match_T97,
    _T97_SANDBOX_PROBE_PATHS,
    _T97_EMERGENT_EXFIL_PATTERNS,
    match_T98,
    _T98_AGENT_DEF_FILES,
    _T98_VALIDATOR_BYPASS_PATTERNS,
    match_T99,
    match_T100,
    match_T101,
    match_T102,
    match_T103,
    match_T108,
    match_T109,
    match_T110,
    match_T104,
    match_T105,
    match_T106,
    match_T107,
    match_T111,
    cleanup_a2a_state,
    _T107_DELEGATION_CHAINS,
    _T111_DELEGATION_COUNTS,
)

from aiglos.integrations.managed_agents import (  # noqa: F401
    ManagedAgentGuard,
    managed_agent_guard,
)

from aiglos.integrations.ollama import (  # noqa: F401
    OllamaGuard,
    OllamaGuardResult,
    attach_for_ollama,
    lmstudio_guard,
    LOCAL_MODEL_FAMILIES,
    OLLAMA_ENDPOINTS,
    LMSTUDIO_ENDPOINTS,
)

from aiglos.forensics import ForensicStore
from aiglos.integrations.gigabrain import (  # noqa: F401
    declare_phantom_pipeline, phantom_autodetect, PHANTOM_PATHS
)  # Phantom self-evolving agent integration, ForensicRecord  # noqa: F401
from aiglos.integrations.openclaw import (  # noqa: F401 -- Zsh bypass defense
    normalize_shell_command,
    extract_shell_tool_name,
    PermissionDenialEvent,
)

from aiglos.forensics import ForensicStore, ForensicRecord  # noqa: F401

from aiglos.integrations.memory_guard import (  # noqa: F401
    check_memory_size_anomaly,
    MEMORY_MAX_LINES,
    MEMORY_MAX_NOTE_CHARS,
)

from aiglos.cli.validate_prompt import (  # noqa: F401
    score_three_layer_structure,
)

from aiglos.integrations.openclaw_mcp import (  # noqa: F401
    attach_for_openclaw_mcp,
    OpenClawMCPSession,
    OPENCLAW_MCP_TOOLS,
    MCP_READ_TOOLS,
    MCP_WRITE_TOOLS,
)

from aiglos.integrations.gigabrain import (  # noqa: F401
    declare_kairos_agent,
    kairos_autodetect,
    KAIROS_PATHS,
    declare_hermes_supervisor,
    hermes_on_escalation,
    hermes_on_escalation_resolved,
    declare_memory_backend,
    gigabrain_autodetect,
    byterover_autodetect,
    declare_self_improvement_pipeline,
    dgm_hyperagents_autodetect,
    declare_studio_pipeline,
    declare_ai_scientist_pipeline,
    declare_hermes_supervisor,
    ai_scientist_autodetect,
    is_registered_memory_path,
    MemoryBackendSession,
    BYTEROVER_DEFAULT_PATHS,
    DGM_PIPELINE_PATHS,
    STUDIO_ROLE_TOOLS,
    AI_SCIENTIST_PATHS,
)
from aiglos.integrations.subagent_registry import (  # noqa: F401
    SubagentRegistry,
    DeclaredSubagent,
    SpawnCheckResult,
)
from aiglos.integrations.openShell import (  # noqa: F401
    is_inside_openShell,
    openShell_context,
    openshell_detect,
    attach_openShell,
    attach_for_claude_code,
    attach_for_codex,
    attach_for_cursor,
    attach_for_openclaw,
)
from aiglos.integrations.nemoclaw import (  # noqa: F401
    NeMoClawSession,
    NeMoClawPolicy,
    mark_as_nemoclaw_session,
    validate_policy as validate_nemoclaw_policy,
)
from aiglos.integrations.superpowers import (  # noqa: F401
    SuperpowersSession,
    SuperpowersPhase,
    mark_as_superpowers_session,
)
from aiglos.autoresearch.ghsa_watcher import (   # noqa: F401
    GHSAWatcher,
    seed_known_advisories,
)
from aiglos.autoresearch.ghsa_coverage import (  # noqa: F401
    generate_coverage_artifact,
    GHSACoverageArtifact,
)

from aiglos.audit.scanner import AuditScanner, AuditResult, CheckResult  # noqa: F401
from aiglos.audit.report  import AuditReporter  # noqa: F401
from aiglos.adaptive.skill_reputation import (  # noqa: F401
    SkillReputationGraph,
    SkillRisk,
)
from aiglos.integrations.sandbox_policy import (  # noqa: F401
    SandboxPolicy,
    SandboxCheckResult,
)

from aiglos.adaptive.source_reputation import (  # noqa: F401
    SourceReputationGraph,
    SourceRecord,
    SourceRisk,
)

from aiglos.integrations.honeypot import (  # noqa: F401
    HoneypotManager,
    HoneypotResult,
)
from aiglos.integrations.override import (  # noqa: F401
    OverrideManager,
    OverrideChallenge,
    OverrideResult,
)

from aiglos.integrations.context_guard import (  # noqa: F401
    ContextDirectoryGuard,
    ContextWriteResult,
    ContextGuardResult,
    is_shared_context_write,
)
from aiglos.integrations.outbound_guard import (  # noqa: F401
    OutboundGuard,
    OutboundScanResult,
    scan_for_secrets,
    contains_secret,
)

from aiglos.cli.launch import (  # noqa: F401
    launch,
    LaunchConfig,
    generate_files,
    KNOWN_TOOLS as LAUNCH_KNOWN_TOOLS,
    KNOWN_MODELS as LAUNCH_KNOWN_MODELS,
)
from aiglos.cli.scaffold import (  # noqa: F401
    scaffold_from_descriptions,
    AgentSpec,
    ROLE_TOOLS,
)

from aiglos.autoresearch.citation_verifier import (  # noqa: F401
    CitationVerifier,
    VerifiedCitation,
    CitationStatus,
)
from aiglos.autoresearch.threat_literature import (  # noqa: F401
    ThreatLiteratureSearch,
    ThreatSignal,
)
from aiglos.autoresearch.verified_rule_engine import (  # noqa: F401
    VerifiedRuleEngine,
    VerifiedRunResult,
)
from aiglos.autoresearch.compliance_report import (  # noqa: F401
    ComplianceReportGenerator,
    ComplianceReport,
)

from aiglos.core.federation import (   # noqa: F401
    FederationClient,
    GlobalPrior,
    extract_shareable_transitions,
    _local_weight,
)

from aiglos.core.policy_proposal import (   # noqa: F401
    PolicyProposalEngine,
    PolicyProposal,
    BlockPattern,
    ProposalType,
    ProposalStatus,
)

from aiglos.core.behavioral_baseline import (  # noqa: F401
    BaselineEngine,
    AgentBaseline,
    BaselineScore,
    FeatureScore,
    SessionStats,
)

from aiglos.core.intent_predictor import (  # noqa: F401
    IntentPredictor,
    PredictionResult,
    MarkovTransitionModel,
)
from aiglos.core.threat_forecast import (  # noqa: F401
    SessionForecaster,
    ForecastAdjustment,
    ForecastSnapshot,
)
from aiglos.core.causal_tracer import (  # noqa: F401
    CausalTracer,
    CausalChain,
    AttributionResult,
    ContextEntry,
    TaggedAction,
)
from aiglos.integrations.injection_scanner import (  # noqa: F401
    InjectionScanner,
    InjectionScanResult,
    scan_tool_output,
    score_content,
    is_injection,
)
from aiglos.integrations.rl_guard import (  # noqa: F401
    RLFeedbackGuard,
    RLFeedbackResult,
    score_opd_feedback,
    is_reward_poison,
)
from aiglos.autoresearch.coupling import (  # noqa: F401
    SecurityAwareReward,
    CoupledRewardResult,
)


# ---------------------------------------------------------------------------
# Module-level generic API  (framework-agnostic)
# ---------------------------------------------------------------------------

_http_intercept_active:    bool = False
_subproc_intercept_active: bool = False
_multi_agent_registry:     Optional["MultiAgentRegistry"] = None
_agent_def_guard:          Optional["AgentDefGuard"]      = None
_session_identity:         Optional["SessionIdentityChain"] = None
_adaptive_engine:          Optional["AdaptiveEngine"]     = None


def attach(
    agent_name:             str            = "aiglos",
    policy:                 str            = "enterprise",
    log_path:               str            = "./aiglos.log",
    # HTTP/API interception
    intercept_http:         bool           = False,
    allow_http:             Optional[List[str]] = None,
    # Subprocess interception
    intercept_subprocess:   bool           = False,
    subprocess_tier3_mode:  str            = "warn",
    tier3_approval_webhook: Optional[str]  = None,
    # Multi-agent (v0.3.0)
    enable_multi_agent:     bool           = True,
    guard_agent_defs:       bool           = True,
    session_id:             Optional[str]  = None,
    # Adaptive layer (v0.4.0)
    enable_adaptive:        bool           = True,
    adaptive_db_path:       Optional[str]  = None,
    **kwargs,
) -> "OpenClawGuard":
    """
    Attach Aiglos to the current session.

    Activates the MCP interception layer unconditionally.
    Optionally activates HTTP/API, subprocess, and multi-agent layers.

    v0.3.0 adds: multi-agent spawn registry, agent definition file integrity
    guard (T36_AGENTDEF), session identity chain (HMAC-signed events), T37
    financial transaction detection, and T38 sub-agent spawn classification.
    """
    global _http_intercept_active, _subproc_intercept_active
    global _multi_agent_registry, _agent_def_guard, _session_identity

    # 1. Always activate MCP layer
    guard = _oc_attach(agent_name=agent_name, policy=policy, log_path=log_path)

    # 2. HTTP/API interception
    import os
    _env_http = os.environ.get("AIGLOS_INTERCEPT_HTTP", "").strip().lower() in ("true", "1", "yes")

    if intercept_http or _env_http:
        try:
            from aiglos.integrations.http_intercept import attach_http_intercept
            mode = _policy_to_mode(policy)
            results = attach_http_intercept(allow_list=allow_http or [], mode=mode)
            _http_intercept_active = True
            patched = [k for k, v in results.items() if v]
            log.info("[Aiglos] HTTP interception active: %s", patched)
        except Exception as e:
            log.warning("[Aiglos] HTTP interception failed to attach: %s", e)

    # 3. Subprocess interception
    _env_subproc = os.environ.get("AIGLOS_INTERCEPT_SUBPROCESS", "").strip().lower() in ("true", "1", "yes")
    _tier3_mode  = os.environ.get("AIGLOS_TIER3_MODE", subprocess_tier3_mode).strip().lower()
    _webhook     = os.environ.get("AIGLOS_TIER3_WEBHOOK", tier3_approval_webhook or "").strip() or tier3_approval_webhook

    if intercept_subprocess or _env_subproc:
        try:
            from aiglos.integrations.subprocess_intercept import attach_subprocess_intercept
            mode = _policy_to_mode(policy)
            results = attach_subprocess_intercept(
                mode=mode, tier3_mode=_tier3_mode, approval_webhook=_webhook or None)
            _subproc_intercept_active = True
            patched = [k for k, v in results.items() if v]
            log.info("[Aiglos] Subprocess interception active: %s | tier3_mode=%s",
                     patched, _tier3_mode)
        except Exception as e:
            log.warning("[Aiglos] Subprocess interception failed to attach: %s", e)

    # 4. Session identity chain (v0.3.0)
    try:
        _session_identity = SessionIdentityChain(agent_name=agent_name, session_id=session_id)
        log.info("[Aiglos] Session identity active: %s", _session_identity.session_id[:12])
    except Exception as e:
        log.warning("[Aiglos] Session identity failed to init: %s", e)

    # 5. Multi-agent spawn registry (v0.3.0)
    if enable_multi_agent:
        try:
            sid = _session_identity.session_id if _session_identity else "unknown"
            _multi_agent_registry = MultiAgentRegistry(root_session_id=sid, root_agent_name=agent_name)
            log.info("[Aiglos] Multi-agent registry active: root=%s", sid[:12])
        except Exception as e:
            log.warning("[Aiglos] Multi-agent registry failed to init: %s", e)

    # 6. Agent definition file guard (v0.3.0)
    if guard_agent_defs:
        try:
            _agent_def_guard = AgentDefGuard(cwd=os.getcwd())
            baseline = _agent_def_guard.snapshot()
            log.info("[Aiglos] Agent def guard active: %d files snapshotted.", len(baseline))
        except Exception as e:
            log.warning("[Aiglos] Agent def guard failed to init: %s", e)

    # 6a. Intent prediction
    if kwargs.get("enable_intent_prediction", False):
        try:
            _active_guard.enable_intent_prediction()
        except Exception as e:
            log.warning("[Aiglos] Intent prediction unavailable: %s", e)

    # 6b. Causal tracing
    if kwargs.get("enable_causal_tracing", False):
        try:
            _active_guard.enable_causal_tracing()
        except Exception as e:
            log.warning("[Aiglos] Causal tracing disabled: %s", e)

    # 6c. Source reputation
    if kwargs.get("enable_source_reputation", False):
        try:
            _active_guard.enable_source_reputation()
        except Exception as e:
            log.warning("[Aiglos] Source reputation unavailable: %s", e)

    # 6d. Behavioral baseline
    if kwargs.get("enable_behavioral_baseline", False):
        try:
            _active_guard.enable_behavioral_baseline()
        except Exception as e:
            log.warning("[Aiglos] Behavioral baseline disabled: %s", e)

    # 6e. Policy proposals
    if kwargs.get("enable_policy_proposals", False):
        try:
            _active_guard.enable_policy_proposals()
        except Exception as e:
            log.warning("[Aiglos] Policy proposals unavailable: %s", e)

    # 6f. Federation
    if kwargs.get("enable_federation", False):
        try:
            fed_kwargs = {k: v for k, v in kwargs.items()
                         if k in ("api_key", "endpoint")}
            _active_guard.enable_federation(**fed_kwargs)
        except Exception as e:
            log.warning("[Aiglos] Federation init failed: %s", e)

    # 6g. Honeypot
    if kwargs.get("enable_honeypot", False):
        try:
            _active_guard.enable_honeypot(
                custom_names = kwargs.get("honeypot_custom_names"),
                honeypot_dir = kwargs.get("honeypot_dir"),
            )
        except Exception as e:
            log.warning("[Aiglos] Honeypot layer unavailable: %s", e)

    # 7. Adaptive engine (v0.4.0)
    if enable_adaptive:
        try:
            _adaptive_engine = AdaptiveEngine(db_path=adaptive_db_path)
            log.info("[Aiglos] Adaptive engine active: %s", _adaptive_engine.graph._db_path)
        except Exception as e:
            log.warning("[Aiglos] Adaptive engine failed to init: %s", e)

    log.info(
        "[Aiglos v%s] Attached — agent=%s policy=%s mcp=on http=%s subprocess=%s "
        "multi_agent=%s agent_def_guard=%s adaptive=%s",
        __version__, agent_name, policy,
        "on" if _http_intercept_active else "off",
        "on" if _subproc_intercept_active else "off",
        "on" if _multi_agent_registry else "off",
        "on" if _agent_def_guard else "off",
        "on" if _adaptive_engine else "off",
    )
    return guard


def _policy_to_mode(policy: str) -> str:
    """Map guard policy to scanner mode."""
    return {
        "permissive": "warn",
        "enterprise": "block",
        "strict":     "block",
        "federal":    "block",
    }.get(policy, "block")


def check(
    tool_name: str,
    tool_args: Optional[Dict[str, Any]] = None,
) -> "CheckResult":
    """Check the input and return the result."""
    """
    Evaluate an MCP tool call before execution.

    Returns a CheckResult with .blocked / .warned / .allowed verdict.
    If blocked, do not execute the call.
    """
    return _oc_check(tool_name, tool_args or {})


def on_heartbeat() -> None:
    """Notify Aiglos of a cron/heartbeat cycle boundary."""
    from aiglos.integrations import openclaw as _oc
    if _oc._active_guard:
        _oc._active_guard.on_heartbeat()


def close() -> "SessionArtifact":
    """
    Close the current session and return a signed SessionArtifact.

    The artifact covers all three interception surfaces (MCP, HTTP, subprocess)
    plus multi-agent spawn tree and agent definition integrity violations.
    Call once at agent shutdown or end of task.
    """
    global _multi_agent_registry, _agent_def_guard, _session_identity

    # Collect events from all active layers
    http_events    = _collect_http_events()
    subproc_events = _collect_subprocess_events()

    # Check agent def integrity one final time before closing
    agentdef_violations: list = []
    if _agent_def_guard:
        try:
            violations = _agent_def_guard.check()
            agentdef_violations = [v.to_dict() for v in violations]
            if violations:
                log.warning(
                    "[Aiglos] %d agent definition integrity violation(s) at session close.",
                    len(violations),
                )
        except Exception as e:
            log.warning("[Aiglos] Agent def check at close failed: %s", e)

    # Collect multi-agent spawn tree
    multi_agent_data: dict = {}
    if _multi_agent_registry:
        try:
            multi_agent_data = _multi_agent_registry.to_dict()
        except Exception as e:
            log.warning("[Aiglos] Multi-agent tree serialization failed: %s", e)

    # Session identity header
    identity_header: dict = {}
    if _session_identity:
        try:
            identity_header = _session_identity.header()
        except Exception as e:
            log.warning("[Aiglos] Session identity header failed: %s", e)

    # Clean up stateful rule tracking for this session
    sid = _session_identity.session_id if _session_identity else "default"
    try:
        from aiglos.core.threat_engine_v2 import cleanup_stateful_rules
        cleanup_stateful_rules(session_key=sid)
    except Exception as e:
        log.warning("[Aiglos] Stateful rule cleanup failed: %s", e)
    try:
        from aiglos.core.threat_engine_v2 import cleanup_a2a_state
        cleanup_a2a_state(session_key=sid)
    except Exception as e:
        log.warning("[Aiglos] A2A state cleanup failed: %s", e)

    # Close the MCP guard and get base artifact
    artifact = _oc_close()

    # Attach all surface events and v0.3.0 data to artifact
    if artifact:
        _augment_artifact(
            artifact, http_events, subproc_events,
            agentdef_violations=agentdef_violations,
            multi_agent=multi_agent_data,
            identity=identity_header,
        )

    # v0.4.0: auto-ingest into adaptive observation graph
    if _adaptive_engine and artifact:
        try:
            _adaptive_engine.ingest(artifact)
        except Exception as e:
            log.debug("[Aiglos] Adaptive ingest (non-fatal): %s", e)

    return artifact


def adaptive_run() -> dict:
    """
    Run a full adaptive cycle: inspect + generate amendment proposals.

    Requires enable_adaptive=True in attach() (default).
    Returns a report dict with triggers fired and proposals made.
    """
    if _adaptive_engine is None:
        return {"error": "Adaptive engine not initialised. Call attach() first."}
    return _adaptive_engine.run()


def adaptive_stats() -> dict:
    """Return the current observation graph summary across all sessions."""
    if _adaptive_engine is None:
        return {"error": "Adaptive engine not initialised. Call attach() first."}
    return _adaptive_engine.stats()


def derive_child_policy(parent_session_id: str) -> "SessionPolicy":
    """Derive a policy for a spawned child agent from parent session history."""
    if _adaptive_engine is None:
        from aiglos.adaptive.policy import SessionPolicy
        return SessionPolicy.empty(parent_session_id)
    return _adaptive_engine.derive_child_policy(parent_session_id)


def _collect_http_events() -> list:
    if not _http_intercept_active:
        return []
    try:
        from aiglos.integrations.http_intercept import (
            get_session_http_events, clear_session_http_events)
        events = get_session_http_events()
        clear_session_http_events()
        return events
    except Exception:
        return []


def _collect_subprocess_events() -> list:
    if not _subproc_intercept_active:
        return []
    try:
        from aiglos.integrations.subprocess_intercept import (
            get_session_subprocess_events, clear_session_subprocess_events)
        events = get_session_subprocess_events()
        clear_session_subprocess_events()
        return events
    except Exception:
        return []


def _augment_artifact(artifact: "SessionArtifact",
                       http_events: list,
                       subproc_events: list,
                       agentdef_violations: list = [],
                       multi_agent: dict = {},
                       identity: dict = {}) -> None:
    """Attach all surface data to a session artifact."""
    try:
        if not hasattr(artifact, "extra"):
            artifact.extra = {}
        artifact.extra["http_events"]            = http_events
        artifact.extra["subproc_events"]         = subproc_events
        artifact.extra["http_blocked"]           = sum(
            1 for e in http_events if e.get("verdict") == "BLOCK")
        artifact.extra["subproc_blocked"]        = sum(
            1 for e in subproc_events if e.get("verdict") == "BLOCK")
        # v0.3.0 fields
        artifact.extra["agentdef_violations"]    = agentdef_violations
        artifact.extra["agentdef_violation_count"] = len(agentdef_violations)
        artifact.extra["multi_agent"]            = multi_agent
        artifact.extra["session_identity"]       = identity
        artifact.extra["aiglos_version"]         = __version__
    except Exception as e:
        log.warning("[Aiglos] Artifact augmentation failed: %s", e)


def status() -> dict:
    """Return current Aiglos runtime status across all layers (v0.3.0)."""
    mcp_status: dict = {}
    try:
        from aiglos.integrations import openclaw as _oc
        if _oc._active_guard:
            mcp_status = _oc._active_guard.status()
    except Exception:
        pass

    http_status: dict = {}
    if _http_intercept_active:
        try:
            from aiglos.integrations.http_intercept import http_intercept_status
            http_status = http_intercept_status()
        except Exception:
            pass

    subproc_status: dict = {}
    if _subproc_intercept_active:
        try:
            from aiglos.integrations.subprocess_intercept import subprocess_intercept_status
            subproc_status = subprocess_intercept_status()
        except Exception:
            pass

    agentdef_status: dict = {}
    if _agent_def_guard:
        try:
            violations = _agent_def_guard.check()
            agentdef_status = {
                "files_monitored": len(_agent_def_guard.baseline),
                "violations":      len(violations),
                "violation_types": [v.violation_type for v in violations],
            }
        except Exception:
            pass

    multi_agent_status: dict = {}
    if _multi_agent_registry:
        try:
            spawns = _multi_agent_registry.all_spawns()
            multi_agent_status = {
                "root_session":  _multi_agent_registry._root_id[:12],
                "spawn_count":   len(spawns),
                "child_count":   len(_multi_agent_registry._children),
            }
        except Exception:
            pass

    identity_status: dict = {}
    if _session_identity:
        try:
            identity_status = {
                "session_id":   _session_identity.session_id[:12],
                "event_count":  _session_identity._event_count,
                "public_token": _session_identity.public_token[:16] + "...",
            }
        except Exception:
            pass

    adaptive_status: dict = {}
    if _adaptive_engine:
        try:
            adaptive_status = _adaptive_engine.stats()
        except Exception:
            pass

    return {
        "version":                 __version__,
        "mcp_layer":               mcp_status,
        "http_layer_active":       _http_intercept_active,
        "http_layer":              http_status,
        "subprocess_layer_active": _subproc_intercept_active,
        "subprocess_layer":        subproc_status,
        "agent_def_guard_active":  _agent_def_guard is not None,
        "agent_def_guard":         agentdef_status,
        "multi_agent_active":      _multi_agent_registry is not None,
        "multi_agent":             multi_agent_status,
        "session_identity_active": _session_identity is not None,
        "session_identity":        identity_status,
        "adaptive_active":         _adaptive_engine is not None,
        "adaptive":                adaptive_status,
    }


__all__ = [
    "__version__",
    "attach",
    "check",
    "on_heartbeat",
    "close",
    "status",
    "adaptive_run",
    "adaptive_stats",
    "derive_child_policy",
    "OpenClawGuard",
    "HermesGuard",
    "CheckResult",
    "SessionArtifact",
    # v0.3.0
    "MultiAgentRegistry",
    "AgentDefGuard",
    "SessionIdentityChain",
    "SpawnEvent",
    "AgentDefViolation",
    # v0.4.0
    "AdaptiveEngine",
    "ObservationGraph",
    "InspectionEngine",
    "AmendmentEngine",
    "PolicySerializer",
    "SessionPolicy",
    "CampaignAnalyzer",
    "CampaignResult",
    # v0.5.0
    "MemoryWriteGuard",
    "MemoryWriteResult",
    "inspect_memory_write",
    "is_memory_tool",
    "MemoryProvenanceGraph",
    "CrossSessionRisk",
    "BeliefDriftReport",
    # v0.6.0
    "RLFeedbackGuard",
    "RLFeedbackResult",
    "SecurityAwareReward",
    "CoupledRewardResult",
    # v0.8.0
    "InjectionScanner",
    "InjectionScanResult",
    "scan_tool_output",
    "score_content",
    "is_injection",
    # v0.9.0
    "CausalTracer",
    "CausalChain",
    "AttributionResult",
    "ContextEntry",
    "TaggedAction",
    # v0.10.0
    "IntentPredictor",
    "PredictionResult",
    "MarkovTransitionModel",
    "SessionForecaster",
    "ForecastAdjustment",
    "ForecastSnapshot",
    # v0.10.0 artifact
    "ArtifactExtensions",
    # v0.11.0
    "BaselineEngine",
    "AgentBaseline",
    "BaselineScore",
    "FeatureScore",
    "SessionStats",
    # v0.12.0
    "PolicyProposalEngine",
    "PolicyProposal",
    "BlockPattern",
    "ProposalType",
    "ProposalStatus",
    # v0.13.0
    "FederationClient",
    "GlobalPrior",
    "extract_shareable_transitions",
    # v0.23.0 — T70 ENV_PATH_HIJACK, GHSA watcher, 3/3 advisory coverage
    "GHSAWatcher",
    "seed_known_advisories",
    "generate_coverage_artifact",
    "GHSACoverageArtifact",
    # v0.23.0 — T70 ENV_PATH_HIJACK, GHSA watcher, GHSA validation
    # v0.25.6 — validate_prompt (Shapiro Input Layer framework)
    "validate_prompt",
    "PromptValidationResult",
    "PromptFinding",
    # v0.25.5 — T81 PTH_FILE_INJECT, scan_deps, REPO_TAKEOVER_CHAIN (LiteLLM incident)
    "scan_deps",
    "ScanDepsResult",
    "COMPROMISED_PACKAGES",
    "TRANSITIVE_EXPOSURE",
    "MALICIOUS_PTH_FILES",
    "print_scan_report",
    # v0.25.4 — T80 UNCENSORED_MODEL_ROUTE, smolagents integration, HF Spaces feed
    "attach_for_smolagents",
    "SmolagentsGuard",
    # v0.25.13 — T84 IP_TRANSFORMATION_EXFIL (claw-code incident March 31 2026),
    #             IP_CIRCUMVENTION_CHAIN campaign (T19/T22 -> T84 -> T01/T41)
    "match_T84",
    "_T84_SOURCE_EXTS",
    "_T84_TARGET_EXTS",
    "_T84_CIRCUMVENTION_KEYWORDS",
    # v0.25.12 — T83 INTER_AGENT_PROTOCOL_SPOOF, declare_hermes_supervisor(),
    #             Hermes in KNOWN_AGENTS, Hermes case study in T82
    "declare_hermes_supervisor",
    "hermes_on_escalation",
    "hermes_on_escalation_resolved",
    "match_T82",
    "match_T83",
    "_T83_REGISTERED_CHANNELS",
    "_T83_ACTIVE_ESCALATIONS",
    # v0.25.13 — T84 IP_TRANSFORMATION_EXFIL (claw-code incident March 31 2026),
    #             IP_CIRCUMVENTION_CHAIN campaign (T19/T22 -> T84 -> T01/T41)
    # v0.25.12 — T83 INTER_AGENT_PROTOCOL_SPOOF, declare_hermes_supervisor(), Hermes in KNOWN_AGENTS
    # v0.25.11 — is_memory_tool() full backend coverage (ByteRover, context_engine, Gigabrain, mem0, Letta, Qdrant, Pinecone)
    # v0.25.10 — declare_ai_scientist_pipeline(), AI Scientist Nature paper T82 citation
    "declare_ai_scientist_pipeline",
    "ai_scientist_autodetect",
    "AI_SCIENTIST_PATHS",
    # v0.25.9 — OpenClaw MCP integration (steipete), T28/T41/T13/T36 MCP tool names
    "attach_for_openclaw_mcp",
    "OpenClawMCPSession",
    "OPENCLAW_MCP_TOOLS",
    "MCP_READ_TOOLS",
    "MCP_WRITE_TOOLS",
    # v0.25.8 — declare_studio_pipeline(), STUDIO_ROLE_TOOLS, Game Studios integration
    "declare_studio_pipeline",
    "STUDIO_ROLE_TOOLS",
    # v0.25.7 — T82 SELF_IMPROVEMENT_HIJACK, METACOGNITIVE_POISON_CHAIN, DGM-H integration
    "declare_self_improvement_pipeline",
    "dgm_hyperagents_autodetect",
    "DGM_PIPELINE_PATHS",
    # v0.25.6 (continued) — ByteRover integration, curl|sh detection in scan_deps
    "byterover_autodetect",
    "BYTEROVER_DEFAULT_PATHS",
    # v0.25.3 — T79 PERSISTENT_MEMORY_INJECT, Gigabrain integration, 21 campaign patterns
    "declare_memory_backend",
    "gigabrain_autodetect",
    "is_registered_memory_path",
    "MemoryBackendSession",
    # v0.25.2 — declare_subagent(), T77 OVERNIGHT_JOB_INJECTION, SubagentRegistry
    "SubagentRegistry",
    "DeclaredSubagent",
    # v0.25.1 — OpenShell agent-agnostic integration, openshell_detect()
    "is_inside_openShell",
    "openShell_context",
    "openshell_detect",
    "attach_openShell",
    "attach_for_claude_code",
    "attach_for_codex",
    "attach_for_cursor",
    "attach_for_openclaw",
    # v0.25.0 — T76 NEMOCLAW_POLICY_BYPASS, NemoClaw integration, 20 campaign patterns
    "NeMoClawSession",
    "NeMoClawPolicy",
    "mark_as_nemoclaw_session",
    "validate_nemoclaw_policy",
    # v0.24.0 — T71-T75 (ATLAS threat model), ATLASCoverage, hardening check
    "ATLASCoverage",
    # v0.22.0 — T69 PLAN_DRIFT, Superpowers integration, 19 campaign patterns
    "SuperpowersSession",
    "SuperpowersPhase",
    "mark_as_superpowers_session",
    # v0.21.0 — T67 HEARTBEAT_SILENCE, T68 INSECURE_DEFAULT_CONFIG, scan-exposed
    # v0.20.0
    "PermissionRecommender",
    "PermissionRecommendation",
    "ToolUsageStats",
    "GovBench",
    "GovBenchResult",
    "DimensionResult",
    # v0.19.0
    "RULES_T44_T66",
    # v0.18.0
    "AuditScanner",
    "AuditResult",
    "AuditReporter",
    "SkillReputationGraph",
    "SkillRisk",
    "SandboxPolicy",
    "SandboxCheckResult",
    # v0.17.0
    "SourceReputationGraph",
    "SourceRecord",
    "SourceRisk",
    # v0.16.0
    "HoneypotManager",
    "HoneypotResult",
    "OverrideManager",
    "OverrideChallenge",
    "OverrideResult",
    # v0.15.0
    "ContextDirectoryGuard",
    "ContextGuardResult",
    "is_shared_context_write",
    "OutboundGuard",
    "OutboundScanResult",
    "scan_for_secrets",
    "contains_secret",
    # v0.14.0
    "CitationVerifier",
    "VerifiedCitation",
    "CitationStatus",
    "ThreatLiteratureSearch",
    "ThreatSignal",
    "VerifiedRuleEngine",
    "VerifiedRunResult",
    "ComplianceReportGenerator",
    "ComplianceReport",
    # v0.25.22 — T94 PROVIDER_POLICY_REJECTION, T95 CROSS_TRUST_BOUNDARY_INJECT, Ollama integration
    "match_T94",
    "_T94_POLICY_REJECTION_PATTERNS",
    "_T94_PROVIDER_API_TOOLS",
    "match_T95",
    "_T95_EXECUTOR_BACKENDS",
    "_T95_INJECTION_PATTERNS",
    "match_T96",
    "_T96_EXPLOIT_TOOLS",
    "_T96_EXPLOIT_PATTERNS",
    "match_T97",
    "_T97_SANDBOX_PROBE_PATHS",
    "_T97_EMERGENT_EXFIL_PATTERNS",
    "match_T98",
    "_T98_AGENT_DEF_FILES",
    "_T98_VALIDATOR_BYPASS_PATTERNS",
    "match_T102",
    "match_T103",
    # v0.25.28 — T108 CREDENTIAL_COMPROMISED_UPDATE, T109 BROWSER_SESSION_HIJACK, T110 SELF_HEALING_BACKDOOR
    "match_T108",
    "match_T109",
    "match_T110",
    # v0.26.0 — A2A Protocol Security (Coordination Platform)
    "match_T104",
    "match_T105",
    "match_T106",
    "match_T107",
    "match_T111",
    "cleanup_a2a_state",
    "_T107_DELEGATION_CHAINS",
    "_T111_DELEGATION_COUNTS",
    "OllamaGuard",
    "OllamaGuardResult",
    "attach_for_ollama",
    "lmstudio_guard",
    "LOCAL_MODEL_FAMILIES",
    "OLLAMA_ENDPOINTS",
    "LMSTUDIO_ENDPOINTS",
]
