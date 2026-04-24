const BASE = "http://localhost:8080/api";

async function post(path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function get(path) {
  const r = await fetch(`${BASE}${path}`);
  return r.json();
}

// Tournaments
const t1 = await post("/tournaments", { taskDescription: "Build microservices migration plan", domain: "backend", taskType: "planning" });
const t2 = await post("/tournaments", { taskDescription: "Evaluate risk models for Q2 forecast", domain: "finance", taskType: "analysis" });
console.log(`Tournaments: ${t1.id}, ${t2.id}`);

// Score T1 variants
for (const [i, v] of t1.variants.entries()) {
  const scores = [
    { qualityScore: 0.88, efficiencyScore: 0.71, costScore: 0.65 },
    { qualityScore: 0.82, efficiencyScore: 0.84, costScore: 0.79 },
    { qualityScore: 0.79, efficiencyScore: 0.91, costScore: 0.88 },
  ];
  await post(`/tournaments/${t1.id}/score`, { variantId: v.id, ...scores[i] });
}
console.log(`T1 variants scored`);

// Score T2 variants (partial — just 2 scored)
const t2v = t2.variants;
await post(`/tournaments/${t2.id}/score`, { variantId: t2v[0].id, qualityScore: 0.74, efficiencyScore: 0.88, costScore: 0.91 });
await post(`/tournaments/${t2.id}/score`, { variantId: t2v[1].id, qualityScore: 0.89, efficiencyScore: 0.77, costScore: 0.72 });
console.log(`T2 partially scored`);

// Strategies
const s1 = await post("/strategies", { name: "Hierarchical Orchestration v2", description: "Centralized orchestrator delegates subtasks with explicit handoff tokens", domain: "backend", coordinationPattern: "hierarchical" });
const s2 = await post("/strategies", { name: "Parallel Debate Protocol", description: "Multiple specialist agents generate solutions independently, best selected by composite scoring", domain: "finance", coordinationPattern: "debate" });
const s3 = await post("/strategies", { name: "Adaptive Hybrid Routing", description: "Dynamically switches between hierarchical and parallel patterns based on task complexity", domain: "security", coordinationPattern: "hybrid" });
console.log(`Strategies: ${s1.id}, ${s2.id}, ${s3.id}`);

await post(`/strategies/${s1.id}/propose`);
await post(`/strategies/${s1.id}/approve`);
await post(`/strategies/${s2.id}/propose`);
// s3 stays in ingest

// Threat events (post via threat rules + manual injection)
const rules = await get("/threats/rules");
const t104 = rules.find((r) => r.ruleCode === "T104");
const t105 = rules.find((r) => r.ruleCode === "T105");
const t106 = rules.find((r) => r.ruleCode === "T106");

// Direct DB: we can POST a fake threat event by calling the API if the route exists
// The OpenAPI spec might expose POST /threats/events — checking by just posting
async function postThreatEvent(ruleId, ruleCode, agentId, severity, details) {
  const r = await fetch(`${BASE}/threats/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ruleId, ruleCode, agentId, severity, details, resolved: 0 }),
  });
  return r.json();
}

// Try posting
if (t104 && t105 && t106) {
  const e1 = await postThreatEvent(t104.id, "T104", 4, "critical", "Agent Apollo received prompt overriding its system constraints via malicious task content");
  const e2 = await postThreatEvent(t105.id, "T105", 3, "high", "Agent Athena attempted to write analysis results to external endpoint not in approved list");
  const e3 = await postThreatEvent(t106.id, "T106", 2, "high", "Agent Hermes claimed admin routing permissions beyond delegated scope");
  console.log(`Threat events posted: ${JSON.stringify([e1?.id, e2?.id, e3?.id])}`);
} else {
  console.log("Rules not found, skipping threat events:", JSON.stringify(rules.slice(0,2)));
}

// Recovery work items
await post("/recovery/work-items", { taskDescription: "Complete Q1 anomaly analysis — agent Atlas timed out", domain: "finance", priority: 8, originalAgentId: 1, recoveryContext: "Session 1 timeout at 95% completion" });
await post("/recovery/work-items", { taskDescription: "Finish inventory API code generation", domain: "backend", priority: 6, originalAgentId: 4, recoveryContext: "Agent paused mid-generation, 3/8 endpoints complete" });
await post("/recovery/work-items", { taskDescription: "Run security audit on auth module", domain: "security", priority: 9, originalAgentId: 5, recoveryContext: "Threat event T105 fired, agent paused for safety" });

console.log("Seed complete!");

const summary = await get("/dashboard/summary");
console.log("Dashboard:", JSON.stringify(summary, null, 2));
