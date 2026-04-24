import pg from "pg";
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Get threat rules
const { rows: rules } = await pool.query("SELECT * FROM threat_rules WHERE rule_code IN ('T104','T105','T106')");
console.log("Rules:", rules.map((r) => r.rule_code));

const t104 = rules.find((r) => r.rule_code === "T104");
const t105 = rules.find((r) => r.rule_code === "T105");
const t106 = rules.find((r) => r.rule_code === "T106");

if (t104 && t105 && t106) {
  await pool.query(`
    INSERT INTO threat_events (rule_id, rule_code, agent_id, session_id, severity, details, resolved)
    VALUES ($1,'T104',4,2,'critical','Agent Apollo received prompt overriding system constraints via malicious task payload',0),
           ($2,'T105',3,1,'high','Agent Athena attempted to write analysis results to external endpoint not in approved list',0),
           ($3,'T106',2,NULL,'high','Agent Hermes claimed admin routing permissions beyond delegated scope',1)
  `, [t104.id, t105.id, t106.id]);
  console.log("Threat events seeded");
} else {
  console.log("Rules not found:", rules.length);
}

// Fix strategy lifecycles for ingest strategies
const { rows: ingestStrats } = await pool.query("SELECT * FROM strategies WHERE lifecycle_stage='ingest'");
console.log("Ingest strategies:", ingestStrats.map((s) => s.name));

for (const s of ingestStrats) {
  if (s.name.includes("Hierarchical")) {
    const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await pool.query("UPDATE strategies SET lifecycle_stage='active', evidence_count=evidence_count+3, expires_at=$1 WHERE id=$2", [expiry, s.id]);
  } else if (s.name.includes("Parallel")) {
    await pool.query("UPDATE strategies SET lifecycle_stage='propose', evidence_count=evidence_count+2 WHERE id=$1", [s.id]);
  }
}

// Print final state
const { rows: summary } = await pool.query(`
  SELECT
    (SELECT count(*)::int FROM agents) as agents,
    (SELECT count(*)::int FROM sessions) as sessions,
    (SELECT count(*)::int FROM threat_rules) as threat_rules,
    (SELECT count(*)::int FROM threat_events) as threat_events,
    (SELECT count(*)::int FROM routing_mappings) as routing_mappings,
    (SELECT count(*)::int FROM proposals) as proposals,
    (SELECT count(*)::int FROM context_domains) as context_domains,
    (SELECT count(*)::int FROM tournaments) as tournaments,
    (SELECT count(*)::int FROM strategies) as strategies,
    (SELECT count(*)::int FROM work_items) as work_items
`);
console.log("Final counts:", JSON.stringify(summary[0], null, 2));

await pool.end();
