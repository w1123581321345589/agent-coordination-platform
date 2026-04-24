import { Router, type IRouter } from "express";
import { eq, desc, sql } from "drizzle-orm";
import { db, strategiesTable } from "@workspace/db";
import {
  CreateStrategyBody,
  ProposeStrategySwitchParams,
  ApproveStrategyParams,
  RejectStrategyParams,
  RollbackStrategyParams,
  LintStrategyParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/strategies", async (_req, res): Promise<void> => {
  const strategies = await db.select().from(strategiesTable).orderBy(desc(strategiesTable.createdAt));
  res.json(strategies);
});

router.post("/strategies", async (req, res): Promise<void> => {
  const parsed = CreateStrategyBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [strategy] = await db.insert(strategiesTable).values({
    ...parsed.data,
    lifecycleStage: "ingest",
    escalationRate: 0,
    evidenceCount: 0,
  }).returning();
  res.status(201).json(strategy);
});

router.post("/strategies/:id/propose", async (req, res): Promise<void> => {
  const params = ProposeStrategySwitchParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [updated] = await db.update(strategiesTable)
    .set({ lifecycleStage: "propose", evidenceCount: sql`${strategiesTable.evidenceCount} + 1` })
    .where(eq(strategiesTable.id, params.data.id))
    .returning();
  if (!updated) {
    res.status(404).json({ error: "Strategy not found" });
    return;
  }
  res.json(updated);
});

router.post("/strategies/:id/approve", async (req, res): Promise<void> => {
  const params = ApproveStrategyParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const [strategy] = await db.update(strategiesTable)
    .set({ lifecycleStage: "active", expiresAt })
    .where(eq(strategiesTable.id, params.data.id))
    .returning();
  if (!strategy) {
    res.status(404).json({ error: "Strategy not found" });
    return;
  }
  res.json(strategy);
});

router.post("/strategies/:id/reject", async (req, res): Promise<void> => {
  const params = RejectStrategyParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [strategy] = await db.update(strategiesTable)
    .set({ lifecycleStage: "rejected" })
    .where(eq(strategiesTable.id, params.data.id))
    .returning();
  if (!strategy) {
    res.status(404).json({ error: "Strategy not found" });
    return;
  }
  res.json(strategy);
});

router.post("/strategies/:id/rollback", async (req, res): Promise<void> => {
  const params = RollbackStrategyParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [strategy] = await db.update(strategiesTable)
    .set({ lifecycleStage: "rolled_back" })
    .where(eq(strategiesTable.id, params.data.id))
    .returning();
  if (!strategy) {
    res.status(404).json({ error: "Strategy not found" });
    return;
  }
  res.json(strategy);
});

router.get("/strategies/:id/lint", async (req, res): Promise<void> => {
  const params = LintStrategyParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [strategy] = await db.select().from(strategiesTable).where(eq(strategiesTable.id, params.data.id));
  if (!strategy) {
    res.status(404).json({ error: "Strategy not found" });
    return;
  }
  const issues: { code: string; message: string; severity: "warning" | "error" }[] = [];
  // Stale check: active for > 25 days
  if (strategy.expiresAt) {
    const daysLeft = (new Date(strategy.expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24);
    if (daysLeft < 5) {
      issues.push({ code: "STALE_STRATEGY", message: "Strategy expires in less than 5 days — consider renewal or replacement.", severity: "warning" });
    }
  }
  // High escalation check
  if (strategy.escalationRate > 0.3) {
    issues.push({ code: "HIGH_ESCALATION", message: `Escalation rate ${(strategy.escalationRate * 100).toFixed(1)}% exceeds 30% threshold.`, severity: "error" });
  }
  // Low evidence
  if (strategy.evidenceCount < 3) {
    issues.push({ code: "LOW_EVIDENCE", message: "Fewer than 3 evidence points — consider gathering more data before deploying.", severity: "warning" });
  }
  res.json({ strategyId: params.data.id, issues, passed: issues.filter((i) => i.severity === "error").length === 0 });
});

router.get("/strategies/learning-curve", async (_req, res): Promise<void> => {
  const strategies = await db.select().from(strategiesTable).orderBy(strategiesTable.createdAt);
  res.json(strategies.map((s) => ({
    strategyId: s.id,
    strategyName: s.name,
    domain: s.domain,
    stage: s.lifecycleStage,
    evidenceCount: s.evidenceCount,
    escalationRate: s.escalationRate,
    createdAt: s.createdAt,
  })));
});

export default router;
