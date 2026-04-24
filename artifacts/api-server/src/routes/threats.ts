import { Router, type IRouter } from "express";
import { eq, sql, desc } from "drizzle-orm";
import { db, threatRulesTable, threatEventsTable } from "@workspace/db";
import {
  CreateThreatRuleBody,
  UpdateThreatRuleParams,
  UpdateThreatRuleBody,
  ResolveThreatEventParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/threats/rules", async (_req, res): Promise<void> => {
  const rules = await db.select().from(threatRulesTable).orderBy(threatRulesTable.createdAt);
  res.json(rules.map((r) => ({ ...r, enabled: r.enabled === 1 })));
});

router.post("/threats/rules", async (req, res): Promise<void> => {
  const parsed = CreateThreatRuleBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [rule] = await db.insert(threatRulesTable).values({ ...parsed.data, enabled: 1, firedCount: 0 }).returning();
  res.status(201).json({ ...rule, enabled: rule.enabled === 1 });
});

router.patch("/threats/rules/:id", async (req, res): Promise<void> => {
  const params = UpdateThreatRuleParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const parsed = UpdateThreatRuleBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const updateData: Record<string, unknown> = {};
  if (parsed.data.enabled !== undefined) updateData.enabled = parsed.data.enabled ? 1 : 0;
  const [rule] = await db.update(threatRulesTable).set(updateData).where(eq(threatRulesTable.id, params.data.id)).returning();
  if (!rule) {
    res.status(404).json({ error: "Rule not found" });
    return;
  }
  res.json({ ...rule, enabled: rule.enabled === 1 });
});

router.get("/threats/events", async (_req, res): Promise<void> => {
  const events = await db.select().from(threatEventsTable).orderBy(desc(threatEventsTable.createdAt));
  res.json(events.map((e) => ({ ...e, resolved: e.resolved === 1 })));
});

router.post("/threats/events/:id/resolve", async (req, res): Promise<void> => {
  const params = ResolveThreatEventParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [event] = await db.update(threatEventsTable).set({ resolved: 1 }).where(eq(threatEventsTable.id, params.data.id)).returning();
  if (!event) {
    res.status(404).json({ error: "Event not found" });
    return;
  }
  res.json({ ...event, resolved: true });
});

router.get("/threats/stats", async (_req, res): Promise<void> => {
  const events = await db.select().from(threatEventsTable);
  const total = events.length;
  const unresolved = events.filter((e) => e.resolved === 0).length;
  const bySeverity = ["low", "medium", "high", "critical"].map((s) => ({
    severity: s,
    count: events.filter((e) => e.severity === s).length,
  }));
  const ruleMap: Record<string, number> = {};
  events.forEach((e) => { ruleMap[e.ruleCode] = (ruleMap[e.ruleCode] || 0) + 1; });
  const byRule = Object.entries(ruleMap).map(([ruleCode, count]) => ({ ruleCode, count }));
  res.json({ totalEvents: total, unresolvedEvents: unresolved, bySeverity, byRule });
});

export default router;
