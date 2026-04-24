import { Router, type IRouter } from "express";
import { eq, desc } from "drizzle-orm";
import { db, routingMappingsTable, routingPerformanceTable } from "@workspace/db";
import {
  CreateRoutingMappingBody,
  UpdateRoutingMappingParams,
  UpdateRoutingMappingBody,
  DeleteRoutingMappingParams,
  RecordRoutingPerformanceBody,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/routing/mappings", async (_req, res): Promise<void> => {
  const mappings = await db.select().from(routingMappingsTable).orderBy(routingMappingsTable.createdAt);
  res.json(mappings.map((m) => ({ ...m, active: m.active === 1 })));
});

router.post("/routing/mappings", async (req, res): Promise<void> => {
  const parsed = CreateRoutingMappingBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [mapping] = await db.insert(routingMappingsTable).values({ ...parsed.data, active: 1 }).returning();
  res.status(201).json({ ...mapping, active: mapping.active === 1 });
});

router.patch("/routing/mappings/:id", async (req, res): Promise<void> => {
  const params = UpdateRoutingMappingParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const parsed = UpdateRoutingMappingBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const updateData: Record<string, unknown> = { ...parsed.data };
  if (parsed.data.active !== undefined) updateData.active = parsed.data.active ? 1 : 0;
  const [mapping] = await db.update(routingMappingsTable).set(updateData).where(eq(routingMappingsTable.id, params.data.id)).returning();
  if (!mapping) {
    res.status(404).json({ error: "Mapping not found" });
    return;
  }
  res.json({ ...mapping, active: mapping.active === 1 });
});

router.delete("/routing/mappings/:id", async (req, res): Promise<void> => {
  const params = DeleteRoutingMappingParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [mapping] = await db.delete(routingMappingsTable).where(eq(routingMappingsTable.id, params.data.id)).returning();
  if (!mapping) {
    res.status(404).json({ error: "Mapping not found" });
    return;
  }
  res.sendStatus(204);
});

router.get("/routing/performance", async (_req, res): Promise<void> => {
  const records = await db.select().from(routingPerformanceTable).orderBy(desc(routingPerformanceTable.compositeScore));
  res.json(records);
});

router.post("/routing/performance", async (req, res): Promise<void> => {
  const parsed = RecordRoutingPerformanceBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const compositeScore = parsed.data.qualityScore * 0.6 + parsed.data.costScore * 0.2 + (1000 / Math.max(parsed.data.latencyMs, 1)) * 0.2;
  const [record] = await db.insert(routingPerformanceTable).values({ ...parsed.data, compositeScore }).returning();
  res.status(201).json(record);
});

export default router;
