import { Router, type IRouter } from "express";
import { eq, desc } from "drizzle-orm";
import { db, workItemsTable, recoveryEventsTable } from "@workspace/db";
import {
  EnqueueWorkItemBody,
  ClaimWorkItemParams,
  ClaimWorkItemBody,
  CompleteWorkItemParams,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/recovery/work-items", async (_req, res): Promise<void> => {
  const items = await db.select().from(workItemsTable).orderBy(desc(workItemsTable.priority), workItemsTable.createdAt);
  res.json(items);
});

router.post("/recovery/work-items", async (req, res): Promise<void> => {
  const parsed = EnqueueWorkItemBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [item] = await db.insert(workItemsTable).values({ ...parsed.data, status: "queued" }).returning();
  // Emit recovery event
  await db.insert(recoveryEventsTable).values({
    eventType: "work_returned",
    workItemId: item.id,
    agentId: parsed.data.originalAgentId ?? null,
    payload: JSON.stringify({ taskDescription: item.taskDescription, domain: item.domain }),
  });
  res.status(201).json(item);
});

router.post("/recovery/work-items/:id/claim", async (req, res): Promise<void> => {
  const params = ClaimWorkItemParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const parsed = ClaimWorkItemBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [item] = await db.update(workItemsTable)
    .set({ status: "claimed", claimedByAgentId: parsed.data.agentId })
    .where(eq(workItemsTable.id, params.data.id))
    .returning();
  if (!item) {
    res.status(404).json({ error: "Work item not found" });
    return;
  }
  await db.insert(recoveryEventsTable).values({
    eventType: "agent_claimed",
    workItemId: item.id,
    agentId: parsed.data.agentId,
    payload: JSON.stringify({ workItemId: item.id, agentId: parsed.data.agentId }),
  });
  res.json(item);
});

router.post("/recovery/work-items/:id/complete", async (req, res): Promise<void> => {
  const params = CompleteWorkItemParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [item] = await db.update(workItemsTable).set({ status: "completed" }).where(eq(workItemsTable.id, params.data.id)).returning();
  if (!item) {
    res.status(404).json({ error: "Work item not found" });
    return;
  }
  await db.insert(recoveryEventsTable).values({
    eventType: "work_completed",
    workItemId: item.id,
    agentId: item.claimedByAgentId ?? null,
    payload: JSON.stringify({ workItemId: item.id }),
  });
  res.json(item);
});

router.get("/recovery/events", async (_req, res): Promise<void> => {
  const events = await db.select().from(recoveryEventsTable).orderBy(desc(recoveryEventsTable.createdAt));
  res.json(events);
});

export default router;
