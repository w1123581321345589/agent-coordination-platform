import { Router, type IRouter } from "express";
import { eq, sql } from "drizzle-orm";
import { db, sessionsTable, messagesTable, agentsTable } from "@workspace/db";
import {
  CreateSessionBody,
  GetSessionParams,
  UpdateSessionParams,
  UpdateSessionBody,
  RouteMessageBody,
  GenerateClaimParams,
} from "@workspace/api-zod";
import { randomUUID } from "crypto";

const router: IRouter = Router();

router.get("/sessions", async (_req, res): Promise<void> => {
  const sessions = await db.select().from(sessionsTable).orderBy(sessionsTable.createdAt);
  res.json(sessions);
});

router.post("/sessions", async (req, res): Promise<void> => {
  const parsed = CreateSessionBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [session] = await db.insert(sessionsTable).values(parsed.data).returning();
  res.status(201).json(session);
});

router.get("/sessions/:id", async (req, res): Promise<void> => {
  const params = GetSessionParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [session] = await db.select().from(sessionsTable).where(eq(sessionsTable.id, params.data.id));
  if (!session) {
    res.status(404).json({ error: "Session not found" });
    return;
  }
  res.json(session);
});

router.patch("/sessions/:id", async (req, res): Promise<void> => {
  const params = UpdateSessionParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const parsed = UpdateSessionBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [session] = await db.update(sessionsTable).set(parsed.data).where(eq(sessionsTable.id, params.data.id)).returning();
  if (!session) {
    res.status(404).json({ error: "Session not found" });
    return;
  }
  res.json(session);
});

// Messages
router.get("/messages", async (req, res): Promise<void> => {
  const sessionId = req.query.sessionId ? Number(req.query.sessionId) : null;
  const messages = sessionId
    ? await db.select().from(messagesTable).where(eq(messagesTable.sessionId, sessionId)).orderBy(messagesTable.createdAt)
    : await db.select().from(messagesTable).orderBy(messagesTable.createdAt);
  const result = messages.map((m) => ({ ...m, claimGenerated: m.claimGenerated === 1 }));
  res.json(result);
});

router.post("/messages", async (req, res): Promise<void> => {
  const parsed = RouteMessageBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [message] = await db.insert(messagesTable).values({ ...parsed.data, claimGenerated: 0 }).returning();
  // Increment session message count
  await db.update(sessionsTable)
    .set({ messageCount: sql`${sessionsTable.messageCount} + 1` })
    .where(eq(sessionsTable.id, parsed.data.sessionId));
  res.status(201).json({ ...message, claimGenerated: false });
});

router.post("/messages/:id/claim", async (req, res): Promise<void> => {
  const params = GenerateClaimParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [message] = await db.select().from(messagesTable).where(eq(messagesTable.id, params.data.id));
  if (!message) {
    res.status(404).json({ error: "Message not found" });
    return;
  }
  // Mark claim as generated
  await db.update(messagesTable).set({ claimGenerated: 1 }).where(eq(messagesTable.id, params.data.id));
  res.json({
    messageId: params.data.id,
    claimId: `CLAIM-${randomUUID().slice(0, 8).toUpperCase()}`,
    claimType: message.messageType === "delegation" ? "coordination" : "attestation",
    payload: JSON.stringify({ messageType: message.messageType, content: message.content.slice(0, 100) }),
    issuedAt: new Date().toISOString(),
  });
});

export default router;
