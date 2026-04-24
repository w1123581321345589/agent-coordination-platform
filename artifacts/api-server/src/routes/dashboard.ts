import { Router, type IRouter } from "express";
import { eq, count, sql } from "drizzle-orm";
import { db, agentsTable, sessionsTable, messagesTable, threatEventsTable, workItemsTable, proposalsTable, strategiesTable, tournamentsTable } from "@workspace/db";

const router: IRouter = Router();

router.get("/dashboard/summary", async (_req, res): Promise<void> => {
  const [agents] = await db.select({ total: count() }).from(agentsTable);
  const [activeAgents] = await db.select({ total: count() }).from(agentsTable).where(eq(agentsTable.status, "active"));
  const [activeSessions] = await db.select({ total: count() }).from(sessionsTable).where(eq(sessionsTable.status, "open"));
  const [messagesRouted] = await db.select({ total: count() }).from(messagesTable);
  const [threatsDetected] = await db.select({ total: count() }).from(threatEventsTable);

  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [threatsFired24h] = await db.select({ total: count() }).from(threatEventsTable)
    .where(sql`${threatEventsTable.createdAt} > ${oneDayAgo}`);

  const [pendingWork] = await db.select({ total: count() }).from(workItemsTable).where(eq(workItemsTable.status, "queued"));
  const [pendingProposals] = await db.select({ total: count() }).from(proposalsTable).where(eq(proposalsTable.status, "pending"));
  const [activeStrategies] = await db.select({ total: count() }).from(strategiesTable).where(eq(strategiesTable.lifecycleStage, "active"));
  const [tournamentsRun] = await db.select({ total: count() }).from(tournamentsTable);

  res.json({
    totalAgents: agents.total,
    activeAgents: activeAgents.total,
    activeSessions: activeSessions.total,
    messagesRouted: messagesRouted.total,
    threatsDetected: threatsDetected.total,
    threatsFired24h: threatsFired24h.total,
    pendingWorkItems: pendingWork.total,
    pendingProposals: pendingProposals.total,
    activeStrategies: activeStrategies.total,
    tournamentsRun: tournamentsRun.total,
  });
});

export default router;
