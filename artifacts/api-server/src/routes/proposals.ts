import { Router, type IRouter } from "express";
import { eq, sql } from "drizzle-orm";
import { db, proposalsTable, failurePatternsTable } from "@workspace/db";
import {
  CreateProposalBody,
  ApproveProposalParams,
  RejectProposalParams,
  RollbackProposalParams,
  RecordFailurePatternBody,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/proposals", async (_req, res): Promise<void> => {
  const proposals = await db.select().from(proposalsTable).orderBy(proposalsTable.createdAt);
  res.json(proposals);
});

router.post("/proposals", async (req, res): Promise<void> => {
  const parsed = CreateProposalBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  const [proposal] = await db.insert(proposalsTable).values({ ...parsed.data, status: "pending", expiresAt }).returning();
  res.status(201).json(proposal);
});

router.post("/proposals/:id/approve", async (req, res): Promise<void> => {
  const params = ApproveProposalParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [proposal] = await db.update(proposalsTable).set({ status: "approved" }).where(eq(proposalsTable.id, params.data.id)).returning();
  if (!proposal) {
    res.status(404).json({ error: "Proposal not found" });
    return;
  }
  res.json(proposal);
});

router.post("/proposals/:id/reject", async (req, res): Promise<void> => {
  const params = RejectProposalParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [proposal] = await db.update(proposalsTable).set({ status: "rejected" }).where(eq(proposalsTable.id, params.data.id)).returning();
  if (!proposal) {
    res.status(404).json({ error: "Proposal not found" });
    return;
  }
  res.json(proposal);
});

router.post("/proposals/:id/rollback", async (req, res): Promise<void> => {
  const params = RollbackProposalParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [proposal] = await db.update(proposalsTable).set({ status: "rolled_back" }).where(eq(proposalsTable.id, params.data.id)).returning();
  if (!proposal) {
    res.status(404).json({ error: "Proposal not found" });
    return;
  }
  res.json(proposal);
});

router.get("/proposals/patterns", async (_req, res): Promise<void> => {
  const patterns = await db.select().from(failurePatternsTable).orderBy(failurePatternsTable.failureCount);
  res.json(patterns.map((p) => ({ ...p, proposalGenerated: p.proposalGenerated === 1 })));
});

router.post("/proposals/patterns", async (req, res): Promise<void> => {
  const parsed = RecordFailurePatternBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  // Upsert: increment failureCount if exists
  const existing = await db.select().from(failurePatternsTable)
    .where(eq(failurePatternsTable.taskType, parsed.data.taskType));
  const domainMatch = existing.find((p) => p.domain === parsed.data.domain);
  if (domainMatch) {
    const [updated] = await db.update(failurePatternsTable)
      .set({ failureCount: sql`${failurePatternsTable.failureCount} + 1`, lastFailedAt: new Date() })
      .where(eq(failurePatternsTable.id, domainMatch.id))
      .returning();
    res.status(201).json({ ...updated, proposalGenerated: updated.proposalGenerated === 1 });
  } else {
    const [pattern] = await db.insert(failurePatternsTable).values({
      ...parsed.data,
      failureCount: 1,
      lastFailedAt: new Date(),
      proposalGenerated: 0,
    }).returning();
    res.status(201).json({ ...pattern, proposalGenerated: false });
  }
});

export default router;
