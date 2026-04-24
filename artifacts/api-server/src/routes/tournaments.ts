import { Router, type IRouter } from "express";
import { eq, desc } from "drizzle-orm";
import { db, tournamentsTable, tournamentVariantsTable } from "@workspace/db";
import {
  CreateTournamentBody,
  GetTournamentParams,
  ScoreTournamentVariantParams,
  ScoreTournamentVariantBody,
} from "@workspace/api-zod";

const router: IRouter = Router();

async function getTournamentWithVariants(id: number) {
  const [tournament] = await db.select().from(tournamentsTable).where(eq(tournamentsTable.id, id));
  if (!tournament) return null;
  const variants = await db.select().from(tournamentVariantsTable).where(eq(tournamentVariantsTable.tournamentId, id));
  return {
    ...tournament,
    variants: variants.map((v) => ({ ...v, winner: v.winner === 1 })),
  };
}

router.get("/tournaments", async (_req, res): Promise<void> => {
  const tournaments = await db.select().from(tournamentsTable).orderBy(desc(tournamentsTable.createdAt));
  const result = await Promise.all(tournaments.map((t) => getTournamentWithVariants(t.id)));
  res.json(result.filter(Boolean));
});

router.post("/tournaments", async (req, res): Promise<void> => {
  const parsed = CreateTournamentBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [tournament] = await db.insert(tournamentsTable).values({ ...parsed.data, status: "running" }).returning();
  // Auto-generate 3 variants
  await db.insert(tournamentVariantsTable).values([
    { tournamentId: tournament.id, pattern: "hierarchical", winner: 0 },
    { tournamentId: tournament.id, pattern: "debate", winner: 0 },
    { tournamentId: tournament.id, pattern: "parallel", winner: 0 },
  ]);
  const result = await getTournamentWithVariants(tournament.id);
  res.status(201).json(result);
});

router.get("/tournaments/:id", async (req, res): Promise<void> => {
  const params = GetTournamentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const result = await getTournamentWithVariants(params.data.id);
  if (!result) {
    res.status(404).json({ error: "Tournament not found" });
    return;
  }
  res.json(result);
});

router.post("/tournaments/:id/score", async (req, res): Promise<void> => {
  const params = ScoreTournamentVariantParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const parsed = ScoreTournamentVariantBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const compositeScore = parsed.data.qualityScore * 0.6 + parsed.data.efficiencyScore * 0.2 + parsed.data.costScore * 0.2;
  await db.update(tournamentVariantsTable)
    .set({ ...parsed.data, compositeScore })
    .where(eq(tournamentVariantsTable.id, parsed.data.variantId));

  // Check if all variants scored — find winner
  const variants = await db.select().from(tournamentVariantsTable).where(eq(tournamentVariantsTable.tournamentId, params.data.id));
  const allScored = variants.every((v) => v.compositeScore != null);
  if (allScored) {
    const winner = variants.reduce((best, v) => (v.compositeScore! > (best.compositeScore ?? -1) ? v : best), variants[0]);
    await db.update(tournamentVariantsTable).set({ winner: 1 }).where(eq(tournamentVariantsTable.id, winner.id));
    await db.update(tournamentsTable).set({ status: "completed", winnerId: winner.id }).where(eq(tournamentsTable.id, params.data.id));
  } else {
    await db.update(tournamentsTable).set({ status: "scored" }).where(eq(tournamentsTable.id, params.data.id));
  }

  const result = await getTournamentWithVariants(params.data.id);
  res.json(result);
});

router.get("/tournaments/patterns/winners", async (_req, res): Promise<void> => {
  const tournaments = await db.select().from(tournamentsTable).where(eq(tournamentsTable.status, "completed"));
  const variants = await db.select().from(tournamentVariantsTable).where(eq(tournamentVariantsTable.winner, 1));

  const patternMap: Record<string, { winCount: number; totalComposite: number }> = {};
  for (const t of tournaments) {
    const winnerVariant = variants.find((v) => v.tournamentId === t.id);
    if (!winnerVariant) continue;
    const key = `${t.domain}::${t.taskType}::${winnerVariant.pattern}`;
    patternMap[key] = patternMap[key] || { winCount: 0, totalComposite: 0 };
    patternMap[key].winCount++;
    patternMap[key].totalComposite += winnerVariant.compositeScore ?? 0;
  }

  const result = Object.entries(patternMap).map(([key, val]) => {
    const [domain, taskType, pattern] = key.split("::");
    return { domain, taskType, pattern, winCount: val.winCount, avgComposite: val.totalComposite / val.winCount };
  });
  res.json(result);
});

export default router;
