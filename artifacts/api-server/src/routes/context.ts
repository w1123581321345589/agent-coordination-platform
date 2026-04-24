import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import { db, contextDomainsTable, shapleyValuesTable, agentsTable } from "@workspace/db";
import {
  CreateContextDomainBody,
  ComputeShapleyValueBody,
} from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/context/domains", async (_req, res): Promise<void> => {
  const domains = await db.select().from(contextDomainsTable).orderBy(contextDomainsTable.name);
  res.json(domains);
});

router.post("/context/domains", async (req, res): Promise<void> => {
  const parsed = CreateContextDomainBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [domain] = await db.insert(contextDomainsTable).values(parsed.data).returning();
  res.status(201).json(domain);
});

router.get("/context/shapley", async (_req, res): Promise<void> => {
  const values = await db.select().from(shapleyValuesTable).orderBy(shapleyValuesTable.createdAt);
  res.json(values);
});

router.post("/context/shapley", async (req, res): Promise<void> => {
  const parsed = ComputeShapleyValueBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const [value] = await db.insert(shapleyValuesTable).values(parsed.data).returning();
  res.status(201).json(value);
});

router.get("/context/diversity", async (_req, res): Promise<void> => {
  const agents = await db.select().from(agentsTable).where(eq(agentsTable.status, "active"));
  const shapley = await db.select().from(shapleyValuesTable);

  const totalAgents = agents.length;
  // Compute diversity as unique capability count / total capabilities
  const allCaps = agents.flatMap((a) => a.capabilities);
  const uniqueCaps = new Set(allCaps).size;
  const diversityScore = totalAgents > 0 ? uniqueCaps / Math.max(allCaps.length, 1) : 0;
  const redundancyScore = 1 - diversityScore;

  // Domains where many agents share all the same capabilities (collapsed)
  const domainMap: Record<string, string[][]> = {};
  agents.forEach((a) => {
    const role = a.role;
    domainMap[role] = domainMap[role] || [];
    domainMap[role].push(a.capabilities);
  });
  const collapsedDomains = Object.entries(domainMap)
    .filter(([, capSets]) => {
      if (capSets.length < 2) return false;
      const first = JSON.stringify(capSets[0].sort());
      return capSets.every((s) => JSON.stringify(s.sort()) === first);
    })
    .map(([domain]) => domain);

  // Top contributors by avg Shapley value
  const agentShapleyMap: Record<number, number[]> = {};
  shapley.forEach((s) => {
    agentShapleyMap[s.agentId] = agentShapleyMap[s.agentId] || [];
    agentShapleyMap[s.agentId].push(s.shapleyValue);
  });
  const topContributors = agents
    .map((a) => {
      const vals = agentShapleyMap[a.id] || [];
      const avgShapley = vals.length > 0 ? vals.reduce((s, v) => s + v, 0) / vals.length : 0;
      return { agentId: a.id, agentName: a.name, avgShapley };
    })
    .sort((a, b) => b.avgShapley - a.avgShapley)
    .slice(0, 5);

  res.json({ totalAgents, diversityScore, redundancyScore, collapsedDomains, topContributors });
});

export default router;
