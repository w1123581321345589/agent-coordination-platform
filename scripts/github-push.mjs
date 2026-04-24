import { ReplitConnectors } from "@replit/connectors-sdk";
import { readFileSync } from "fs";
import { execSync } from "child_process";

const connectors = new ReplitConnectors();
const OWNER = "w1123581321345589";
const REPO = "agent-coordination-platform";
const ROOT = "/home/runner/workspace";

async function ghProxy(path, opts = {}) {
  const r = await connectors.proxy("github", path, {
    method: opts.method || "GET",
    ...(opts.body ? { body: JSON.stringify(opts.body), headers: { "Content-Type": "application/json" } } : {}),
  });
  return r.json();
}

// Step 1: Initialize repo with a README via Contents API (bypasses empty repo restriction)
console.log("Initializing repository...");
const readmeContent = Buffer.from(`# Agent Coordination Platform

Full-stack platform for coordinating multi-agent AI systems.

## Modules
- **A2A Protocol** — Agent-to-agent session management and message routing
- **A2A Security** — Threat detection, rule enforcement, and event resolution
- **Recovery Router** — Work item queue with automatic failover and redistribution
- **Cross-Model Router** — Dynamic role-to-provider routing with performance learning
- **Agent Proposal Engine** — Failure-pattern clustering and agent capability proposals
- **Context Router + Shapley** — Knowledge domain management and Shapley value attribution
- **Coordination Tournament** — Hierarchical/debate/parallel variant scoring
- **Meta-Learner** — Strategy lifecycle management with lint validation and learning curves

## Stack
- **Frontend**: React + Vite + shadcn/ui + recharts + wouter
- **Backend**: Express 5 + Drizzle ORM + PostgreSQL
- **API**: OpenAPI 3.1 spec with Orval codegen (React Query hooks + Zod schemas)
- **Monorepo**: pnpm workspaces
`).toString("base64");

const initResult = await ghProxy(`/repos/${OWNER}/${REPO}/contents/README.md`, {
  method: "PUT",
  body: { message: "chore: initialize repository", content: readmeContent }
});

if (!initResult.commit?.sha) {
  console.error("Init failed:", JSON.stringify(initResult).slice(0, 300));
  process.exit(1);
}
const initSha = initResult.commit.sha;
const initTreeSha = initResult.commit.tree?.sha || initResult.commit.tree;
console.log("Init commit SHA:", initSha);

// Step 2: Get all tracked files
const files = execSync("git ls-files", { cwd: ROOT }).toString().trim().split("\n").filter(Boolean);
const SKIP = ["scripts/", "dist/", ".env"];
const filtered = files.filter(f => !SKIP.some(s => f.startsWith(s)) && f !== "README.md");
console.log(`Uploading ${filtered.length} files...`);

// Step 3: Create blobs for all files
const treeItems = [];
let i = 0;
for (const file of filtered) {
  let content;
  try {
    content = readFileSync(`${ROOT}/${file}`);
  } catch {
    continue; // skip unreadable files
  }
  const blob = await ghProxy(`/repos/${OWNER}/${REPO}/git/blobs`, {
    method: "POST",
    body: { content: content.toString("base64"), encoding: "base64" }
  });
  if (!blob.sha) {
    console.warn(`Skipping ${file}: ${JSON.stringify(blob).slice(0, 100)}`);
    continue;
  }
  treeItems.push({ path: file, mode: "100644", type: "blob", sha: blob.sha });
  i++;
  if (i % 25 === 0) console.log(`  ${i}/${filtered.length} blobs created`);
}
console.log(`Created ${treeItems.length} blobs`);

// Step 4: Create tree on top of initial commit
const tree = await ghProxy(`/repos/${OWNER}/${REPO}/git/trees`, {
  method: "POST",
  body: { base_tree: initTreeSha, tree: treeItems }
});
if (!tree.sha) throw new Error(`Tree failed: ${JSON.stringify(tree).slice(0, 200)}`);
console.log("Tree SHA:", tree.sha);

// Step 5: Create commit with parent
const commit = await ghProxy(`/repos/${OWNER}/${REPO}/git/commits`, {
  method: "POST",
  body: {
    message: "feat: initial full-stack Agent Coordination Platform\n\nIncludes all 8 modules with React dashboard, Express API, PostgreSQL + Drizzle ORM, OpenAPI codegen.",
    tree: tree.sha,
    parents: [initSha],
  }
});
if (!commit.sha) throw new Error(`Commit failed: ${JSON.stringify(commit).slice(0, 200)}`);
console.log("Commit SHA:", commit.sha);

// Step 6: Update main branch ref
const ref = await ghProxy(`/repos/${OWNER}/${REPO}/git/refs/heads/main`, {
  method: "PATCH",
  body: { sha: commit.sha, force: true }
});
console.log("Ref updated:", ref.ref || JSON.stringify(ref).slice(0, 100));
console.log(`\nDone! https://github.com/${OWNER}/${REPO}`);
