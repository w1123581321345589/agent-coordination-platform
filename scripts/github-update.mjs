import { ReplitConnectors } from "@replit/connectors-sdk";
import { readFileSync, existsSync } from "fs";

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

// Get current HEAD
const branchInfo = await ghProxy(`/repos/${OWNER}/${REPO}/git/refs/heads/main`);
const currentSha = branchInfo.object?.sha;
if (!currentSha) throw new Error("Could not get HEAD: " + JSON.stringify(branchInfo));
console.log("Current HEAD:", currentSha);

// Get current commit to get tree SHA
const currentCommit = await ghProxy(`/repos/${OWNER}/${REPO}/git/commits/${currentSha}`);
const currentTreeSha = currentCommit.tree?.sha;
console.log("Current tree:", currentTreeSha);

// Files to update (new pages + updated files)
const filesToPush = [
  "artifacts/platform/src/App.tsx",
  "artifacts/platform/src/pages/threats.tsx",
  "artifacts/platform/src/pages/recovery.tsx",
  "artifacts/platform/src/pages/routing.tsx",
  "artifacts/platform/src/pages/proposals.tsx",
  "artifacts/platform/src/pages/context.tsx",
  "artifacts/platform/src/pages/tournaments.tsx",
  "artifacts/platform/src/pages/strategies.tsx",
  "artifacts/platform/src/pages/agents.tsx",
  "artifacts/platform/src/pages/sessions.tsx",
  "artifacts/platform/src/pages/dashboard.tsx",
  "artifacts/platform/src/components/layout.tsx",
  "artifacts/platform/src/index.css",
  "lib/db/src/schema/agents.ts",
  "lib/db/src/schema/sessions.ts",
  "lib/db/src/schema/threats.ts",
  "lib/db/src/schema/recovery.ts",
  "lib/db/src/schema/routing.ts",
  "lib/db/src/schema/proposals.ts",
  "lib/db/src/schema/context.ts",
  "lib/db/src/schema/tournaments.ts",
  "lib/db/src/schema/strategies.ts",
  "lib/db/src/schema/index.ts",
  "artifacts/api-server/src/routes/index.ts",
  "artifacts/api-server/src/routes/dashboard.ts",
  "artifacts/api-server/src/routes/agents.ts",
  "artifacts/api-server/src/routes/sessions.ts",
  "artifacts/api-server/src/routes/threats.ts",
  "artifacts/api-server/src/routes/recovery.ts",
  "artifacts/api-server/src/routes/routing.ts",
  "artifacts/api-server/src/routes/proposals.ts",
  "artifacts/api-server/src/routes/context.ts",
  "artifacts/api-server/src/routes/tournaments.ts",
  "artifacts/api-server/src/routes/strategies.ts",
  "lib/api-spec/openapi.yaml",
  "scripts/seed.mjs",
  "scripts/seed-threats.mjs",
];

// Create blobs for each file
const treeItems = [];
let i = 0;
console.log(`Pushing ${filesToPush.length} files...`);

for (const file of filesToPush) {
  const fullPath = `${ROOT}/${file}`;
  if (!existsSync(fullPath)) {
    console.warn(`  Skipping (not found): ${file}`);
    continue;
  }
  const content = readFileSync(fullPath);
  const blob = await ghProxy(`/repos/${OWNER}/${REPO}/git/blobs`, {
    method: "POST",
    body: { content: content.toString("base64"), encoding: "base64" }
  });
  if (!blob.sha) {
    console.warn(`  Failed blob for ${file}: ${JSON.stringify(blob).slice(0, 100)}`);
    continue;
  }
  treeItems.push({ path: file, mode: "100644", type: "blob", sha: blob.sha });
  i++;
  if (i % 10 === 0) console.log(`  ${i}/${filesToPush.length} blobs created`);
}
console.log(`Created ${treeItems.length} blobs`);

// Create tree (delta on top of existing tree)
const tree = await ghProxy(`/repos/${OWNER}/${REPO}/git/trees`, {
  method: "POST",
  body: { base_tree: currentTreeSha, tree: treeItems }
});
if (!tree.sha) throw new Error(`Tree failed: ${JSON.stringify(tree).slice(0, 200)}`);
console.log("New tree SHA:", tree.sha);

// Create commit
const commit = await ghProxy(`/repos/${OWNER}/${REPO}/git/commits`, {
  method: "POST",
  body: {
    message: "feat: add all 9 module pages, DB schemas, API routes, and seed data\n\nCompletes the full-stack implementation:\n- All 11 frontend pages (dashboard + 9 module pages)\n- Complete DB schema for all 8 modules\n- Full API route handlers wired to Express router\n- Seed data for all modules\n- OpenAPI 3.1 spec",
    tree: tree.sha,
    parents: [currentSha],
  }
});
if (!commit.sha) throw new Error(`Commit failed: ${JSON.stringify(commit).slice(0, 200)}`);
console.log("New commit SHA:", commit.sha);

// Update main branch
const ref = await ghProxy(`/repos/${OWNER}/${REPO}/git/refs/heads/main`, {
  method: "PATCH",
  body: { sha: commit.sha, force: false }
});
console.log("Ref updated:", ref.ref || JSON.stringify(ref).slice(0, 100));
console.log(`\nDone! https://github.com/${OWNER}/${REPO}`);
