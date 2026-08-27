// Deploys the Worker and records what was deployed.
//
// Why this exists: on 2026-08-26 a feature branch shipped from a checkout that
// predated a merge to main, and main sat an entire day ahead of production —
// /openapi.json and /.well-known/ai-catalog.json answered 404 while both were
// on main. Nothing noticed, because nothing here compared the two. It surfaced
// by accident during an unrelated merge.
//
// A date cannot answer the question: a squash or a rebase writes a new commit
// with new timestamps and identical content. So the deploy stamps a digest of
// the bundled files into the deployment message, and check-deployed.mjs reads
// it back. This mirrors deploy-all.js in agenda-intelligence-md, deliberately:
// two fleets that answer "is production running this code?" two different ways
// is one way too many.
//
//   npm run deploy

import { spawn } from "node:child_process";
import { bundleDigest, DIGEST_PREFIX } from "./bundle-digest.mjs";

function run(command, args) {
  return new Promise((resolve) => {
    spawn(command, args, { stdio: "inherit", shell: false }).on("close", (code) => resolve(code ?? 1));
  });
}

const { digest, reason } = await bundleDigest();
if (!digest) console.warn(`Deploying without a content stamp: ${reason}.`);

const args = ["--yes", "wrangler", "deploy"];
if (digest) args.push("--message", `${DIGEST_PREFIX} ${digest}`);

const code = await run("npx", args);
if (code !== 0) process.exit(code);
if (digest) console.log(`\nstamped ${DIGEST_PREFIX} ${digest}`);
