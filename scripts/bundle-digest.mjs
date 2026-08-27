// A digest of exactly what wrangler bundles, and nothing else.
//
// README and test changes must not read as a stale deployment, or the check
// cries wolf until nobody reads it. `git ls-tree` prints mode, type, object id
// and path per entry, so its output describes the content of these paths and
// is stable across rebases, squashes and cherry-picks.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

export const BUNDLED_PATHS = ["src", "wrangler.jsonc", "package.json"];
export const DIGEST_PREFIX = "src";
export const DIGEST_PATTERN = new RegExp(`\\b${DIGEST_PREFIX}\\s+([0-9a-f]{12})\\b`);

const repoDir = fileURLToPath(new URL("..", import.meta.url));

function git(args) {
  return new Promise((resolve) => {
    execFile("git", args, { cwd: repoDir }, (error, stdout) => resolve({ ok: !error, out: stdout ?? "" }));
  });
}

// A dirty tree has no digest at all. The bytes being deployed are then in no
// commit, so a digest computed from HEAD would describe something else, and a
// confident answer built on the wrong baseline is worse than no answer.
export async function bundleDigest() {
  const dirty = await git(["status", "--porcelain", "--", ...BUNDLED_PATHS]);
  if (!dirty.ok) return { digest: null, reason: "git could not read the working tree" };
  if (dirty.out.trim()) return { digest: null, reason: "the working tree is dirty" };

  const listed = await git(["ls-tree", "-r", "HEAD", "--", ...BUNDLED_PATHS]);
  if (!listed.ok || !listed.out.trim()) return { digest: null, reason: "git could not list the bundled files" };

  return { digest: createHash("sha256").update(listed.out).digest("hex").slice(0, 12), reason: null };
}

// `wrangler deployments list` prints oldest first, so only the final block
// describes what is live. Splitting on the unindented Created: lines skips the
// indented per-version ones, which are not deployments.
export function newestDeployedDigest(output) {
  const blocks = String(output).split(/\nCreated:\s+/).slice(1);
  const newest = blocks[blocks.length - 1] ?? "";
  return DIGEST_PATTERN.exec(newest)?.[1] ?? null;
}
