// Answers one question: is production running this code?
//
//   npm run check:deployed
//
// Exits 1 when the live Worker carries a different digest from the current
// bundle. A deployment made before the stamp existed reports as unstamped and
// exits 0 — unknown is not drift, and a check that fails until the next deploy
// is a check nobody reads.

import { execFile } from "node:child_process";
import { bundleDigest, DIGEST_PREFIX, newestDeployedDigest } from "./bundle-digest.mjs";

function wrangler(args) {
  return new Promise((resolve) => {
    execFile("npx", args, { maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) =>
      resolve({ ok: !error, out: `${stdout ?? ""}${stderr ?? ""}` })
    );
  });
}

const { digest, reason } = await bundleDigest();
if (!digest) {
  console.log(`check:deployed skipped — ${reason}.`);
  process.exit(0);
}

const listed = await wrangler(["--yes", "wrangler", "deployments", "list"]);
if (!listed.ok) {
  console.error("Could not read the deployment list.");
  process.exit(1);
}

const live = newestDeployedDigest(listed.out);
console.log(`bundled  ${DIGEST_PREFIX} ${digest}`);

if (live === null) {
  console.log("live     unstamped — deployed before the content stamp existed, so it was not checked.");
  console.log("         The next `npm run deploy` stamps it.");
  process.exit(0);
}
if (live === digest) {
  console.log("live     current");
  process.exit(0);
}
console.error(`live     ${DIGEST_PREFIX} ${live}  — production is running different code.`);
console.error("Run `npm run deploy`.");
process.exit(1);
