import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const probe = fileURLToPath(new URL("./fixtures/sdk-url-probe.mjs", import.meta.url));

describe("SDK URL normalization resource behavior", () => {
  // Bound the child so the old regex cannot block the test runner. This is a
  // generous process deadline, not a microbenchmark or production SLA.
  it.each(["interior", "interior-with-tail", "trailing"])(
    "constructs with a long %s slash run within a bounded child process",
    mode => {
      const result = spawnSync(process.execPath, [probe, mode], {
        encoding: "utf8", timeout: 5_000, killSignal: "SIGKILL", maxBuffer: 16_384,
      });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({ constructed: true, mode });
    },
    10_000,
  );
});
