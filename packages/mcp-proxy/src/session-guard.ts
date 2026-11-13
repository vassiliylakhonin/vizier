import { realpath, lstat } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { type JsonValue } from "@agenda-intelligence/vizier-sdk";

const argumentRule = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("path"), argument: z.string().min(1), root: z.string().min(1) }),
  z.strictObject({ kind: z.literal("url"), argument: z.string().min(1), origins: z.array(z.string().url()).min(1) }),
]);
export const guardPolicySchema = z.strictObject({
  tools: z.record(z.string(), z.strictObject({
    arguments: z.array(argumentRule).default([]),
    label: z.enum(["source:private", "sink:external", "none"]).default("none"),
  })).default({}),
});
export type GuardPolicy = z.input<typeof guardPolicySchema>;
export interface GuardFailure { readonly code: string; readonly recovery: string }

// Decode once. Nested encoding is ambiguous across executors, so refuse it.
export function decodeArgument(value: string): string {
  const decoded = decodeURIComponent(value);
  if ([...decoded].some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) || /%[0-9a-f]{2}/iu.test(decoded)) throw new Error("AMBIGUOUS_ENCODING");
  return decoded;
}
export function canonicalOrigin(value: string): string {
  const raw = new URL(value);
  const url = new URL(decodeArgument(value));
  if ([raw, url].some(item => !["http:", "https:"].includes(item.protocol) || item.username || item.password) || raw.origin !== url.origin) throw new Error("INVALID_URL");
  return url.origin; // WHATWG URL handles host case, default port and IDNA/punycode.
}
function inside(root: string, path: string): boolean {
  const suffix = relative(root, path);
  return suffix !== ".." && !suffix.startsWith(`..${sep}`) && !isAbsolute(suffix);
}
async function resolvedPath(path: string): Promise<string> {
  try { return await realpath(path); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    // A new file is allowed only under an existing real parent. Dangling links
    // are not new files and must not be treated as safe destinations.
    try { await lstat(path); throw new Error("DANGLING_SYMLINK", { cause: error }); }
    catch (statError) { if ((statError as NodeJS.ErrnoException).code !== "ENOENT") throw statError; }
    return resolve(await realpath(dirname(path)), basename(path));
  }
}
export async function evaluateArguments(policy: GuardPolicy, tool: string, args: Record<string, JsonValue>): Promise<GuardFailure | null> {
  const config = guardPolicySchema.parse(policy).tools[tool];
  for (const rule of config?.arguments ?? []) {
    const value = args[rule.argument];
    if (typeof value !== "string") return { code: "ARGUMENT_REQUIRED", recovery: "Supply the configured string argument; do not remove or rename the policy field." };
    try { decodeArgument(value); }
    catch { return { code: "ARGUMENT_INVALID", recovery: "Use a single unambiguous encoding without control characters." }; }
    if (rule.kind === "url") {
      try { canonicalOrigin(value); }
      catch { return { code: "ARGUMENT_INVALID", recovery: "Use an absolute HTTP(S) URL without credentials." }; }
    }
    try {
      if (rule.kind === "url") {
        if (!rule.origins.map(canonicalOrigin).includes(canonicalOrigin(value))) return { code: "URL_ORIGIN_NOT_ALLOWED", recovery: "Use an operator-approved URL origin. Ask the owner before changing destinations." };
      } else {
        if (!isAbsolute(rule.root)) throw new Error("ABSOLUTE_ROOT_REQUIRED");
        const root = await realpath(rule.root);
        const decoded = decodeArgument(value);
        // Windows separators and drive-relative paths are ambiguous on a POSIX host.
        if (decoded.includes("\\") || /^[a-z]:/iu.test(decoded)) return { code: "ARGUMENT_INVALID", recovery: "Use a POSIX path without Windows separators or drive prefixes." };
        // Do not collapse link/.. before realpath: POSIX resolves the link
        // first, which can make a lexically in-root path escape the root.
        const candidates = [...new Set([value, decoded])].map(path => isAbsolute(path) ? path : `${root}/${path}`);
        if (candidates.some(candidate => !inside(root, candidate)) || (await Promise.all(candidates.map(async candidate => inside(root, await resolvedPath(candidate))))).some(safe => !safe)) return { code: "PATH_OUTSIDE_ROOT", recovery: "Choose a path inside the configured workspace. Do not retry with alternate encodings or symlinks." };
      }
    } catch {
      return { code: "PATH_STATE_UNAVAILABLE", recovery: "Use an unambiguous path/URL and an existing workspace parent. The operator must fix unavailable filesystem state." };
    }
  }
  return null;
}

/** One operator-owned session per proxy instance. No caller-supplied reset/id. */
export class SessionGuard {
  private privateSeen = false;
  readonly policy: z.output<typeof guardPolicySchema>;
  constructor(policy: GuardPolicy = {}) { this.policy = guardPolicySchema.parse(structuredClone(policy)); }
  async check(tool: string, args: Record<string, JsonValue>): Promise<GuardFailure | null> {
    const invalid = await evaluateArguments(this.policy, tool, args);
    if (invalid) return invalid;
    if (this.privateSeen && this.policy.tools[tool]?.label === "sink:external") return { code: "TAINT_PRIVATE_TO_EXTERNAL", recovery: "This session has accessed a labelled private source. Ask the owner to review disclosure outside this session; do not relabel tools or start a fresh session to bypass the block." };
    return null;
  }
  beforeForward(tool: string): void {
    // Mark before network I/O: a lost/error response is not proof no data was read.
    if (this.policy.tools[tool]?.label === "source:private") this.privateSeen = true;
  }
}
