export const MAX_JSON_DEPTH = 64;
export const MAX_JSON_NODES = 50_000;

export class JsonComplexityError extends Error {
  constructor(readonly reason: "depth" | "nodes" | "cycle") {
    super(`JSON ${reason} limit exceeded`);
    this.name = "JsonComplexityError";
  }
}

interface PendingValue {
  readonly value: unknown;
  readonly depth: number;
}

export function assertJsonComplexity(
  value: unknown,
  options: {
    readonly maxDepth?: number;
    readonly maxNodes?: number;
  } = {},
): void {
  const maxDepth = options.maxDepth ?? MAX_JSON_DEPTH;
  const maxNodes = options.maxNodes ?? MAX_JSON_NODES;
  const pending: PendingValue[] = [{ value, depth: 0 }];
  const visited = new WeakSet<object>();
  let nodeCount = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) {
      break;
    }
    nodeCount += 1;
    if (nodeCount > maxNodes) {
      throw new JsonComplexityError("nodes");
    }
    if (current.depth > maxDepth) {
      throw new JsonComplexityError("depth");
    }

    if (typeof current.value !== "object" || current.value === null) {
      continue;
    }
    if (visited.has(current.value)) {
      throw new JsonComplexityError("cycle");
    }
    visited.add(current.value);

    const children = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value as Record<string, unknown>);
    for (const child of children) {
      pending.push({ value: child, depth: current.depth + 1 });
    }
  }
}
