export const MAX_JSON_DEPTH = 64;
export const MAX_JSON_NODES = 50_000;

export class JsonComplexityError extends Error {
  constructor(readonly reason: "depth" | "nodes" | "cycle") {
    super(`JSON ${reason} limit exceeded`);
    this.name = "JsonComplexityError";
  }
}

type PendingValue =
  | { readonly phase: "enter"; readonly value: unknown; readonly depth: number }
  | { readonly phase: "leave"; readonly value: object };

export function assertJsonComplexity(
  value: unknown,
  options: {
    readonly maxDepth?: number;
    readonly maxNodes?: number;
  } = {},
): void {
  const maxDepth = options.maxDepth ?? MAX_JSON_DEPTH;
  const maxNodes = options.maxNodes ?? MAX_JSON_NODES;
  const pending: PendingValue[] = [{ phase: "enter", value, depth: 0 }];
  const ancestors = new WeakSet<object>();
  let nodeCount = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) {
      break;
    }
    if (current.phase === "leave") {
      ancestors.delete(current.value);
      continue;
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
    if (ancestors.has(current.value)) {
      throw new JsonComplexityError("cycle");
    }
    ancestors.add(current.value);
    // JSON repeats acyclic aliases. Count each expanded occurrence; only a
    // reference to an active ancestor is a cycle. Leave markers cost no nodes.
    pending.push({ phase: "leave", value: current.value });

    const children = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value as Record<string, unknown>);
    for (const child of children) {
      pending.push({ phase: "enter", value: child, depth: current.depth + 1 });
    }
  }
}
