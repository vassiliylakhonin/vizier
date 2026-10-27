import { readFileSync } from "node:fs";

// Fixture values travel as JSON data; the preload module is always fixed code.
const { body, status } = JSON.parse(readFileSync(0, "utf8"));
globalThis.fetch = async () => new globalThis.Response(JSON.stringify(body), { status });
