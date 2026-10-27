import process from "node:process";

import { Vizier } from "../../packages/sdk/dist/index.js";

const mode = process.argv[2];
const slashes = "/".repeat(500_000);
let baseUrl;
if (mode === "interior") baseUrl = "https://vizier.example/" + slashes + "x";
else if (mode === "interior-with-tail") baseUrl = "https://vizier.example/" + slashes + "x///";
else if (mode === "trailing") baseUrl = "https://vizier.example" + slashes;
else throw new TypeError("Unknown URL probe mode");

new Vizier({ baseUrl });
process.stdout.write(JSON.stringify({ constructed: true, mode, inputLength: baseUrl.length }));
