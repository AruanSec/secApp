import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { access } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { frontendUrl } = require("../desktop/config.cjs");
const desktop = fileURLToPath(new URL("../desktop/", import.meta.url));

async function run(command, args, options = {}) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", ...options });
    child.on("error", reject);
    child.on("exit", (code, signal) => code === 0 ? resolve() : reject(
      new Error(`${command} exited ${signal ? `with ${signal}` : `with code ${code}`}`)));
  });
}

async function launch() {
  let choice = process.argv[2];
  if (!choice) {
    if (!process.stdin.isTTY) throw new Error("Choose a frontend: npm run start:web or npm run start:electron");
    const prompt = createInterface({ input: process.stdin, output: process.stdout });
    try {
      const answer = (await prompt.question("Choose frontend: [1] Web browser  [2] Electron app (default 1): ")).trim().toLowerCase();
      if (["", "1", "web"].includes(answer)) choice = "--web";
      else if (["2", "electron"].includes(answer)) choice = "--electron";
      else throw new Error("Choose 1 (web) or 2 (Electron).");
    } finally { prompt.close(); }
  }
  if (!["--web", "--electron"].includes(choice)) throw new Error("Use --web or --electron.");
  const origin = frontendUrl(process.env.SENTINEL_FRONTEND_URL);
  try {
    const response = await fetch(origin, { method: "HEAD", signal: AbortSignal.timeout(5000), redirect: "error" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  } catch {
    throw new Error(`Frontend unavailable at ${origin}. Start it with: docker compose up -d --wait`);
  }
  if (choice === "--web") {
    const [command, args] = process.platform === "darwin" ? ["open", [origin]]
      : process.platform === "win32" ? ["rundll32.exe", ["url.dll,FileProtocolHandler", origin]]
      : ["xdg-open", [origin]];
    console.log(`Opening web frontend: ${origin}`);
    await run(command, args);
  } else {
    try { await access(`${desktop}node_modules/electron/package.json`); }
    catch { throw new Error("Install the desktop frontend first: npm ci --prefix desktop"); }
    // Launch the binary directly so this also works without a platform-specific shell.
    const electronPath = require(`${desktop}node_modules/electron`);
    console.log(`Opening Electron frontend: ${origin}`);
    const env = { ...process.env };
    delete env.ELECTRON_RUN_AS_NODE;
    await run(electronPath, [desktop], { cwd: desktop, env });
  }
}
launch().catch((error) => { console.error(error.message); process.exitCode = 1; });
