import { mkdir, access, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const require = createRequire(import.meta.url);
const desktop = fileURLToPath(new URL("../desktop/", import.meta.url));
const { SCHEME, linuxDesktopEntry } = require("../desktop/protocol.cjs");

try {
  if (process.platform !== "linux") {
    throw new Error("On Windows, start Electron once to register the link. On macOS, a packaged app with a registered URL scheme is required; use npm run start:electron for this source checkout.");
  }
  await access(join(desktop, "node_modules/electron/package.json"));
  const executable = require(join(desktop, "node_modules/electron"));
  await access(executable);
  const dataHome = process.env.XDG_DATA_HOME || join(homedir(), ".local/share");
  const applications = join(dataHome, "applications");
  await mkdir(applications, { recursive: true });
  const name = "sentinel-scan.desktop";
  await writeFile(join(applications, name), linuxDesktopEntry(executable, desktop), { mode: 0o644 });
  execFileSync("xdg-mime", ["default", name, `x-scheme-handler/${SCHEME}`], { stdio: "inherit" });
  const registered = execFileSync("xdg-mime", ["query", "default", `x-scheme-handler/${SCHEME}`], { encoding: "utf8" }).trim();
  if (registered !== name) throw new Error("The desktop link could not be registered");
  console.log("Desktop link registered. The web app’s Launch desktop app button is ready.");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
