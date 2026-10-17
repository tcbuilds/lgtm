#!/usr/bin/env node
// Measure generated-extension execution against the original Jev template sources.
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const directory = path.join(root, "target", "jev-coverage");
fs.mkdirSync(directory, { recursive: true });
const args = ["exec", "--yes", "--package=c8@12.0.0", "--", "c8", "--all", "--src", "templates/pi", "--include", "**/jev*.js", "--temp-directory", path.join(directory, "v8"), "--reports-dir", directory, "--reporter=lcov", "--reporter=text", "--check-coverage", "--lines=80", "--branches=80", "cargo", "test", "--locked", "--test", "jev_pi"];
const child = spawn(process.platform === "win32" ? "npm.cmd" : "npm", args, {
  cwd: root, stdio: "inherit", detached: process.platform !== "win32",
  env: { ...process.env, npm_config_fetch_timeout: "60000", npm_config_fetch_retries: "1" },
});
let timedOut = false;
function stop() {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === "win32") child.kill("SIGKILL");
    else process.kill(-child.pid, "SIGKILL");
  } catch (error) {
    // A child can exit between the observation above and the kill request.
    if (error.code !== "ESRCH") { console.error("Could not terminate Jev coverage process group"); process.exitCode = 1; }
  }
}
const timer = setTimeout(() => { timedOut = true; stop(); }, 600_000);
process.once("SIGINT", stop);
process.once("SIGTERM", stop);
child.once("error", () => { clearTimeout(timer); console.error("Could not start npm for Jev coverage"); process.exitCode = 1; });
child.once("close", (code) => { clearTimeout(timer); process.exitCode = timedOut ? 124 : (code ?? 1); });
