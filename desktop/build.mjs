// Builds the desktop installer for the current OS:
//   1. static export of the Next.js UI      -> frontend/out
//   2. PyInstaller bundle of the backend    -> backend/dist/soclab-server
//   3. electron-builder installer           -> desktop/release
// Usage: node build.mjs [--dir] [--skip-web] [--skip-server]
// PYTHON=<path> selects the interpreter (defaults to backend/.venv, then python3/python).

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const frontend = join(root, "frontend");
const backend = join(root, "backend");
const args = new Set(process.argv.slice(2));
const win = process.platform === "win32";

const run = (cmd, cwd, env = {}) => {
  console.log(`\n> ${cmd}   (${cwd})`);
  execSync(cmd, { cwd, stdio: "inherit", env: { ...process.env, ...env } });
};

if (!args.has("--skip-web")) {
  if (!existsSync(join(frontend, "node_modules"))) run("npm ci --no-audit --no-fund", frontend);
  run("npx next build", frontend, { NEXT_OUTPUT: "export", NEXT_TELEMETRY_DISABLED: "1" });
}

if (!args.has("--skip-server")) {
  const venv = join(backend, ".venv", win ? "Scripts/python.exe" : "bin/python");
  const python = process.env.PYTHON ?? (existsSync(venv) ? venv : win ? "python" : "python3");
  run(`"${python}" -m pip install -q -r requirements.txt "pyinstaller>=6.10"`, backend);
  run(`"${python}" build_server.py`, backend);
}

const target = win ? "--win" : process.platform === "linux" ? "--linux" : "--mac";
run(`npx electron-builder ${target} ${args.has("--dir") ? "--dir" : ""} --publish never`, here);
console.log(`\nDone. Installers are in ${join(here, "release")}`);
