// Starts the lab exactly like the desktop app does: the FastAPI backend serving the exported UI,
// with a fresh, throw-away state directory so every run starts from the seed dataset.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const backend = resolve(here, "..", "..", "backend");
const win = process.platform === "win32";
const venv = join(backend, ".venv", win ? "Scripts/python.exe" : "bin/python");
const python = process.env.PYTHON ?? (existsSync(venv) ? venv : win ? "python" : "python3");
const port = process.env.E2E_PORT ?? "47500";

const child = spawn(
  python,
  [join(backend, "soclab_server.py"), "--port", port, "--state-dir", mkdtempSync(join(tmpdir(), "soclab-e2e-")), "--static-dir", resolve(here, "..", "out")],
  { cwd: backend, stdio: "inherit" },
);
const stop = () => child.kill();
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
child.on("exit", (code) => process.exit(code ?? 0));
