// Regenerates the README screenshots (docs/screenshots/*.png) from a fresh lab.
// Prerequisite: the static UI is built (NEXT_OUTPUT=export npx next build).  Usage: node scripts/screenshots.mjs
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const backend = resolve(here, "..", "..", "backend");
const outDir = resolve(here, "..", "..", "docs", "screenshots");
const win = process.platform === "win32";
const venv = join(backend, ".venv", win ? "Scripts/python.exe" : "bin/python");
const python = process.env.PYTHON ?? (existsSync(venv) ? venv : win ? "python" : "python3");
const port = 47510;
const base = `http://127.0.0.1:${port}`;

const server = spawn(
  python,
  [join(backend, "soclab_server.py"), "--port", String(port), "--state-dir", mkdtempSync(join(tmpdir(), "soclab-shots-")), "--static-dir", resolve(here, "..", "out")],
  { cwd: backend, stdio: "ignore" },
);

const api = async (path, body) => {
  const res = await fetch(`${base}/api${path}`, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
};

try {
  for (let i = 0; i < 60; i++) {
    try {
      await api("/health");
      break;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  // A realistic shift: several attacks, one benign alert, one incident already closed.
  const runs = {};
  for (const [id, seed] of [["ssh-bruteforce-compromise", 3], ["windows-password-spray", 4], ["lsass-credential-dumping", 5], ["after-hours-maintenance", 6], ["powershell-download-cradle", 7]]) {
    runs[id] = (await api("/simulations/run", { scenario_id: id, seed })).run;
  }
  const closed = runs["windows-password-spray"].incident_ids[0];
  await fetch(`${base}/api/incidents/${closed}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: "closed", classification: "true_positive", resolution: "Sprayed account l.pereira reset, MFA enforced, source blocked." }),
  });
  const incident = runs["powershell-download-cradle"].incident_ids[0];

  mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5, colorScheme: "dark" });
  const shot = async (name, path, prepare) => {
    await page.goto(base + path);
    await page.waitForLoadState("networkidle");
    const target = prepare ? await prepare() : undefined;
    await page.waitForTimeout(400);
    // A prepare step may return a locator to capture just that element instead of the viewport.
    await (target ?? page).screenshot({ path: join(outDir, `${name}.png`) });
    console.log(`saved ${name}.png`);
  };

  await shot("dashboard", "/?");
  await shot("incident", `/incidents/view/?id=${incident}`);
  await shot("simulation-challenge", `/simulations/?scenario=lsass-credential-dumping&run=${runs["lsass-credential-dumping"].id}`, async () => {
    return page.locator("section", { has: page.getByText("Investigation challenge") });
  });
  await shot("query-language", "/events/?mode=query&query=" + encodeURIComponent("outcome:failure | stats count by source_ip, hostname | head 12"));
  await shot("mitre", "/mitre/");
  await shot("rule-sigma", "/rules/?rule=LAB-015", async () => {
    await page.getByRole("tab", { name: "Sigma rule" }).click();
  });
  await shot("report", `/reports/view/?id=${incident}`);
  await shot("regression", "/rules/?rule=LAB-002", async () => {
    await page.getByRole("spinbutton", { name: "Failed attempts" }).fill("15");
    await page.getByRole("button", { name: "Regression test" }).click();
    await page.getByText(/Failed: 1 attack scenario/).waitFor();
  });
  // Seed 2 queues both PIX scenarios (the fraud and the verified phone swap) next to an SSH attack and a maintenance window.
  await api("/shifts", { duration_minutes: 20, seed: 2 });
  await shot("shift", "/shift/", async () => {
    await page.getByRole("timer").waitFor();
    await page.getByRole("button", { name: /Account Takeover Followed by PIX Transfer/ }).last().click();
    await page.getByRole("radio", { name: /Malicious/ }).click();
    await page.getByLabel("Justification").fill("Hosting IP signed in from a never-seen device and swapped the phone before the PIX.");
  });
  await browser.close();
} finally {
  server.kill();
}
