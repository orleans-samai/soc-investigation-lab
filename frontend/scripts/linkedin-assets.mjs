// Builds the LinkedIn demo images (marketing/linkedin/*.png + carousel PDF) from a fresh lab.
// 1. captures real UI states of each differentiator into marketing/linkedin/raw/
// 2. renders marketing/linkedin/slides.html (1080x1350 slides) to PNG and to a PDF carousel.
// Prerequisite: the static UI is built (NEXT_OUTPUT=export npx next build).  Usage: node scripts/linkedin-assets.mjs [--skip-capture]
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { chromium } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..");
const backend = join(root, "backend");
const outDir = join(root, "marketing", "linkedin");
const rawDir = join(outDir, "raw");
const win = process.platform === "win32";
const venv = join(backend, ".venv", win ? "Scripts/python.exe" : "bin/python");
const python = process.env.PYTHON ?? (existsSync(venv) ? venv : win ? "python" : "python3");
const port = 47520;
const base = `http://127.0.0.1:${port}`;

async function api(path, body, method = body ? "POST" : "GET") {
  const res = await fetch(`${base}/api${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
  return res.status === 204 ? null : res.json();
}

async function capture(browser) {
  const server = spawn(
    python,
    [join(backend, "soclab_server.py"), "--port", String(port), "--state-dir", mkdtempSync(join(tmpdir(), "soclab-li-")), "--static-dir", resolve(here, "..", "out")],
    { cwd: backend, stdio: "ignore" },
  );
  try {
    for (let i = 0; i < 60; i++) {
      try {
        await api("/health");
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    // Some history so the overview looks like a working lab.
    for (const [id, seed] of [["ssh-bruteforce-compromise", 3], ["windows-password-spray", 4], ["lsass-credential-dumping", 5], ["powershell-download-cradle", 7]]) {
      await api("/simulations/run", { scenario_id: id, seed });
    }
    const pix = (await api("/simulations/run", { scenario_id: "pix-account-takeover", seed: 4 })).run;
    await api(`/incidents/${pix.incident_ids[0]}`, { personal_data: true }, "PATCH");

    mkdirSync(rawDir, { recursive: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2, colorScheme: "dark" });
    const go = async (path, height = 1000, width = 1440) => {
      await page.setViewportSize({ width, height });
      await page.goto(base + path);
      await page.waitForLoadState("networkidle");
    };
    const save = async (name, target) => {
      await page.waitForTimeout(500);
      await target.screenshot({ path: join(rawDir, `${name}.png`) });
      console.log(`captured ${name}`);
    };
    // A sheet's body only (no title bar, no empty space below the content).
    const sheetBody = () => page.getByRole("dialog").locator(".overflow-y-auto > div").first();
    const mainClip = async (name, height) => {
      await page.waitForTimeout(500);
      const box = await page.locator("main").boundingBox();
      await page.screenshot({ path: join(rawDir, `${name}.png`), clip: { x: box.x, y: box.y, width: box.width, height: Math.min(height, box.height) } });
      console.log(`captured ${name}`);
    };

    // Cover: the overview with its signal chain.
    await go("/?", 1000);
    await mainClip("overview", 820);

    // 1. Regression test that fails a tuning change.
    await go("/rules/?rule=LAB-002", 1750);
    await page.getByRole("spinbutton", { name: "Failed attempts" }).fill("15");
    await page.getByRole("button", { name: "Regression test" }).click();
    await page.getByText(/Failed: 1 attack scenario/).waitFor();
    await save("regression", sheetBody());

    // 2. Shift: the live queue, then the debrief with a missed attack.
    const shift = await api("/shifts", { duration_minutes: 20, seed: 2 });
    // Below the xl breakpoint the queue and the triage panel stack, which suits a portrait slide.
    await go("/shift/", 1900, 1180);
    await page.getByRole("timer").waitFor();
    await page.getByRole("button", { name: /Account Takeover Followed by PIX Transfer/ }).last().click();
    await page.getByRole("radio", { name: /Malicious/ }).click();
    await page.getByLabel("Justification").fill("cli.bruno.lima: never-seen device from a hosting IP, phone swapped, then 2 PIX to a new payee.");
    await mainClip("shift-live", 1750);

    const notes = {
      malicious: (a) => `Confirmed with the timeline of ${a.username ?? a.hostname}; escalated to incident response.`,
      benign: (a) => `${a.username ?? a.hostname}: authorised activity, verified with the owner and the change record.`,
      false_positive: (a) => `${a.username ?? a.hostname}: looks like noise, closing.`,
    };
    const verdictFor = (a) => {
      if (a.rule_id === "LAB-014") return "false_positive"; // deliberate mistake: a real privilege escalation closed as noise
      if (a.rule_id === "LAB-005") return "false_positive"; // authorised change, labelled with the wrong non-malicious verdict
      if (a.rule_id === "LAB-018") return /diego|elisa|fabio/.test(a.username ?? "") ? "benign" : "malicious";
      return "malicious";
    };
    for (const item of shift.queue) {
      const verdict = verdictFor(item.alert);
      await api(`/shifts/${shift.id}/alerts/${item.alert.id}`, { verdict, note: notes[verdict](item.alert) });
    }
    await go(`/shift/?id=${shift.id}`, 1000);
    await page.getByText("Shift score").waitFor();
    // Only the debrief table: the score figures are restated, larger, on the slide itself.
    await save("shift-debrief", page.getByRole("table").locator("../.."));

    // 3. Sigma rule written in the lab, validated on real events.
    await go("/rules/", 1350);
    await page.getByRole("button", { name: "New Sigma rule" }).click();
    await page.getByRole("button", { name: "Validate & dry-run" }).click();
    await page.getByText(/Matches \d+ stored event/).waitFor();
    await save("sigma", sheetBody());

    // 4. PIX account takeover alert and the LGPD section of its report.
    const detail = await api(`/simulations/runs/${pix.id}`);
    const alert = detail.alerts.find((a) => a.rule_id === "LAB-018");
    await go(`/alerts/view/?id=${alert.id}`, 1600, 1180);
    await mainClip("pix-alert", 1200);
    await go(`/reports/view/?id=${pix.incident_ids[0]}`, 1000);
    const lgpd = page.locator("section", { has: page.getByRole("heading", { name: /LGPD notification/ }) });
    await lgpd.scrollIntoViewIfNeeded();
    await save("lgpd", lgpd);

    // 5. Scenario built from a Log Explorer query over an imported auth.log, anonymized.
    const form = new FormData();
    form.append("file", new Blob([readFileSync(join(root, "samples", "linux_auth_sample.log"))]), "linux_auth_sample.log");
    form.append("year", "2026");
    form.append("dry_run", "false");
    const imported = await fetch(`${base}/api/imports`, { method: "POST", body: form });
    if (!imported.ok) throw new Error(`import failed: ${await imported.text()}`);
    await go("/events/?mode=query&query=" + encodeURIComponent("host:web-01 source_ip:198.51.100.200"), 1700);
    await page.getByRole("button", { name: "Save as scenario" }).click();
    const sheet = page.getByRole("dialog");
    await sheet.getByLabel("Name").fill("SSH brute force on web-01 (real log replay)");
    await sheet.getByLabel("What happened (shown to the trainee)").fill("auth.log from the web server, imported and anonymized for training.");
    await sheet.getByRole("button", { name: "Preview" }).click();
    await sheet.getByText("First event as stored in the scenario").or(sheet.getByRole("alert")).waitFor();
    if (await sheet.getByRole("alert").isVisible()) throw new Error(`scenario preview failed: ${await sheet.getByRole("alert").textContent()}`);
    await save("scenario-builder", sheetBody());
    await page.close();
  } finally {
    server.kill();
  }
}

async function render(browser) {
  const page = await browser.newPage({ viewport: { width: 1080, height: 1350 }, deviceScaleFactor: 2 });
  await page.goto(pathToFileURL(join(outDir, "slides.html")).href);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(300);
  const slides = page.locator(".slide");
  const count = await slides.count();
  for (let i = 0; i < count; i++) {
    const name = await slides.nth(i).getAttribute("data-name");
    await slides.nth(i).screenshot({ path: join(outDir, `${String(i + 1).padStart(2, "0")}-${name}.png`) });
    console.log(`rendered ${name}`);
  }
  await page.emulateMedia({ media: "print" });
  await page.pdf({ path: join(outDir, "soc-investigation-lab-carousel.pdf"), width: "1080px", height: "1350px", printBackground: true });
  console.log("rendered carousel PDF");
  await page.close();
}

const browser = await chromium.launch();
try {
  if (!process.argv.includes("--skip-capture")) await capture(browser);
  await render(browser);
} finally {
  await browser.close();
}
