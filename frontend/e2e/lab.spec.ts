import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

// The tests share one lab instance and run in order: each step builds on the previous one,
// exactly like an analyst's session.
test.describe.configure({ mode: "serial" });

async function runScenario(page: Page, name: string) {
  await page.goto("/simulations/");
  await page.getByRole("button", { name: new RegExp(name, "i") }).first().click();
  await page.getByRole("button", { name: "Run scenario" }).click();
  await expect(page.getByText("all expected detections fired")).toBeVisible();
}

test("dashboard shows live KPIs in simulation mode", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Security Overview" })).toBeVisible();
  await expect(page.getByText("Simulation Mode", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("Events processed")).toBeVisible();
  await expect(page.getByRole("link", { name: /SSH Brute Force/ }).first()).toBeVisible();
});

test("simulation -> incident -> documented closure -> report", async ({ page }) => {
  await runScenario(page, "Malicious macro");
  await expect(page.getByText("Normalized events")).toBeVisible();

  await page.getByRole("link", { name: /Investigate INC-/ }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Suspicious PowerShell Execution");

  await page.getByRole("tab", { name: /Notes/ }).click();
  await page.getByLabel("New note").fill("Word spawned encoded PowerShell; payload host 203.0.113.80 blocked at the proxy.");
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText("payload host 203.0.113.80 blocked")).toBeVisible();

  // Closing without a written resolution is not possible.
  await page.getByRole("button", { name: "Close incident" }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("button", { name: "Close incident" })).toBeDisabled();
  await dialog.getByLabel("Resolution & justification").fill("Malicious macro confirmed. Host isolated, IOC blocked, password reset for j.silva.");
  await dialog.getByRole("button", { name: "Close incident" }).click();
  await expect(page.getByText("Closed", { exact: true }).or(page.getByText("closed", { exact: true })).first()).toBeVisible();

  await page.getByRole("link", { name: "Report", exact: true }).click();
  await expect(page.getByRole("heading", { name: /Incident Report - INC-/ })).toBeVisible();
  await expect(page.getByText("203.0.113.80").first()).toBeVisible();
  await expect(page.getByText("True positive (malicious)").first()).toBeVisible();
});

test("challenge mode scores the analyst's answers", async ({ page }) => {
  await runScenario(page, "Root login with stolen key");
  const challenge = page.locator("section", { has: page.getByText("Investigation challenge") });
  await challenge.getByRole("radio", { name: "publickey" }).check();
  await challenge.getByRole("radio", { name: "sudo", exact: true }).check();
  await challenge.getByRole("button", { name: /Show hint/ }).first().click();
  await expect(challenge.getByText(/Accepted publickey for root/)).toBeVisible();
  await challenge.getByRole("button", { name: "Submit answers" }).click();
  // Two choice questions right (25 + 25), two text questions left blank.
  await expect(challenge.getByText("50/100")).toBeVisible();
  await expect(challenge.getByText(/expected:/).first()).toBeVisible();
});

test("query language aggregates and drills down", async ({ page }) => {
  await page.goto("/events/");
  await page.getByRole("radio", { name: "Query language" }).click();
  await page.getByRole("textbox", { name: "Query", exact: true }).fill("outcome:failure host:bastion-01 | stats count by source_ip | head 5");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  const firstRow = page.locator("tbody tr").first();
  await expect(firstRow).toContainText("198.51.100.23");
  await firstRow.click();
  await expect(page.getByRole("textbox", { name: "Query", exact: true })).toHaveValue(/source_ip:"198\.51\.100\.23"/);
  await expect(page.getByText(/results? from/)).toBeVisible();

  await page.getByRole("textbox", { name: "Query", exact: true }).fill("nosuchfield:1");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText(/unknown field/)).toBeVisible();
});

test("import validates a malformed file line by line", async ({ page }) => {
  await page.goto("/import/");
  await page.locator('input[type="file"]').setInputFiles(path.join(__dirname, "..", "public", "samples", "malformed_sample.log"));
  await page.getByRole("button", { name: "Validate file" }).click();
  await expect(page.getByText("Parsing errors")).toBeVisible();
  await expect(page.getByText("line does not match a supported syslog header").first()).toBeVisible();
  await page.getByRole("button", { name: /Import \d+ events/ }).click();
  await expect(page.getByText("Import complete")).toBeVisible();
});
