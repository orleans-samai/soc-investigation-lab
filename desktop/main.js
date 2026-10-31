// SOC Investigation Lab - desktop shell.
// Starts the bundled backend (which also serves the exported UI) on 127.0.0.1 and shows it in a native window.

const { app, BrowserWindow, Menu, dialog, shell } = require("electron");
const { spawn, execFile } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const PREFERRED_PORT = 47321;
const STARTUP_TIMEOUT_MS = 60_000;

let mainWindow = null;
let server = null;
let serverUrl = null;
let quitting = false;

const userData = app.getPath("userData");
const stateDir = path.join(userData, "state");
const logDir = path.join(userData, "logs");
fs.mkdirSync(logDir, { recursive: true });
const logFile = path.join(logDir, "server.log");

function serverCommand() {
  const exe = process.platform === "win32" ? "soclab-server.exe" : "soclab-server";
  if (app.isPackaged) {
    return {
      command: path.join(process.resourcesPath, "server", exe),
      args: [],
      cwd: path.join(process.resourcesPath, "server"),
      staticDir: path.join(process.resourcesPath, "web"),
    };
  }
  // Development: run the backend from source with the project's virtualenv.
  const backend = path.resolve(__dirname, "..", "backend");
  const venvPython = process.platform === "win32" ? path.join(backend, ".venv", "Scripts", "python.exe") : path.join(backend, ".venv", "bin", "python");
  return {
    command: process.env.SOCLAB_PYTHON || (fs.existsSync(venvPython) ? venvPython : "python3"),
    args: [path.join(backend, "soclab_server.py")],
    cwd: backend,
    staticDir: path.resolve(__dirname, "..", "frontend", "out"),
  };
}

function startServer() {
  return new Promise((resolve, reject) => {
    const { command, args, cwd, staticDir } = serverCommand();
    if (!fs.existsSync(path.join(staticDir, "index.html"))) {
      reject(new Error(`User interface not found in ${staticDir}. Build it with: npm run dist (or NEXT_OUTPUT=export next build).`));
      return;
    }
    const log = fs.createWriteStream(logFile, { flags: "w" });
    server = spawn(command, [...args, "--port", String(PREFERRED_PORT), "--state-dir", stateDir, "--static-dir", staticDir], {
      cwd,
      windowsHide: true,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
    });

    const timer = setTimeout(() => reject(new Error("The lab server did not start within 60 seconds.")), STARTUP_TIMEOUT_MS);
    let buffer = "";
    server.stdout.on("data", (chunk) => {
      log.write(chunk);
      buffer += chunk.toString();
      const match = buffer.match(/SOCLAB_LISTENING (\S+)/);
      if (match && !serverUrl) {
        serverUrl = match[1];
        waitForHealth(serverUrl).then(
          () => (clearTimeout(timer), resolve(serverUrl)),
          (err) => (clearTimeout(timer), reject(err)),
        );
      }
    });
    server.stderr.on("data", (chunk) => log.write(chunk));
    server.on("error", (err) => (clearTimeout(timer), reject(err)));
    server.on("exit", (code) => {
      log.end();
      server = null;
      if (!quitting) {
        clearTimeout(timer);
        const message = `The lab server stopped unexpectedly (exit code ${code}).\n\nLog: ${logFile}`;
        if (mainWindow) dialog.showErrorBox("SOC Investigation Lab", message);
        reject(new Error(message));
        app.quit();
      }
    });
  });
}

function waitForHealth(baseUrl) {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      http
        .get(new URL("api/health", baseUrl), (res) => {
          res.resume();
          if (res.statusCode === 200) return resolve();
          retry();
        })
        .on("error", retry);
    };
    const retry = () => (Date.now() > deadline ? reject(new Error("Health check timed out")) : setTimeout(attempt, 250));
    attempt();
  });
}

function stopServer() {
  if (!server) return;
  const pid = server.pid;
  if (process.platform === "win32") execFile("taskkill", ["/pid", String(pid), "/T", "/F"], () => undefined);
  else server.kill("SIGTERM");
}

function isAppUrl(url) {
  return serverUrl && url.startsWith(serverUrl);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 680,
    backgroundColor: "#090b0f",
    title: "SOC Investigation Lab",
    icon: path.join(__dirname, "build", "icon.png"),
    show: false,
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false },
  });
  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.loadFile(path.join(__dirname, "loading.html"));

  // Links to other sites (MITRE ATT&CK pages) open in the user's browser, never inside the app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url) && !isAppUrl(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (!isAppUrl(url) && !url.startsWith("file:")) {
      event.preventDefault();
      if (/^https?:/.test(url)) shell.openExternal(url);
    }
  });
  mainWindow.on("closed", () => (mainWindow = null));
}

function buildMenu() {
  const template = [
    {
      label: "File",
      submenu: [
        { label: "Open data folder", click: () => shell.openPath(userData) },
        { label: "Open server log", click: () => shell.openPath(logFile) },
        { type: "separator" },
        { role: "quit" },
      ],
    },
    {
      label: "View",
      submenu: [{ role: "reload" }, { type: "separator" }, { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { type: "separator" }, { role: "togglefullscreen" }],
    },
    {
      label: "Help",
      submenu: [
        { label: "API documentation", click: () => serverUrl && shell.openExternal(new URL("docs", serverUrl).toString()) },
        { label: "Developer tools", accelerator: "CmdOrCtrl+Shift+I", click: () => mainWindow?.webContents.toggleDevTools() },
        { type: "separator" },
        {
          label: "About",
          click: () =>
            dialog.showMessageBox({
              type: "info",
              title: "SOC Investigation Lab",
              message: `SOC Investigation Lab ${app.getVersion()}`,
              detail: `Security Operations & Incident Investigation Simulator.\nAll data is synthetic (Simulation Mode).\n\nData folder: ${userData}`,
            }),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    buildMenu();
    createWindow();
    try {
      const url = await startServer();
      mainWindow?.loadURL(url);
    } catch (err) {
      dialog.showErrorBox("SOC Investigation Lab could not start", `${err.message}\n\nLog: ${logFile}`);
      quitting = true;
      stopServer();
      app.quit();
    }
  });

  app.on("before-quit", () => {
    quitting = true;
    stopServer();
  });
  app.on("window-all-closed", () => app.quit());
}
