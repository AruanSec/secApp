const { app, BrowserWindow, dialog, Menu } = require("electron");
const { SCHEME } = require("./protocol.cjs");
const { frontendUrl, sameOrigin } = require("./config.cjs");

let origin;
let window;
app.setName("Sentinel Scan");

async function loadFrontend() {
  try {
    await window.loadURL(origin);
  } catch {
    if (!window || window.isDestroyed()) return;
    window.show();
    const { response } = await dialog.showMessageBox(window, {
      type: "error",
      title: "Sentinel Scan is unavailable",
      message: `Could not connect to ${origin}`,
      detail: "Start the app services from the project folder:\ndocker compose up -d --wait\n\nThen choose Retry. Electron uses the same backend as the web frontend.",
      buttons: ["Retry", "Quit"], defaultId: 0, cancelId: 1,
    });
    if (response === 0) void loadFrontend();
    else app.quit();
  }
}

function createWindow() {
  window = new BrowserWindow({
    width: 1360, height: 960, minWidth: 360, minHeight: 600,
    title: "Sentinel Scan", backgroundColor: "#090e15", show: false,
    webPreferences: {
      nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true,
      partition: "persist:sentinel-desktop",
    },
  });
  const { webContents } = window;
  webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  for (const event of ["will-navigate", "will-redirect"]) {
    webContents.on(event, (event, url) => {
      if (!sameOrigin(url, origin)) event.preventDefault();
    });
  }
  webContents.on("will-attach-webview", (event) => event.preventDefault());
  webContents.session.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  webContents.session.setPermissionCheckHandler(() => false);
  webContents.session.webRequest.onHeadersReceived((details, callback) => {
    const headers = { ...details.responseHeaders };
    if (sameOrigin(details.url, origin)) {
      for (const name of Object.keys(headers)) {
        if (name.toLowerCase() === "content-security-policy") delete headers[name];
      }
      headers["Content-Security-Policy"] = [
        `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ${origin.replace("http:", "ws:")}; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'`,
      ];
    }
    callback({ responseHeaders: headers });
  });
  window.once("ready-to-show", () => window.show());
  window.on("closed", () => { window = null; });
  void loadFrontend();
}

function focusWindow() {
  if (!app.isReady() || !origin) return;
  if (!window) { createWindow(); return; }
  if (window.isMinimized()) window.restore();
  window.show(); window.focus();
}

// Incoming links only open/focus the app; they never select an origin or carry credentials.
app.on("open-url", (event) => { event.preventDefault(); focusWindow(); });

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", focusWindow);
  app.whenReady().then(() => {
    if (process.platform === "win32") {
      if (process.defaultApp) app.setAsDefaultProtocolClient(SCHEME, process.execPath, [__dirname]);
      else app.setAsDefaultProtocolClient(SCHEME);
    }
    try { origin = frontendUrl(process.env.SENTINEL_FRONTEND_URL); }
    catch (error) { dialog.showErrorBox("Invalid frontend address", error.message); app.quit(); return; }
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      ...(process.platform === "darwin" ? [{ role: "appMenu" }] : []),
      { label: "File", submenu: [{ role: "quit" }] },
      { role: "editMenu" },
      { label: "View", submenu: [
        { label: "Reload", accelerator: "CmdOrCtrl+R", click: () => { if (window) void loadFrontend(); } },
        { role: "resetZoom" }, { role: "zoomIn" }, { role: "zoomOut" }, { role: "togglefullscreen" },
      ] },
    ]));
    createWindow();
    app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
}
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
