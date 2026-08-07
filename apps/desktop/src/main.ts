import { app, BrowserWindow, clipboard, dialog, ipcMain, protocol, safeStorage, shell } from "electron";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { NativeOAuthClient, SafeStorageOwnerTokenProvider } from "./oauth-client.js";
import { ProductDesktopBackend } from "./product-backend.js";
import { loadProductConfig } from "./product-config.js";
import { MacPublisherIdentityProvider } from "./publisher-identity.js";
import { SafeStorageSecretStore } from "./secret-store.js";
import { assertTrustedSender, isAllowedExternalUrl, isAllowedMcpResourceUrl, isIpcChannel, isWithinDirectory, safeIpcError } from "./security.js";
import { OpenSshAdapter } from "./ssh.js";
import type { DesktopBackend, ServerInput } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const APP_SCHEME = "vaultbridge";
const APP_HOST = "app";

app.enableSandbox();
protocol.registerSchemesAsPrivileged([
  {
    scheme: APP_SCHEME,
    privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false }
  }
]);

export interface DesktopRuntime {
  start(): Promise<void>;
  stop(): void;
  getWindow(): BrowserWindow | null;
}

export interface DesktopRuntimeOptions {
  backend?: DesktopBackend;
  userDataPath?: string;
}

export function createDesktopRuntime(options: DesktopRuntimeOptions = {}): DesktopRuntime {
  let backend: DesktopBackend | undefined = options.backend;
  let mainWindow: BrowserWindow | null = null;
  let unsubscribe: (() => void) | null = null;
  let registered = false;

  const requireBackend = (): DesktopBackend => {
    if (!backend) throw new Error("Backend is unavailable");
    return backend;
  };

  const registerProtocol = (): void => {
    protocol.handle(APP_SCHEME, async (request) => {
      const url = new URL(request.url);
      if (url.hostname !== APP_HOST) return new Response("Not found", { status: 404 });
      // `app.getAppPath()` points at `dist/` when Electron is launched with
      // `electron dist/main.js`, but at the application root when packaged.
      // The bundled main module and renderer directory are siblings in both
      // layouts, so anchor resource lookup to this module instead.
      const rendererRoot = resolve(__dirname, "renderer");
      let requestPath: string;
      try {
        requestPath = decodeURIComponent(url.pathname.replace(/^\/+/, "")) || "index.html";
      } catch {
        return new Response("Not found", { status: 404 });
      }
      const candidate = resolve(rendererRoot, requestPath);
      if (!isWithinDirectory(rendererRoot, candidate)) return new Response("Not found", { status: 404 });
      try {
        const contents = await readFile(candidate);
        return new Response(contents, { headers: { "content-type": mimeType(candidate) } });
      } catch {
        return new Response("Not found", { status: 404 });
      }
    });
  };

  const assertSender = (event: Electron.IpcMainInvokeEvent): void => {
    const frameUrl = event.senderFrame?.url ?? "";
    const expectedId = mainWindow?.webContents.id;
    if (expectedId === undefined) throw new Error("Window is unavailable");
    assertTrustedSender(event.sender.id, frameUrl, expectedId);
  };

  const emitState = async (): Promise<void> => {
    if (!backend) return;
    const state = await backend.getState();
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("state:changed", state);
  };

  const registerIpc = (): void => {
    const currentBackend = (): DesktopBackend => {
      if (!backend) throw new Error("Backend is unavailable");
      return backend;
    };
    if (registered) return;
    registered = true;
    ipcMain.handle("state:get", async (event) => {
      assertSender(event);
      return currentBackend().getState();
    });
    ipcMain.handle("vault:choose", async (event) => {
      assertSender(event);
      const dialogOptions: Electron.OpenDialogOptions = {
        title: "Choose vault",
        properties: ["openDirectory", "dontAddToRecent"]
      };
      const result = mainWindow
        ? await dialog.showOpenDialog(mainWindow, dialogOptions)
        : await dialog.showOpenDialog(dialogOptions);
      const root = result.canceled ? null : result.filePaths[0];
      if (!root) return currentBackend().getState();
      try {
        await currentBackend().selectVault(root);
        return currentBackend().getState();
      } catch (error) {
        throw safeIpcError(error);
      }
    });
    ipcMain.handle("server:configure", async (event, payload: unknown) => {
      assertSender(event);
      const input = parseServerInput(payload);
      try {
        await currentBackend().configureServer(input);
        return currentBackend().getState();
      } catch (error) {
        throw safeIpcError(error);
      }
    });
    ipcMain.handle("setup:start", async (event) => {
      assertSender(event);
      return currentBackend().setup();
    });
    ipcMain.handle("sync:now", async (event) => {
      assertSender(event);
      return currentBackend().synchronize();
    });
    ipcMain.handle("sync:set-paused", async (event, payload: unknown) => {
      assertSender(event);
      if (typeof payload !== "boolean") throw safeIpcError(new TypeError("Invalid pause state"));
      return currentBackend().setPaused(payload);
    });
    ipcMain.handle("journal:list", async (event) => {
      assertSender(event);
      return currentBackend().getJournal();
    });
    ipcMain.handle("settings:set-start-at-login", async (event, payload: unknown) => {
      assertSender(event);
      if (typeof payload !== "boolean") throw safeIpcError(new TypeError("Invalid login setting"));
      app.setLoginItemSettings({ openAtLogin: payload, type: "mainAppService" });
      await currentBackend().setStartAtLogin(payload);
    });
    ipcMain.handle("chatgpt:connect", async (event) => {
      assertSender(event);
      try {
        const state = await currentBackend().getState();
        const resourceUrl = state.mcp?.resourceUrl;
        if (!resourceUrl || !isAllowedMcpResourceUrl(resourceUrl)) throw new Error("MCP endpoint unavailable");
        clipboard.writeText(resourceUrl);
        return await currentBackend().connectChatGpt();
      } catch (error) {
        throw safeIpcError(error);
      }
    });
    ipcMain.handle("owner:connect", async (event) => {
      assertSender(event);
      const connect = currentBackend().connectOwner;
      if (!connect) throw safeIpcError(new Error("Owner sign-in unavailable"));
      return connect.call(currentBackend());
    });
    ipcMain.handle("deployment:update", async (event) => {
      assertSender(event);
      const update = currentBackend().update;
      if (!update) throw safeIpcError(new Error("Update unavailable"));
      return update.call(currentBackend());
    });
    ipcMain.handle("security:disconnect", async (event) => {
      assertSender(event);
      const disconnect = currentBackend().disconnect;
      if (!disconnect) throw safeIpcError(new Error("Disconnect unavailable"));
      const result = await dialog.showMessageBox({
        type: "warning",
        buttons: ["Cancel", "Disconnect"],
        defaultId: 0,
        cancelId: 0,
        title: "Disconnect Vault Bridge",
        message: "Disconnect from the server?",
        detail: "Remote access will be revoked and the service stopped. The server copy will remain."
      });
      if (result.response !== 1) return currentBackend().getState();
      try {
        return await disconnect.call(currentBackend());
      } catch (error) {
        throw safeIpcError(error);
      }
    });
    ipcMain.handle("security:remove-server-copy", async (event) => {
      assertSender(event);
      const removeServerCopy = currentBackend().removeServerCopy;
      if (!removeServerCopy) throw safeIpcError(new Error("Removal unavailable"));
      const result = await dialog.showMessageBox({
        type: "warning",
        buttons: ["Cancel", "Remove server copy"],
        defaultId: 0,
        cancelId: 0,
        checkboxLabel: "I understand that the server copy and its Docker volumes will be deleted.",
        checkboxChecked: false,
        title: "Remove server copy",
        message: "Remove this vault from the server?",
        detail: "Remote access will be revoked. This cannot be undone. Your local vault will not be changed."
      });
      if (result.response !== 1 || !result.checkboxChecked) return currentBackend().getState();
      try {
        return await removeServerCopy.call(currentBackend());
      } catch (error) {
        throw safeIpcError(error);
      }
    });
    ipcMain.handle("external:open", async (event, payload: unknown) => {
      assertSender(event);
      if (typeof payload !== "string" || !isAllowedExternalUrl(payload)) {
        throw safeIpcError(new TypeError("Invalid external URL"));
      }
      await shell.openExternal(payload);
    });
    // Defensive assertion catches a typo when a new handler is added without
    // first extending the explicit channel allow-list.
    for (const channel of [
      "state:get",
      "vault:choose",
      "server:configure",
      "setup:start",
      "sync:now",
      "sync:set-paused",
      "journal:list",
      "settings:set-start-at-login",
      "chatgpt:connect",
      "owner:connect",
      "deployment:update",
      "security:disconnect",
      "security:remove-server-copy",
      "external:open"
    ]) {
      if (!isIpcChannel(channel)) throw new Error(`IPC channel is not allow-listed: ${channel}`);
    }
  };

  const createWindow = (): BrowserWindow => {
    const window = new BrowserWindow({
      width: 640,
      height: 620,
      minWidth: 520,
      minHeight: 480,
      show: false,
      title: "Vault Bridge",
      webPreferences: {
        preload: join(__dirname, "preload.cjs"),
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        webSecurity: true,
        webviewTag: false,
        spellcheck: false
      }
    });
    window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    window.webContents.on("will-navigate", (event) => event.preventDefault());
    window.webContents.on("will-attach-webview", (event) => event.preventDefault());
    window.webContents.session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    window.on("closed", () => {
      if (mainWindow === window) mainWindow = null;
    });
    window.once("ready-to-show", () => window.show());
    void window.loadURL(`${APP_SCHEME}://${APP_HOST}/index.html`);
    return window;
  };

  return {
    async start() {
      if (options.userDataPath) app.setPath("userData", options.userDataPath);
      await app.whenReady();
      if (!backend) {
        const secretStore = new SafeStorageSecretStore(join(app.getPath("userData"), "secrets.json"), safeStorage);
        const config = await loadProductConfig({
          filePaths: [
            join(app.getPath("userData"), "product-config.json"),
            join(process.resourcesPath, "product-config.json")
          ],
          allowLoopback: !app.isPackaged && process.env.NODE_ENV !== "production"
        });
        const browser = { openExternal: (url: string) => shell.openExternal(url) };
        const oauth = config
          ? new NativeOAuthClient(config, secretStore, browser)
          : undefined;
        const ownerTokens = oauth ?? new SafeStorageOwnerTokenProvider(secretStore);
        backend = new ProductDesktopBackend({
          appDataPath: app.getPath("userData"),
          ...(config ? { config } : {}),
          secretStore,
          ownerTokens,
          browser,
          publisherIdentity: new MacPublisherIdentityProvider(secretStore),
          ...(oauth ? { oauth } : {}),
          ssh: new OpenSshAdapter(undefined, join(app.getPath("userData"), "ssh", "known_hosts")),
          confirmation: {
            async confirm(fingerprint, target) {
              const result = await dialog.showMessageBox({
                type: "question",
                buttons: ["Cancel", "Trust"],
                defaultId: 0,
                cancelId: 0,
                title: "Verify server",
                message: `${target.user}@${target.host}`,
                detail: fingerprint
              });
              return result.response === 1;
            }
          }
        });
      }
      registerProtocol();
      registerIpc();
      if (backend.initialize) await backend.initialize();
      mainWindow = createWindow();
      unsubscribe = requireBackend().subscribe((state) => {
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("state:changed", state);
      });
      app.on("activate", () => {
        if (!mainWindow) mainWindow = createWindow();
      });
      app.on("window-all-closed", () => {
        if (process.platform !== "darwin") app.quit();
      });
      // Instantiate the store here so the app fails closed if safeStorage is
      // unavailable when a future backend requests a credential.
      await emitState();
    },
    stop() {
      backend?.close?.();
      unsubscribe?.();
      unsubscribe = null;
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.close();
      mainWindow = null;
    },
    getWindow() {
      return mainWindow;
    }
  };
}

function parseServerInput(payload: unknown): ServerInput {
  if (!payload || typeof payload !== "object") throw new TypeError("Invalid server input");
  const candidate = payload as Partial<ServerInput>;
  if (typeof candidate.host !== "string" || typeof candidate.user !== "string" || typeof candidate.port !== "number") {
    throw new TypeError("Invalid server input");
  }
  return { host: candidate.host, user: candidate.user, port: candidate.port };
}

function mimeType(path: string): string {
  switch (extname(path).toLowerCase()) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

if (process.env.VAULT_BRIDGE_NO_BOOT !== "1") {
  const runtime = createDesktopRuntime();
  void runtime.start();
} else if (process.env.VAULT_BRIDGE_SMOKE_MAIN === "1") {
  void app.whenReady().then(
    () => app.quit(),
    () => app.exit(1)
  );
}
