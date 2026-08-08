import { app, BrowserWindow, clipboard, dialog, ipcMain, protocol, safeStorage, shell } from "electron";
import { mkdtempSync } from "node:fs";
import { access, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { AGENT_HELP, agentJournal, agentStatus, parseAgentCommand, readAgentSetupPlan, readRuntimeKeyFromStdin } from "./agent-command.js";
import { NativeOAuthClient, SafeStorageOwnerTokenProvider } from "./oauth-client.js";
import { PrivateDesktopBackend } from "./private-backend.js";
import { ProductDesktopBackend } from "./product-backend.js";
import { loadProductConfig } from "./product-config.js";
import { MacPublisherIdentityProvider } from "./publisher-identity.js";
import { SafeStorageSecretStore } from "./secret-store.js";
import { loadSecureTunnelProductConfig } from "./secure-tunnel-config.js";
import { assertTrustedSender, isAllowedExternalUrl, isAllowedMcpResourceUrl, isIpcChannel, isWithinDirectory, safeIpcError } from "./security.js";
import { OpenSshAdapter, normalizeFingerprint, type SshTarget } from "./ssh.js";
import type { DesktopBackend, ServerInput, TunnelInput } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const APP_SCHEME = "vaultbridge";
const APP_HOST = "app";

app.setName("Vault Bridge");
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

type BackendBundle = {
  backend: DesktopBackend;
  kind: "private" | "advanced";
  privateBackend?: PrivateDesktopBackend;
  ssh?: OpenSshAdapter;
};

async function createDefaultBackend(options: {
  confirmation?: { confirm(fingerprint: string, target: SshTarget): Promise<boolean> };
} = {}): Promise<BackendBundle> {
  const appDataPath = app.getPath("userData");
  const secretStore = new SafeStorageSecretStore(join(appDataPath, "secrets.json"), safeStorage);
  const productConfig = await loadProductConfig({
    filePaths: [join(appDataPath, "product-config.json"), join(process.resourcesPath, "product-config.json")],
    allowLoopback: !app.isPackaged && process.env.NODE_ENV !== "production"
  });
  const browser = { openExternal: (url: string) => shell.openExternal(url) };
  const confirmation = options.confirmation ?? {
    async confirm(fingerprint: string, target: SshTarget) {
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
  };
  const ssh = new OpenSshAdapter(undefined, join(appDataPath, "ssh", "known_hosts"));
  if (productConfig) {
    const oauth = new NativeOAuthClient(productConfig, secretStore, browser);
    return {
      kind: "advanced",
      backend: new ProductDesktopBackend({
        appDataPath,
        config: productConfig,
        secretStore,
        ownerTokens: oauth ?? new SafeStorageOwnerTokenProvider(secretStore),
        browser,
        publisherIdentity: new MacPublisherIdentityProvider(secretStore),
        oauth,
        ssh,
        confirmation
      })
    };
  }
  const secureConfig = await loadSecureTunnelProductConfig({
    filePaths: [join(appDataPath, "secure-tunnel-config.json"), join(process.resourcesPath, "secure-tunnel-config.json")],
    allowMutableImage: !app.isPackaged && process.env.NODE_ENV !== "production"
  }) ?? (!app.isPackaged
    ? { image: "vault-mcp-bridge-secure-tunnel:local", syncIntervalMinutes: 5 }
    : undefined);
  if (!secureConfig) throw new Error("Secure tunnel product configuration is missing");
  const privateBackend = new PrivateDesktopBackend({
    appDataPath,
    config: secureConfig,
    composeTemplatePath: join(__dirname, "assets", "secure-tunnel-compose.yaml"),
    secretStore,
    browser,
    ssh,
    confirmation
  });
  return { kind: "private", backend: privateBackend, privateBackend, ssh };
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
    ipcMain.handle("tunnel:configure", async (event, payload: unknown) => {
      assertSender(event);
      const configure = currentBackend().configureTunnel;
      if (!configure) throw safeIpcError(new Error("Secure tunnel configuration unavailable"));
      const input = parseTunnelInput(payload);
      try {
        await configure.call(currentBackend(), input);
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
    ipcMain.handle("settings:get-start-at-login", async (event) => {
      assertSender(event);
      return app.getLoginItemSettings().openAtLogin;
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
        if (!state.requiresTunnelConfig) {
          const resourceUrl = state.mcp?.resourceUrl;
          if (!resourceUrl || !isAllowedMcpResourceUrl(resourceUrl)) throw new Error("MCP endpoint unavailable");
          clipboard.writeText(resourceUrl);
        }
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
      "tunnel:configure",
      "setup:start",
      "sync:now",
      "sync:set-paused",
      "journal:list",
      "settings:get-start-at-login",
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
      width: 980,
      height: 760,
      minWidth: 720,
      minHeight: 600,
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
        backend = (await createDefaultBackend()).backend;
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

function parseTunnelInput(payload: unknown): TunnelInput {
  if (!payload || typeof payload !== "object") throw new TypeError("Invalid tunnel input");
  const candidate = payload as Partial<TunnelInput>;
  if (typeof candidate.tunnelId !== "string" || typeof candidate.apiKey !== "string") {
    throw new TypeError("Invalid tunnel input");
  }
  return { tunnelId: candidate.tunnelId, apiKey: candidate.apiKey };
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

async function runAgentMode(arguments_: readonly string[]): Promise<number> {
  const command = parseAgentCommand(arguments_);
  if ((command.name === "prepare" || command.name === "setup") && !app.requestSingleInstanceLock()) {
    throw new Error("agent_app_running");
  }
  await app.whenReady();
  if (command.name === "help") {
    writeAgentJson(AGENT_HELP);
    return 0;
  }
  if (command.name === "doctor") {
    const guiRunning = !app.requestSingleInstanceLock();
    const checks = {
      platform: process.platform === "darwin",
      encryptedStorage: false,
      ssh: await access("/usr/bin/ssh").then(() => true, () => false),
      packaged: app.isPackaged,
      startAtLogin: app.getLoginItemSettings().openAtLogin
    };
    let installation: Awaited<ReturnType<PrivateDesktopBackend["diagnose"]>> | null = null;
    let backendAvailable = true;
    if (checks.platform && checks.ssh) {
      try {
        const bundle = await createDefaultBackend({ confirmation: { confirm: async () => false } });
        if (bundle.kind === "private" && bundle.privateBackend) {
          await bundle.privateBackend.initialize({ backgroundSync: false, refreshVault: false });
          try {
            installation = await bundle.privateBackend.diagnose({ verifyLocalTunnelCredential: false });
          } finally {
            bundle.privateBackend.close();
          }
        }
      } catch {
        backendAvailable = false;
        installation = null;
      }
    }
    const configured = installation?.checks.configuration.status === "pass";
    // A configured installation proves that encrypted setup completed. Avoid
    // opening macOS Keychain from a diagnostic child process; that synchronous
    // lookup can contend with the GUI. Clean, unconfigured installs still run
    // Electron's capability check once before setup.
    checks.encryptedStorage = Boolean(guiRunning || configured || safeStorage.isEncryptionAvailable());
    const ready = configured ? Boolean(installation?.ok) : false;
    const ok = checks.platform && checks.encryptedStorage && checks.ssh && backendAvailable && (!configured || ready);
    writeAgentJson({ ok, ready, appVersion: app.getVersion(), checks: { ...checks, installation } });
    return ok ? 0 : 1;
  }

  let approvedFingerprint: string | undefined;
  if (command.name === "setup") approvedFingerprint = normalizeFingerprint(command.approvedFingerprint);
  const bundle = await createDefaultBackend({
    confirmation: {
      confirm: async (fingerprint) => approvedFingerprint !== undefined && normalizeFingerprint(fingerprint) === approvedFingerprint
    }
  });
  if (bundle.kind !== "private" || !bundle.privateBackend || !bundle.ssh) throw new Error("agent_mode_requires_private_tunnel");
  const backend = bundle.privateBackend;
  try {
    await backend.initialize({ backgroundSync: false, refreshVault: false });
    if (command.name === "status") {
      writeAgentJson(agentStatus(await backend.getState()));
      return 0;
    }
    if (command.name === "journal") {
      writeAgentJson(agentJournal(await backend.getJournal()));
      return 0;
    }
    if (command.name === "prepare") {
      const plan = await readAgentSetupPlan(command.configPath);
      const runtimeKey = await readRuntimeKeyFromStdin(process.stdin);
      await backend.selectVault(plan.vaultRoot);
      await backend.configureServer(plan.server);
      const resolvedTarget = await bundle.ssh.resolve(OpenSshAdapter.fromInput(plan.server));
      const fingerprint = await bundle.ssh.readHostFingerprint(resolvedTarget);
      if (!fingerprint) throw new Error("server_identity_unavailable");
      await backend.configureTunnel({ tunnelId: plan.openai.tunnelId, apiKey: runtimeKey });
      writeAgentJson({
        ok: true,
        prepared: true,
        state: agentStatus(await backend.getState()),
        approval: { kind: "ssh-host-fingerprint", fingerprint },
        nextCommand: `vault-bridge setup --approve-host-fingerprint ${fingerprint} --json`
      });
      return 0;
    }
    const state = await backend.setup();
    const status = agentStatus(state);
    writeAgentJson(status);
    return state.mode === "ready" ? 0 : 1;
  } finally {
    backend.close();
  }
}

function writeAgentJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function safeAgentError(error: unknown): string {
  const code = error instanceof Error ? error.message : "agent_command_failed";
  const allowed = new Set([
    "agent_command_invalid",
    "agent_config_path_invalid",
    "agent_config_invalid",
    "agent_config_owner_invalid",
    "agent_config_permissions_invalid",
    "runtime_key_stdin_invalid",
    "agent_mode_requires_private_tunnel",
    "agent_app_running",
    "server_identity_unavailable",
    "Secure tunnel product configuration is missing"
  ]);
  if (allowed.has(code)) return code;
  if (/tunnel|api key/iu.test(code)) return "openai_tunnel_credentials_invalid";
  if (/vault|scan/iu.test(code)) return "vault_unavailable";
  if (/ssh|server identity|fingerprint/iu.test(code)) return "ssh_preflight_failed";
  if (/safeStorage|encryption|keychain/iu.test(code)) return "encrypted_storage_unavailable";
  return "agent_command_failed";
}

const agentArgumentIndex = process.argv.findIndex((argument) => argument === "--agent" || argument === "agent");
const agentArguments = process.env.VAULT_BRIDGE_AGENT_MODE === "1"
  ? process.argv.slice(1)
  : agentArgumentIndex >= 0
    ? process.argv.slice(agentArgumentIndex + 1)
    : undefined;
if (agentArguments) {
  // Agent commands may run while the GUI owns its normal Chromium profile.
  // Isolate ephemeral network/cache state to prevent multi-process profile
  // contention while keeping product configuration and safeStorage in the
  // canonical app userData directory used by createDefaultBackend().
  const agentSessionDataPath = mkdtempSync(join(tmpdir(), "vault-bridge-agent-"));
  app.setPath("sessionData", agentSessionDataPath);
  app.disableHardwareAcceleration();
  app.commandLine.appendSwitch("log-level", "3");
  let exitPromise: Promise<void> | undefined;
  const exitAgent = (code: number): Promise<void> => {
    exitPromise ??= rm(agentSessionDataPath, { recursive: true, force: true })
      .catch(() => undefined)
      .then(() => { app.exit(code); });
    return exitPromise;
  };
  process.stdout.on("error", (error: NodeJS.ErrnoException) => {
    void exitAgent(error.code === "EPIPE" ? 0 : 1);
  });
  void runAgentMode(agentArguments).then(
    (code) => exitAgent(code),
    (error: unknown) => {
      writeAgentJson({ ok: false, error: safeAgentError(error) });
      return exitAgent(1);
    }
  );
} else if (process.env.VAULT_BRIDGE_NO_BOOT !== "1") {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
  } else {
    const runtime = createDesktopRuntime();
    app.on("second-instance", () => {
      const window = runtime.getWindow();
      if (window) {
        if (window.isMinimized()) window.restore();
        window.show();
        window.focus();
      }
    });
    void runtime.start().catch(() => {
      dialog.showErrorBox("Vault Bridge could not start", "Run `vault-bridge doctor --json` for a safe diagnostic report.");
      app.quit();
    });
  }
} else if (process.env.VAULT_BRIDGE_SMOKE_MAIN === "1") {
  void app.whenReady().then(
    () => app.quit(),
    () => app.exit(1)
  );
}
