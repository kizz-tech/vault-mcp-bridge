import { EMPTY_STATE } from "../types.js";
import type { DesktopState, JournalEntry, ServerInput, TunnelInput, VaultBridgeRendererApi } from "../types.js";

declare global {
  interface Window {
    vaultBridge: VaultBridgeRendererApi;
  }
}

const bridge = window.vaultBridge;
const elements = {
  onboarding: required<HTMLElement>("onboarding"),
  ready: required<HTMLElement>("ready"),
  vaultValue: required<HTMLElement>("vault-value"),
  serverValue: required<HTMLElement>("server-value"),
  vaultAction: required<HTMLButtonElement>("vault-action"),
  serverAction: required<HTMLButtonElement>("server-action"),
  tunnelRow: required<HTMLElement>("tunnel-row"),
  tunnelValue: required<HTMLElement>("tunnel-value"),
  tunnelAction: required<HTMLButtonElement>("tunnel-action"),
  setupAction: required<HTMLButtonElement>("setup-action"),
  onboardingError: required<HTMLElement>("onboarding-error"),
  statusPill: required<HTMLElement>("status-pill"),
  readySummary: required<HTMLElement>("ready-summary"),
  readyServer: required<HTMLElement>("ready-server"),
  readyServerAction: required<HTMLButtonElement>("ready-server-action"),
  readyChatGpt: required<HTMLElement>("ready-chatgpt"),
  chatGptAction: required<HTMLButtonElement>("chatgpt-action"),
  readySync: required<HTMLElement>("ready-sync"),
  pauseAction: required<HTMLButtonElement>("pause-action"),
  syncAction: required<HTMLButtonElement>("sync-action"),
  readyError: required<HTMLElement>("ready-error"),
  attention: required<HTMLElement>("attention"),
  attentionMessage: required<HTMLElement>("attention-message"),
  attentionAction: required<HTMLButtonElement>("attention-action"),
  serverDialog: required<HTMLDialogElement>("server-dialog"),
  serverForm: required<HTMLFormElement>("server-form"),
  serverCancel: required<HTMLButtonElement>("server-cancel"),
  serverHost: required<HTMLInputElement>("server-host"),
  serverUser: required<HTMLInputElement>("server-user"),
  serverPort: required<HTMLInputElement>("server-port"),
  tunnelDialog: required<HTMLDialogElement>("tunnel-dialog"),
  tunnelForm: required<HTMLFormElement>("tunnel-form"),
  tunnelCancel: required<HTMLButtonElement>("tunnel-cancel"),
  tunnelId: required<HTMLInputElement>("tunnel-id"),
  tunnelKey: required<HTMLInputElement>("tunnel-key"),
  openTunnels: required<HTMLButtonElement>("open-tunnels"),
  openApiKeys: required<HTMLButtonElement>("open-api-keys"),
  journalButton: required<HTMLButtonElement>("journal-button"),
  journalDialog: required<HTMLDialogElement>("journal-dialog"),
  journalClose: required<HTMLButtonElement>("journal-close"),
  journalList: required<HTMLOListElement>("journal-list"),
  menuButton: required<HTMLButtonElement>("menu-button"),
  settingsDialog: required<HTMLDialogElement>("settings-dialog"),
  loginToggle: required<HTMLInputElement>("login-toggle"),
  disconnectAction: required<HTMLButtonElement>("disconnect-action"),
  removeServerCopyAction: required<HTMLButtonElement>("remove-server-copy-action"),
  settingsError: required<HTMLElement>("settings-error")
};

let currentState: DesktopState = { ...EMPTY_STATE };

function render(state: DesktopState): void {
  currentState = state;
  const hasSetupInputs = Boolean(state.vault && state.server && (!state.requiresTunnelConfig || state.tunnel));
  const ready = state.mode === "ready" || state.mode === "synchronizing";
  elements.onboarding.hidden = ready;
  elements.ready.hidden = !ready;
  elements.attention.hidden = !state.attention;

  elements.vaultValue.textContent = state.vault
    ? `${state.vault.name} · ${state.vault.noteCount.toLocaleString()} notes · ${formatBytes(state.vault.bytes)}`
    : "Not selected";
  elements.serverValue.textContent = state.server?.label ?? "Not configured";
  if (state.server && state.serverCopy === "retained") elements.serverValue.textContent += " · copy retained";
  elements.tunnelRow.hidden = !state.requiresTunnelConfig;
  elements.tunnelValue.textContent = state.tunnel?.configured ? "Configured" : "Not configured";
  elements.setupAction.disabled = !hasSetupInputs || state.mode === "synchronizing" || (!state.requiresTunnelConfig && state.serverCopy === "retained") || state.serverCopy === "unknown";
  elements.setupAction.textContent = state.mode === "synchronizing" ? statusText(state.phase) : "Set up";

  const status = state.mode === "synchronizing" ? "Synchronizing" : state.mode === "attention" ? "Needs attention" : "Ready";
  elements.statusPill.textContent = status;
  elements.statusPill.className = `status ${state.mode}`;
  elements.readySummary.textContent = state.vault
    ? `${state.vault.noteCount.toLocaleString()} notes · ${formatBytes(state.vault.bytes)}${publishedText(state)}`
    : "";
  elements.readyServer.textContent = state.server?.label ?? "Not configured";
  elements.readyChatGpt.textContent = state.mcp?.host ?? "Not configured";
  elements.chatGptAction.textContent = state.requiresTunnelConfig ? "Open ChatGPT" : "Copy URL & Open";
  elements.readySync.textContent = state.paused ? "Paused" : "Automatic";
  elements.pauseAction.textContent = state.paused ? "Resume" : "Pause";
  elements.syncAction.disabled = state.mode === "synchronizing" || state.paused;
  elements.syncAction.textContent = state.mode === "synchronizing" ? statusText(state.phase) : "Synchronize";
  elements.attentionMessage.textContent = state.attention?.message ?? "";
  elements.attentionAction.textContent = attentionActionText(state.attention?.action);
  elements.attentionAction.disabled = !state.attention;
  const hasActiveInstallation = state.serverCopy === "active";
  const canRemoveServerCopy = state.serverCopy === "active" || state.serverCopy === "retained";
  elements.disconnectAction.disabled = !hasActiveInstallation || state.mode === "synchronizing";
  elements.removeServerCopyAction.disabled = !canRemoveServerCopy || state.mode === "synchronizing";
  clearError(elements.onboardingError);
  clearError(elements.readyError);
}

async function chooseVault(): Promise<void> {
  await run(async () => bridge.chooseVault(), elements.onboardingError);
}

function openServerDialog(): void {
  elements.serverHost.value = currentState.server?.host ?? "";
  elements.serverUser.value = currentState.server?.user ?? "";
  elements.serverPort.value = String(currentState.server?.port ?? 22);
  elements.serverDialog.showModal();
}

function openTunnelDialog(): void {
  elements.tunnelId.value = "";
  elements.tunnelKey.value = "";
  elements.tunnelDialog.showModal();
}

async function configureServer(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const input: ServerInput = {
    host: elements.serverHost.value.trim(),
    user: elements.serverUser.value.trim(),
    port: Number(elements.serverPort.value)
  };
  await run(async () => bridge.configureServer(input), elements.onboardingError);
  if (!elements.onboardingError.textContent) elements.serverDialog.close();
}

async function configureTunnel(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  const input: TunnelInput = {
    tunnelId: elements.tunnelId.value.trim(),
    apiKey: elements.tunnelKey.value.trim()
  };
  await run(async () => bridge.configureTunnel(input), elements.onboardingError);
  elements.tunnelKey.value = "";
  if (!elements.onboardingError.textContent) elements.tunnelDialog.close();
}

async function startSetup(): Promise<void> {
  await run(async () => bridge.setup(), elements.onboardingError);
}

async function synchronize(): Promise<void> {
  await run(async () => bridge.synchronize(), elements.readyError);
}

async function togglePause(): Promise<void> {
  await run(async () => bridge.setPaused(!currentState.paused), elements.readyError);
}

async function openJournal(): Promise<void> {
  const entries = await runValue(() => bridge.getJournal(), elements.readyError);
  if (entries) {
    renderJournal(entries);
    elements.journalDialog.showModal();
  }
}

async function connectChatGpt(): Promise<void> {
  await run(async () => bridge.connectChatGpt(), elements.readyError);
  if (!elements.readyError.textContent) {
    if (!currentState.requiresTunnelConfig) {
      elements.chatGptAction.textContent = "Copied";
      window.setTimeout(() => { elements.chatGptAction.textContent = "Copy URL & Open"; }, 2_000);
    }
  }
}

async function connectOwner(): Promise<void> {
  await run(async () => bridge.connectOwner(), elements.onboardingError);
}

async function disconnect(): Promise<void> {
  const state = await run(async () => bridge.disconnect(), elements.settingsError);
  if (state?.attention) showStateError(elements.settingsError, state.attention.message);
  if (state && !state.attention && state.serverCopy === "retained") elements.settingsDialog.close();
}

async function removeServerCopy(): Promise<void> {
  const state = await run(async () => bridge.removeServerCopy(), elements.settingsError);
  if (state?.attention) showStateError(elements.settingsError, state.attention.message);
  if (state && !state.attention && state.serverCopy === "none") elements.settingsDialog.close();
}

async function run(operation: () => Promise<DesktopState>, errorElement: HTMLElement): Promise<DesktopState | null> {
  clearError(errorElement);
  try {
    const state = await operation();
    render(state);
    return state;
  } catch {
    errorElement.textContent = "Operation failed";
    errorElement.hidden = false;
    return null;
  }
}

function showStateError(element: HTMLElement, message: string): void {
  element.textContent = message;
  element.hidden = false;
}

async function runValue<T>(operation: () => Promise<T>, errorElement: HTMLElement): Promise<T | null> {
  clearError(errorElement);
  try {
    return await operation();
  } catch {
    errorElement.textContent = "Operation failed";
    errorElement.hidden = false;
    return null;
  }
}

function renderJournal(entries: JournalEntry[]): void {
  elements.journalList.replaceChildren();
  for (const entry of entries.slice(-200)) {
    const item = document.createElement("li");
    item.className = entry.level;
    const time = document.createElement("time");
    time.textContent = formatTime(entry.at);
    const message = document.createElement("span");
    message.textContent = entry.message;
    item.append(time, message);
    elements.journalList.append(item);
  }
}

function statusText(phase: DesktopState["phase"]): string {
  switch (phase) {
    case "preflight": return "Checking server";
    case "staged": return "Starting container";
    case "deployed": return "Securing connection";
    case "device-bound":
    case "first-snapshot": return "Synchronizing vault";
    case "endpoint-verified": return "Verifying endpoint";
    default: return "Working";
  }
}

function publishedText(state: DesktopState): string {
  return state.lastPublishedAt ? ` · published ${formatTime(state.lastPublishedAt)}` : "";
}

function attentionActionText(action: NonNullable<DesktopState["attention"]>["action"] | undefined): string {
  switch (action) {
    case "choose-vault": return "Choose";
    case "change-server": return "Change connection";
    case "configure-tunnel": return "Configure";
    case "review-fingerprint": return "Review fingerprint";
    case "connect": return "Connect";
    case "limits": return "Limits";
    default: return "Retry";
  }
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "--:--";
}

function clearError(element: HTMLElement): void {
  element.textContent = "";
  element.hidden = true;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function required<T extends Element>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing UI element: ${id}`);
  return element as unknown as T;
}

elements.vaultAction.addEventListener("click", () => void chooseVault());
elements.serverAction.addEventListener("click", openServerDialog);
elements.tunnelAction.addEventListener("click", openTunnelDialog);
elements.readyServerAction.addEventListener("click", () => elements.settingsDialog.showModal());
elements.setupAction.addEventListener("click", () => void startSetup());
elements.syncAction.addEventListener("click", () => void synchronize());
elements.pauseAction.addEventListener("click", () => void togglePause());
elements.chatGptAction.addEventListener("click", () => void connectChatGpt());
elements.serverCancel.addEventListener("click", () => elements.serverDialog.close());
elements.serverForm.addEventListener("submit", (event) => void configureServer(event));
elements.tunnelCancel.addEventListener("click", () => elements.tunnelDialog.close());
elements.tunnelForm.addEventListener("submit", (event) => void configureTunnel(event));
elements.openTunnels.addEventListener("click", () => void bridge.openExternal("https://platform.openai.com/settings/organization/tunnels"));
elements.openApiKeys.addEventListener("click", () => void bridge.openExternal("https://platform.openai.com/settings/organization/api-keys"));
elements.journalButton.addEventListener("click", () => void openJournal());
elements.journalClose.addEventListener("click", () => elements.journalDialog.close());
elements.menuButton.addEventListener("click", () => elements.settingsDialog.showModal());
elements.loginToggle.addEventListener("change", () => void bridge.setStartAtLogin(elements.loginToggle.checked));
elements.disconnectAction.addEventListener("click", () => void disconnect());
elements.removeServerCopyAction.addEventListener("click", () => void removeServerCopy());
elements.attentionAction.addEventListener("click", () => {
  switch (currentState.attention?.action) {
    case "choose-vault": void chooseVault(); break;
    case "change-server": openServerDialog(); break;
    case "configure-tunnel": openTunnelDialog(); break;
    case "connect": void connectOwner(); break;
    case "review-fingerprint": openServerDialog(); break;
    default: void startSetup();
  }
});

void (async () => {
  try {
    render(await bridge.getState());
    bridge.onState(render);
  } catch {
    elements.onboardingError.textContent = "Operation failed";
    elements.onboardingError.hidden = false;
  }
})();
