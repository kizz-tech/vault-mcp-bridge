import { contextBridge, ipcRenderer } from "electron";

import { IPC_CHANNELS, isAllowedExternalUrl, type IpcChannel } from "./security.js";
import type { DesktopState, JournalEntry, ServerInput, TunnelInput, VaultBridgeRendererApi } from "./types.js";

function invoke<T>(channel: Exclude<IpcChannel, "state:changed">, payload?: unknown): Promise<T> {
  return ipcRenderer.invoke(channel, payload) as Promise<T>;
}

const api: VaultBridgeRendererApi = Object.freeze({
  getState: () => invoke<DesktopState>("state:get"),
  chooseVault: () => invoke<DesktopState>("vault:choose"),
  configureServer: (input: ServerInput) => invoke<DesktopState>("server:configure", input),
  configureTunnel: (input: TunnelInput) => invoke<DesktopState>("tunnel:configure", input),
  setup: () => invoke<DesktopState>("setup:start"),
  synchronize: () => invoke<DesktopState>("sync:now"),
  setPaused: (paused: boolean) => invoke<DesktopState>("sync:set-paused", paused),
  getJournal: () => invoke<JournalEntry[]>("journal:list"),
  getStartAtLogin: () => invoke<boolean>("settings:get-start-at-login"),
  setStartAtLogin: (enabled: boolean) => invoke<void>("settings:set-start-at-login", enabled),
  connectChatGpt: () => invoke<DesktopState>("chatgpt:connect"),
  connectOwner: () => invoke<DesktopState>("owner:connect"),
  update: () => invoke<DesktopState>("deployment:update"),
  disconnect: () => invoke<DesktopState>("security:disconnect"),
  removeServerCopy: () => invoke<DesktopState>("security:remove-server-copy"),
  onState: (listener: (state: DesktopState) => void) => {
    const wrapped = (_event: Electron.IpcRendererEvent, state: DesktopState): void => listener(state);
    ipcRenderer.on("state:changed", wrapped);
  },
  openExternal: async (url: string) => {
    if (!isAllowedExternalUrl(url)) throw new Error("Only HTTPS links can be opened");
    await invoke<void>("external:open", url);
  }
});

// Keep the allow-list referenced so a missing channel cannot accidentally be
// exposed during a future refactor.
void IPC_CHANNELS;
contextBridge.exposeInMainWorld("vaultBridge", api);

declare global {
  interface Window {
    vaultBridge: VaultBridgeRendererApi;
  }
}
