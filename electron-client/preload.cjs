const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sharedBrowser', {
  bootstrap: () => ipcRenderer.invoke('browser:bootstrap'),
  navigate: (url) => ipcRenderer.invoke('browser:navigate', url),
  back: () => ipcRenderer.invoke('browser:back'),
  forward: () => ipcRenderer.invoke('browser:forward'),
  reload: () => ipcRenderer.invoke('browser:reload'),
  stop: () => ipcRenderer.invoke('browser:stop'),
  newTab: (url) => ipcRenderer.invoke('browser:new-tab', url),
  selectTab: (id) => ipcRenderer.invoke('browser:select-tab', id),
  closeTab: (id) => ipcRenderer.invoke('browser:close-tab', id),
  syncNow: () => ipcRenderer.invoke('browser:sync-now'),
  privacyCheck: () => ipcRenderer.invoke('browser:privacy-check'),
  setSettingsOpen: (open) => ipcRenderer.invoke('browser:settings-open', Boolean(open)),
  saveSettings: (settings) => ipcRenderer.invoke('browser:save-settings', settings),
  checkForUpdates: () => ipcRenderer.invoke('browser:check-updates'),
  installUpdate: () => ipcRenderer.invoke('browser:install-update'),
  onState: (callback) => ipcRenderer.on('browser:state', (_, value) => callback(value)),
  onTabs: (callback) => ipcRenderer.on('browser:tabs', (_, value) => callback(value)),
  onStatus: (callback) => ipcRenderer.on('browser:status', (_, value) => callback(value)),
  onShowSettings: (callback) => ipcRenderer.on('browser:show-settings', () => callback()),
  onFocusAddress: (callback) => ipcRenderer.on('browser:focus-address', () => callback()),
  onUpdate: (callback) => ipcRenderer.on('browser:update', (_, value) => callback(value))
});
