const state = { csrfToken: '', activity: [], configLoaded: false, identityExists: false };

const $ = (id) => document.getElementById(id);
const formatBytes = (bytes) => {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
};
const formatTime = (value) => value ? new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Never';
function addActivity(message, error = false) {
  state.activity.unshift({ message, error, at: new Date() });
  state.activity = state.activity.slice(0, 8);
  $('activity').innerHTML = state.activity.map((item) => `<div class="activity-item ${item.error ? 'error' : ''}"><span class="activity-dot"></span><div><strong>${escapeHtml(item.message)}</strong></div><span class="activity-time">${item.at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span></div>`).join('');
}
function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]); }
function showError(error) { const banner = $('error-banner'); banner.textContent = error; banner.classList.remove('hidden'); addActivity(error, true); }
function clearError() { $('error-banner').classList.add('hidden'); }
async function api(path, options = {}) {
  const headers = { accept: 'application/json', ...(options.body ? { 'content-type': 'application/json' } : {}), ...(options.method && options.method !== 'GET' ? { 'x-bridge-csrf': state.csrfToken } : {}), ...(options.headers || {}) };
  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}
function applyStatus(status, identity) {
  $('connection-label').textContent = 'Agent online · loopback only';
  $('credential-summary').textContent = status.credentialStore === 'file-development' ? 'Development file store · mode 0600' : 'macOS Keychain adapter unavailable';
  const paired = status.pairingConfigured;
  $('sync-state').textContent = paired ? 'PAIRED' : 'NOT PAIRED';
  $('sync-state').classList.toggle('ready', paired);
  $('sync-button').disabled = !paired || !status.vaultConfigured || !status.previewValid;
  $('sync-button').title = status.previewValid ? '' : 'Run a preview scan before publishing.';
  $('preview-validity').textContent = status.previewValid ? 'VALID FOR PUBLISH' : 'PREVIEW REQUIRED';
  $('preview-validity').classList.toggle('muted', !status.previewValid);
  $('last-scan').textContent = formatTime(status.lastScanAt);
  $('last-upload').textContent = formatTime(status.lastUploadAt);
  const age = status.lastPublisherStatus?.freshnessSeconds;
  $('freshness').textContent = Number.isFinite(age) ? `${Math.round(age)}s` : '—';
  if (identity) {
    state.identityExists = true;
    $('identity-summary').textContent = `Ed25519 identity · ${identity.publicKey.slice(0, 22)}…`;
    $('identity-state').textContent = 'READY'; $('identity-state').classList.remove('muted');
  }
  const preview = status.lastPreview;
  if (preview) applyPreview(preview);
  const pending = (status.pendingRevocations || []).slice(0, 32);
  const warning = $('rotation-warning');
  if (pending.length) {
    const ids = pending.map((record) => record.deviceId).join(', ');
    warning.textContent = `${pending.length} old device ${pending.length === 1 ? 'identity' : 'identities'} pending revocation (${ids}). Revoke them on the server before treating this agent as fully rotated.`;
    warning.classList.remove('hidden');
  } else warning.classList.add('hidden');
  updateSteps(status, state.identityExists || Boolean(identity));
}
function applyPreview(preview) {
  $('metric-documents').textContent = preview.documents.toLocaleString();
  $('metric-bytes').textContent = formatBytes(preview.bytes);
  $('metric-excluded').textContent = preview.excluded.toLocaleString();
  const included = (preview.included || []).slice(0, 200);
  const excluded = (preview.exclusions || []).slice(0, 200);
  const includedTotal = Number.isFinite(preview.includedTotal) ? preview.includedTotal : included.length;
  const excludedTotal = Number.isFinite(preview.excludedTotal) ? preview.excludedTotal : (preview.excluded || excluded.length);
  const includedOmitted = Number.isFinite(preview.includedOmitted) ? preview.includedOmitted : Math.max(0, includedTotal - included.length);
  const excludedOmitted = Number.isFinite(preview.excludedOmitted) ? preview.excludedOmitted : Math.max(0, excludedTotal - excluded.length);
  $('included-count').textContent = `${includedTotal} total`;
  $('excluded-count').textContent = `${excludedTotal} total`;
  $('included-omitted').textContent = includedOmitted ? ` · ${includedOmitted} omitted from list` : '';
  $('excluded-omitted').textContent = excludedOmitted ? ` · ${excludedOmitted} omitted from list` : '';
  $('included-list').innerHTML = included.length ? included.map((entry) => `<li><span>${escapeHtml(entry.path)}</span><span>${formatBytes(entry.bytes)}</span></li>`).join('') : '<li class="muted-row">No included entries.</li>';
  $('excluded-list').innerHTML = excluded.length ? excluded.map((entry) => `<li><span>${escapeHtml(entry.path)}</span><span class="reason">${escapeHtml(entry.reason)}</span></li>`).join('') : '<li class="muted-row">No exclusions.</li>';
}
function updateSteps(status, identityReady) {
  const complete = { vault: status.vaultConfigured, preview: Boolean(status.previewValid), identity: identityReady, pair: status.pairingConfigured };
  let count = 0;
  for (const [name, done] of Object.entries(complete)) { const item = document.querySelector(`[data-step="${name}"]`); if (item) { item.classList.toggle('complete', done); item.querySelector('.step-state').textContent = done ? 'Done' : 'Next'; } if (done) count += 1; }
  $('step-count').textContent = `${count}/4`;
}
function applyConfig(config) {
  if (!config || state.configLoaded) return;
  $('vault-root').value = config.vaultRoot || '';
  $('vault-id').value = config.vaultId || '';
  $('remote-url').value = config.remoteServerUrl || '';
  $('include').value = (config.include || ['**/*.md', '**/*.canvas', '**/*.base']).join(', ');
  $('exclude').value = (config.exclude || ['.obsidian/**', '**/.git/**', '**/.*']).join(', ');
  $('sync-interval').value = String(config.syncIntervalMinutes || 0);
  state.configLoaded = true;
}
async function refresh() {
  try {
    const boot = await api('/api/bootstrap');
    state.csrfToken = boot.csrfToken; applyConfig(boot.config); applyStatus(boot.status, boot.identity); clearError();
  } catch (error) { $('connection-label').textContent = 'Agent unavailable'; showError(error.message); }
}
$('config-form').addEventListener('submit', async (event) => {
  event.preventDefault(); clearError();
  const form = new FormData(event.currentTarget);
  const payload = { vaultRoot: form.get('vaultRoot')?.toString().trim(), vaultId: form.get('vaultId')?.toString().trim(), remoteServerUrl: form.get('remoteServerUrl')?.toString().trim(), include: form.get('include')?.toString().split(',').map((v) => v.trim()).filter(Boolean), exclude: form.get('exclude')?.toString().split(',').map((v) => v.trim()).filter(Boolean), syncIntervalMinutes: Number(form.get('syncIntervalMinutes') || 0) };
  try { const result = await api('/api/config', { method: 'POST', body: JSON.stringify(payload) }); applyStatus(result.status); addActivity('Export policy saved'); } catch (error) { showError(error.message); }
});
$('preview-button').addEventListener('click', async () => {
  clearError(); const root = $('vault-root').value.trim();
  if (!root) return showError('Enter a vault root before previewing.');
  try { const result = await api('/api/preview', { method: 'POST', body: JSON.stringify({ vaultRoot: root }) }); applyPreview(result.preview); addActivity(`Preview complete · ${result.preview.documents} documents`); await refresh(); } catch (error) { showError(error.message); }
});
$('identity-button').addEventListener('click', async () => { clearError(); const rotate = state.identityExists; if (rotate && !window.confirm('Rotate this device identity? The current server device must be revoked and paired again.')) return; try { const result = await api('/api/device/generate', { method: 'POST', body: JSON.stringify({ rotate }) }); addActivity(rotate ? 'Device identity rotated · pair again' : 'Device identity generated'); applyStatus((await api('/api/status')).status, result.identity); } catch (error) { showError(error.message); } });
$('pair-button').addEventListener('click', async () => { clearError(); const code = $('pair-code').value.trim(); if (!code) return showError('Paste a one-time pairing code.'); try { await api('/api/pair', { method: 'POST', body: JSON.stringify({ code }) }); $('pair-code').value = ''; addActivity('Remote server paired'); await refresh(); } catch (error) { showError(error.message); } });
$('sync-button').addEventListener('click', async () => { clearError(); $('sync-button').disabled = true; try { const result = await api('/api/sync', { method: 'POST', body: '{}' }); addActivity(`Snapshot ${result.snapshotId.slice(0, 12)}… uploaded`); await refresh(); } catch (error) { showError(error.message); await refresh(); } });
$('status-button').addEventListener('click', async () => { clearError(); try { const result = await api('/api/publisher/status', { method: 'POST', body: '{}' }); addActivity('Publisher status refreshed'); $('freshness').textContent = Number.isFinite(result.status.freshnessSeconds) ? `${Math.round(result.status.freshnessSeconds)}s` : '—'; } catch (error) { showError(error.message); } });
refresh();
