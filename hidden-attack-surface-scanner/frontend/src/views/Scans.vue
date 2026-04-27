<script setup>
import { reactive, ref, onMounted, computed, watch } from 'vue';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';
import { useToastStore } from '../stores/toast.js';
import { useWebSocketStore } from '../stores/websocket.js';
import { useRouter } from 'vue-router';

const app = useAppStore();
const toast = useToastStore();
const ws = useWebSocketStore();
const router = useRouter();
const showForm = ref(true);
const submitting = ref(false);
const confirmDelete = ref(null);
const confirmBatchDelete = ref(false);
const selectedLogScan = ref('');
const selectedScanIds = ref([]);

const form = reactive({
  targets: '',
  mode: 'quick',
  concurrency: 10,
  batch_size: 1500,
  rate_limit: 20,
  callback_timeout_minutes: 1440,
  proxy: '',
  default_origin: '',
  default_referer: '',
  custom_headers: '',
});

function applySettingsDefaults() {
  if (!app.settings?.scanner) return;
  form.concurrency = app.settings.scanner.default_concurrency || 10;
  form.batch_size = app.settings.scanner.default_batch_size || 1500;
  form.rate_limit = app.settings.scanner.default_rate_limit || 20;
  form.callback_timeout_minutes = app.settings.scanner.default_timeout_minutes || 1440;
  form.default_origin = app.settings.scanner.default_origin || '';
  form.default_referer = app.settings.scanner.default_referer || '';
}

onMounted(async () => {
  await Promise.all([app.loadScans(), app.loadSettings()]);
  applySettingsDefaults();
});

const modeDescriptions = {
  quick: 'Recommended for broad coverage: standard headers, one Host-only request, and six high-value raw variants.',
  full: 'Every enabled payload in the Payload workspace. Use after quick mode identifies promising targets.',
};

const finishedStatuses = new Set(['completed', 'failed', 'stopped']);

const queueStats = computed(() => ({
  total: app.scans.length,
  running: app.scans.filter((scan) => scan.status === 'running').length,
  waiting: app.scans.filter((scan) => scan.status === 'waiting_callback').length,
  hits: app.scans.filter((scan) => (scan.pingback_count || 0) > 0).length,
  finished: app.scans.filter((scan) => finishedStatuses.has(scan.status)).length,
}));

const batchDeletableScanIDs = computed(() =>
  app.scans.filter((scan) => finishedStatuses.has(scan.status)).map((scan) => scan.id),
);

const selectedBatchDeleteIDs = computed(() =>
  selectedScanIds.value.filter((id) => batchDeletableScanIDs.value.includes(id)),
);

const allFinishedSelected = computed(() =>
  batchDeletableScanIDs.value.length > 0 &&
  selectedBatchDeleteIDs.value.length === batchDeletableScanIDs.value.length,
);

const activeLogs = computed(() => {
  const selected = selectedLogScan.value;
  return [...ws.logs]
    .filter((entry) => !selected || entry.scan_id === selected)
    .slice(-80)
    .reverse();
});

watch(() => app.scans, () => {
  const liveIDs = new Set(app.scans.map((scan) => scan.id));
  selectedScanIds.value = selectedScanIds.value.filter((id) => liveIDs.has(id));
  if (selectedLogScan.value && !liveIDs.has(selectedLogScan.value)) {
    selectedLogScan.value = '';
  }
}, { deep: true });

async function startScan() {
  submitting.value = true;
  try {
    const targets = form.targets.split('\n').map((item) => item.trim()).filter(Boolean);
    if (!targets.length) {
      toast.error('Please enter at least one target URL');
      return;
    }

    let customHeaders = {};
    if (form.custom_headers.trim()) {
      try { customHeaders = JSON.parse(form.custom_headers); }
      catch { toast.error('Custom headers must be valid JSON'); return; }
    }

    const scan = await api.createScan({
      targets,
      mode: form.mode,
      concurrency: Number(form.concurrency),
      batch_size: Number(form.batch_size),
      rate_limit: Number(form.rate_limit),
      callback_timeout_minutes: Number(form.callback_timeout_minutes),
      proxy: form.proxy,
      default_origin: form.default_origin,
      default_referer: form.default_referer,
      custom_headers: customHeaders,
    });

    selectedLogScan.value = scan.id;
    toast.success(`Scan started with ${targets.length} target(s) in batches of ${Number(form.batch_size) || 1500}`);
    await app.refreshAll();
  } catch (e) {
    toast.error(e.message);
  } finally {
    submitting.value = false;
  }
}

async function stopScan(id) {
  try {
    await api.stopScan(id);
    selectedLogScan.value = id;
    toast.info('Scan stop requested');
    await app.loadScans();
  } catch (e) {
    toast.error(e.message);
  }
}

async function deleteScan(id) {
  try {
    await api.deleteScan(id);
    toast.success('Scan deleted');
    confirmDelete.value = null;
    confirmBatchDelete.value = false;
    selectedScanIds.value = selectedScanIds.value.filter((scanID) => scanID !== id);
    if (selectedLogScan.value === id) selectedLogScan.value = '';
    await app.refreshAll();
  } catch (e) {
    toast.error(e.message);
  }
}

async function deleteSelectedScans() {
  if (!selectedBatchDeleteIDs.value.length) {
    toast.error('Select at least one finished scan');
    return;
  }

  try {
    const result = await api.deleteScans(selectedBatchDeleteIDs.value);
    const deletedIDs = Array.isArray(result.deleted_ids) ? result.deleted_ids : [];
    const skippedCount = Number(result.skipped_count || 0);

    selectedScanIds.value = selectedScanIds.value.filter((id) => !deletedIDs.includes(id));
    if (selectedLogScan.value && deletedIDs.includes(selectedLogScan.value)) {
      selectedLogScan.value = '';
    }
    confirmBatchDelete.value = false;
    confirmDelete.value = null;

    if (deletedIDs.length && skippedCount) {
      toast.success(`Deleted ${deletedIDs.length} finished scan(s), skipped ${skippedCount}.`);
    } else {
      toast.success(`Deleted ${deletedIDs.length} finished scan(s).`);
    }
    await app.refreshAll();
  } catch (e) {
    toast.error(e.message);
  }
}

function viewResults(id) {
  router.push({ name: 'results', query: { scan_task_id: id } });
}

function openDebug(id) {
  selectedLogScan.value = id;
  router.push({ name: 'debug', query: { scan_task_id: id } });
}

function selectLogScan(id) {
  selectedLogScan.value = selectedLogScan.value === id ? '' : id;
}

function toggleScanSelection(id) {
  if (selectedScanIds.value.includes(id)) {
    selectedScanIds.value = selectedScanIds.value.filter((scanID) => scanID !== id);
    return;
  }
  selectedScanIds.value = [...selectedScanIds.value, id];
}

function toggleAllFinishedScans() {
  if (allFinishedSelected.value) {
    selectedScanIds.value = selectedScanIds.value.filter((id) => !batchDeletableScanIDs.value.includes(id));
    return;
  }
  selectedScanIds.value = Array.from(new Set([...selectedScanIds.value, ...batchDeletableScanIDs.value]));
}

function clearSelectedScans() {
  selectedScanIds.value = [];
  confirmBatchDelete.value = false;
}

function isScanSelected(id) {
  return selectedScanIds.value.includes(id);
}

function isFinishedScan(scan) {
  return finishedStatuses.has(scan.status);
}

function statusClass(status) {
  return `badge badge-${status || 'pending'}`;
}

function progressPercent(scan) {
  const total = scan._total || scan.estimated_requests || 0;
  if (!total) return null;
  return Math.round((scan.request_sent / total) * 100);
}

function targetPercent(scan) {
  if (!scan.target_count || scan.target_count === 0) return null;
  return Math.round(((scan.completed_targets || 0) / scan.target_count) * 100);
}

function formatTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

function shortId(id) {
  return id?.substring(0, 8) || '-';
}

function trimText(value, max = 72) {
  if (!value) return '-';
  return value.length > max ? `${value.slice(0, max)}...` : value;
}
</script>

<template>
  <div class="scans-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Scan planner</h2>
          <p>Queue large target lists in quick-mode batches. The backend runs each batch in sequence and streams progress through the live log.</p>
        </div>
        <div class="inline-actions">
          <button class="ghost-button" @click="showForm = !showForm">{{ showForm ? 'Hide form' : 'Show form' }}</button>
          <button class="ghost-button" @click="app.loadScans()">Refresh queue</button>
        </div>
      </div>

      <div class="stat-strip">
        <div class="stat-block"><span>Total jobs</span><strong>{{ queueStats.total }}</strong></div>
        <div class="stat-block"><span>Running</span><strong>{{ queueStats.running }}</strong></div>
        <div class="stat-block"><span>Waiting callback</span><strong>{{ queueStats.waiting }}</strong></div>
        <div class="stat-block"><span>Finished</span><strong>{{ queueStats.finished }}</strong></div>
      </div>

      <div class="hint-strip" style="margin-top: 18px">
        <span><code>Quick</code> is the default fleet-wide mode for all targets</span>
        <span>Use <code>batch_size</code> to cap each dispatch wave at roughly <code>1500</code> hosts</span>
        <span>Batch delete only targets <code>completed</code>, <code>failed</code>, and <code>stopped</code> jobs</span>
      </div>

      <div v-if="showForm" class="form-grid" style="margin-top: 18px">
        <div class="form-group form-span-12">
          <label>Targets</label>
          <textarea v-model="form.targets" rows="7" placeholder="https://app.example.com&#10;https://api.example.com&#10;https://admin.example.com"></textarea>
        </div>
        <div class="form-group form-span-3"><label>Scan type</label><select v-model="form.mode"><option value="quick">Quick</option><option value="full">Full</option></select><small>{{ modeDescriptions[form.mode] }}</small></div>
        <div class="form-group form-span-3"><label>Concurrency</label><input v-model.number="form.concurrency" type="number" min="1" max="500" /></div>
        <div class="form-group form-span-3"><label>Batch size</label><input v-model.number="form.batch_size" type="number" min="1" max="5000" /><small>Recommended: 1000-1500 live targets per batch.</small></div>
        <div class="form-group form-span-3"><label>Rate limit (QPS)</label><input v-model.number="form.rate_limit" type="number" min="0" /></div>
        <div class="form-group form-span-4"><label>Callback timeout (minutes)</label><input v-model.number="form.callback_timeout_minutes" type="number" min="1" /></div>
        <div class="form-group form-span-4"><label>Default origin</label><input v-model="form.default_origin" placeholder="https://example.com" /></div>
        <div class="form-group form-span-4"><label>Default referer</label><input v-model="form.default_referer" placeholder="https://example.com/" /></div>
        <div class="form-group form-span-6"><label>Proxy</label><input v-model="form.proxy" placeholder="http://127.0.0.1:8080 or socks5://127.0.0.1:1080" /></div>
        <div class="form-group form-span-6"><label>Custom headers</label><textarea v-model="form.custom_headers" rows="3" placeholder='{"Cookie":"session=abc","Authorization":"Bearer token"}'></textarea></div>
        <div class="form-actions form-span-12"><button class="ghost-button" @click="showForm = false">Collapse</button><button class="primary" :disabled="submitting" @click="startScan">{{ submitting ? 'Starting...' : 'Start scan' }}</button></div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Scan queue</h2>
          <p>Track batch dispatch, current target, target completion, request volume, and callback hits from one table.</p>
        </div>
        <div class="inline-actions">
          <button class="ghost-button" @click="toggleAllFinishedScans()">{{ allFinishedSelected ? 'Unselect finished' : 'Select finished' }}</button>
          <button class="ghost-button" :disabled="!selectedScanIds.length" @click="clearSelectedScans">Clear selection</button>
          <button v-if="confirmBatchDelete" class="btn-danger" :disabled="!selectedBatchDeleteIDs.length" @click="deleteSelectedScans">Confirm delete {{ selectedBatchDeleteIDs.length }}</button>
          <button v-else class="ghost-button" :disabled="!selectedBatchDeleteIDs.length" @click="confirmBatchDelete = true">Delete selected {{ selectedBatchDeleteIDs.length }}</button>
        </div>
      </div>

      <div class="table-shell" v-if="app.scans.length">
        <table>
          <thead><tr><th class="fit"><input :checked="allFinishedSelected" type="checkbox" @change="toggleAllFinishedScans" /></th><th>ID</th><th>Status</th><th>Mode</th><th>Batch</th><th>Targets</th><th>Requests</th><th>Current</th><th>Pingbacks</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody>
            <tr v-for="scan in app.scans" :key="scan.id" :class="{ selected: selectedLogScan === scan.id }" @click="selectLogScan(scan.id)">
              <td class="fit">
                <input
                  v-if="isFinishedScan(scan)"
                  :checked="isScanSelected(scan.id)"
                  type="checkbox"
                  @click.stop
                  @change="toggleScanSelection(scan.id)"
                />
                <span v-else class="muted">-</span>
              </td>
              <td class="mono">{{ shortId(scan.id) }}</td>
              <td><span :class="statusClass(scan.status)">{{ scan.status }}</span></td>
              <td>{{ scan.mode }}</td>
              <td>
                <div class="mono">{{ scan.current_batch || 0 }}/{{ scan.batch_count || 0 }}</div>
                <div class="muted">size {{ scan.batch_size || '-' }}</div>
              </td>
              <td>
                <div class="mono">{{ scan.completed_targets || 0 }}/{{ scan.target_count }}</div>
                <div v-if="targetPercent(scan) !== null" class="scan-progress"><div class="progress-bar" :style="{ width: targetPercent(scan) + '%' }"></div></div>
              </td>
              <td>
                <div class="mono">{{ scan.request_sent }}</div>
                <div v-if="progressPercent(scan) !== null" class="scan-progress"><div class="progress-bar" :style="{ width: progressPercent(scan) + '%' }"></div></div>
              </td>
              <td>
                <div class="mono">{{ scan.current_stage || '-' }}</div>
                <div class="muted" :title="scan.current_target || ''">{{ trimText(scan.current_target) }}</div>
              </td>
              <td><span v-if="scan.pingback_count" class="badge badge-high">{{ scan.pingback_count }}</span><span v-else class="muted">0</span></td>
              <td class="mono">{{ formatTime(scan.created_at) }}</td>
              <td><div class="action-row"><button class="icon-button" @click.stop="viewResults(scan.id)">Open</button><button class="icon-button" @click.stop="openDebug(scan.id)">Live log</button><button v-if="scan.status === 'running' || scan.status === 'waiting_callback'" class="icon-button" @click.stop="stopScan(scan.id)">Stop</button><button v-if="confirmDelete === scan.id" class="btn-danger" @click.stop="deleteScan(scan.id)">Confirm delete</button><button v-else class="icon-button" @click.stop="confirmDelete = scan.id">Delete</button></div></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state"><strong>No scan jobs yet.</strong><p class="muted">Use the planner above to queue the first quick batch scan.</p></div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Live activity</h2>
          <p>Structured log-style progress. Filter implicitly by selecting a scan row above, or leave it empty to watch all active tasks.</p>
        </div>
        <div class="inline-actions">
          <span class="badge" :class="ws.connected ? 'badge-low' : 'badge-critical'">{{ ws.connected ? 'socket online' : 'socket offline' }}</span>
          <button class="ghost-button" @click="selectedLogScan = ''">Show all</button>
        </div>
      </div>
      <div class="live-log">
        <div v-if="!activeLogs.length" class="empty-state">No log entries yet.</div>
        <div v-for="entry in activeLogs" :key="entry.id" class="live-log-entry">
          <span class="mono live-log-time">{{ shortId(entry.scan_id || '') }}</span>
          <span class="badge" :class="`badge-${entry.level || 'info'}`">{{ (entry.level || 'info').toUpperCase() }}</span>
          <span class="muted live-log-msg">{{ entry.message }}</span>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.live-log { display: flex; flex-direction: column; gap: 10px; max-height: 360px; overflow: auto; }
.live-log-entry { display: flex; align-items: flex-start; gap: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,.08); }
.live-log-entry:first-child { border-top: 0; padding-top: 0; }
.live-log-time { min-width: 64px; }
.live-log-msg { word-break: break-word; line-height: 1.45; }
tbody tr.selected { background: rgba(186, 235, 255, 0.06); }
</style>
