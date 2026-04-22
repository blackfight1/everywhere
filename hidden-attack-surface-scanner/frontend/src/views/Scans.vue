<script setup>
import { reactive, ref, onMounted, computed } from 'vue';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';
import { useToastStore } from '../stores/toast.js';
import { useRouter } from 'vue-router';

const app = useAppStore();
const toast = useToastStore();
const router = useRouter();
const showForm = ref(true);
const submitting = ref(false);
const confirmDelete = ref(null);

const form = reactive({
  targets: '',
  mode: 'quick',
  concurrency: 10,
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
  quick: '1 merged default request + 1 dedicated Host override request per target.',
  full: 'All active standard payloads, while Host remains isolated in its own request.',
  cracking: 'Full mode plus any enabled raw Cracking the Lens variants.',
  custom: 'Use only the payloads currently enabled in the Payloads workspace.',
};

const queueStats = computed(() => ({
  total: app.scans.length,
  running: app.scans.filter((scan) => scan.status === 'running').length,
  waiting: app.scans.filter((scan) => scan.status === 'waiting_callback').length,
  hits: app.scans.filter((scan) => (scan.pingback_count || 0) > 0).length,
}));

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

    await api.createScan({
      targets,
      mode: form.mode,
      concurrency: Number(form.concurrency),
      rate_limit: Number(form.rate_limit),
      callback_timeout_minutes: Number(form.callback_timeout_minutes),
      proxy: form.proxy,
      default_origin: form.default_origin,
      default_referer: form.default_referer,
      custom_headers: customHeaders,
    });

    toast.success(`Scan started with ${targets.length} target(s)`);
    await app.refreshAll();
    router.push({ name: 'results' });
  } catch (e) {
    toast.error(e.message);
  } finally {
    submitting.value = false;
  }
}

async function stopScan(id) {
  try { await api.stopScan(id); toast.info('Scan stop requested'); await app.loadScans(); }
  catch (e) { toast.error(e.message); }
}

async function deleteScan(id) {
  try { await api.deleteScan(id); toast.success('Scan deleted'); confirmDelete.value = null; await app.refreshAll(); }
  catch (e) { toast.error(e.message); }
}

function viewResults(id) { router.push({ name: 'results', query: { scan_task_id: id } }); }
function statusClass(status) { return `badge badge-${status || 'pending'}`; }
function progressPercent(scan) { if (!scan._total || scan._total === 0) return null; return Math.round((scan.request_sent / scan._total) * 100); }
function formatTime(value) { if (!value) return '-'; return new Date(value).toLocaleString(); }
function shortId(id) { return id?.substring(0, 8) || '-'; }
</script>

<template>
  <div class="scans-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Scan planner</h2>
          <p>Define targets, dispatch mode, and callback window before the backend starts sending requests.</p>
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
        <div class="stat-block"><span>Jobs with hits</span><strong>{{ queueStats.hits }}</strong></div>
      </div>

      <div v-if="showForm" class="form-grid" style="margin-top: 18px">
        <div class="form-group form-span-12">
          <label>Targets</label>
          <textarea v-model="form.targets" rows="7" placeholder="https://app.example.com&#10;https://api.example.com&#10;https://admin.example.com"></textarea>
        </div>
        <div class="form-group form-span-4"><label>Mode</label><select v-model="form.mode"><option value="quick">Quick</option><option value="full">Full</option><option value="cracking">Cracking</option><option value="custom">Custom</option></select><small>{{ modeDescriptions[form.mode] }}</small></div>
        <div class="form-group form-span-4"><label>Concurrency</label><input v-model.number="form.concurrency" type="number" min="1" max="500" /></div>
        <div class="form-group form-span-4"><label>Rate limit (QPS)</label><input v-model.number="form.rate_limit" type="number" min="0" /></div>
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
          <p>Each row tracks request dispatch, callback hits, and the current lifecycle state.</p>
        </div>
      </div>

      <div class="table-shell" v-if="app.scans.length">
        <table>
          <thead><tr><th>ID</th><th>Status</th><th>Mode</th><th>Targets</th><th>Requests</th><th>Pingbacks</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody>
            <tr v-for="scan in app.scans" :key="scan.id">
              <td class="mono">{{ shortId(scan.id) }}</td>
              <td><span :class="statusClass(scan.status)">{{ scan.status }}</span></td>
              <td>{{ scan.mode }}</td>
              <td>{{ scan.target_count }}</td>
              <td><div class="mono">{{ scan.request_sent }}</div><div v-if="progressPercent(scan) !== null" class="scan-progress"><div class="progress-bar" :style="{ width: progressPercent(scan) + '%' }"></div></div></td>
              <td><span v-if="scan.pingback_count" class="badge badge-high">{{ scan.pingback_count }}</span><span v-else class="muted">0</span></td>
              <td class="mono">{{ formatTime(scan.created_at) }}</td>
              <td><div class="action-row"><button class="icon-button" @click="viewResults(scan.id)">Open</button><button v-if="scan.status === 'running' || scan.status === 'waiting_callback'" class="icon-button" @click="stopScan(scan.id)">Stop</button><button v-if="confirmDelete === scan.id" class="btn-danger" @click="deleteScan(scan.id)">Confirm delete</button><button v-else class="icon-button" @click="confirmDelete = scan.id">Delete</button></div></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state"><strong>No scan jobs yet.</strong><p class="muted">Use the planner above to queue the first scan.</p></div>
    </section>
  </div>
</template>
