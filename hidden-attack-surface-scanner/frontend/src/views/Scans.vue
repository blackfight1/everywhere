<script setup>
import { reactive, ref, computed, onMounted } from 'vue';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';
import { useToastStore } from '../stores/toast.js';
import { useRouter } from 'vue-router';

const app = useAppStore();
const toast = useToastStore();
const router = useRouter();

const showForm = ref(false);
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

onMounted(() => { app.loadScans(); });

const modeDescriptions = {
  quick: 'Standard active headers only (~27 headers merged into 1 request per target)',
  full: 'All standard headers + URL params (~48 payloads, ~16 requests per target)',
  cracking: 'Full + Cracking the Lens raw payloads (~60 payloads, ~25 requests per target)',
  custom: 'Only manually enabled payloads in the Payloads tab',
};

async function startScan() {
  submitting.value = true;
  try {
    const targets = form.targets.split('\n').map(t => t.trim()).filter(Boolean);
    if (!targets.length) { toast.error('Please enter at least one target URL'); return; }

    let customHeaders = {};
    if (form.custom_headers.trim()) {
      try { customHeaders = JSON.parse(form.custom_headers); }
      catch { toast.error('Custom headers must be valid JSON'); return; }
    }

    const payload = {
      targets,
      mode: form.mode,
      concurrency: Number(form.concurrency),
      rate_limit: Number(form.rate_limit),
      callback_timeout_minutes: Number(form.callback_timeout_minutes),
      proxy: form.proxy,
      default_origin: form.default_origin,
      default_referer: form.default_referer,
      custom_headers: customHeaders,
    };

    await api.createScan(payload);
    toast.success(`Scan started with ${targets.length} target(s) in ${form.mode} mode`);
    showForm.value = false;
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
    toast.info('Scan stop requested');
    await app.loadScans();
  } catch (e) { toast.error(e.message); }
}

async function deleteScan(id) {
  try {
    await api.deleteScan(id);
    toast.success('Scan deleted');
    confirmDelete.value = null;
    await app.refreshAll();
  } catch (e) { toast.error(e.message); }
}

function viewResults(id) {
  router.push({ name: 'results', query: { scan_task_id: id } });
}

function statusClass(status) {
  return `badge badge-${status || 'pending'}`;
}

function progressPercent(scan) {
  if (!scan._total || scan._total === 0) return null;
  return Math.round((scan.request_sent / scan._total) * 100);
}

function formatTime(t) {
  if (!t) return '-';
  return new Date(t).toLocaleString();
}

function shortId(id) {
  return id?.substring(0, 8) || '-';
}
</script>

<template>
  <div class="scans-page">
    <!-- Action Bar -->
    <div class="action-bar">
      <button class="primary" @click="showForm = !showForm">
        {{ showForm ? '✕ Close' : '+ New Scan' }}
      </button>
      <button class="ghost-button" @click="app.loadScans()">↻ Refresh</button>
    </div>

    <!-- Scan Form -->
    <transition name="tab-content">
      <div v-if="showForm" class="panel scan-form">
        <h2>Create New Scan</h2>

        <div class="form-group">
          <label>Target URLs <small class="muted">(one per line)</small></label>
          <textarea v-model="form.targets" rows="6" placeholder="https://example.com&#10;https://api.example.com&#10;https://admin.example.com"></textarea>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Scan Mode</label>
            <select v-model="form.mode">
              <option value="quick">Quick</option>
              <option value="full">Full</option>
              <option value="cracking">Cracking the Lens</option>
              <option value="custom">Custom</option>
            </select>
            <small class="muted">{{ modeDescriptions[form.mode] }}</small>
          </div>

          <div class="form-group">
            <label>Concurrency</label>
            <input v-model.number="form.concurrency" type="number" min="1" max="500" />
          </div>

          <div class="form-group">
            <label>Rate Limit (QPS)</label>
            <input v-model.number="form.rate_limit" type="number" min="0" />
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Callback Timeout (min)</label>
            <input v-model.number="form.callback_timeout_minutes" type="number" min="1" />
          </div>

          <div class="form-group">
            <label>Proxy</label>
            <input v-model="form.proxy" placeholder="http://127.0.0.1:8080 or socks5://..." />
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Default Origin <small class="muted">(for %o placeholder)</small></label>
            <input v-model="form.default_origin" placeholder="https://example.com" />
          </div>
          <div class="form-group">
            <label>Default Referer <small class="muted">(for %r placeholder)</small></label>
            <input v-model="form.default_referer" placeholder="https://example.com/" />
          </div>
        </div>

        <div class="form-group">
          <label>Custom Headers <small class="muted">(JSON object, e.g. {"Cookie":"session=abc"})</small></label>
          <textarea v-model="form.custom_headers" rows="3" placeholder='{"Cookie": "session=abc123", "Authorization": "Bearer xxx"}'></textarea>
        </div>

        <div class="form-actions">
          <button class="ghost-button" @click="showForm = false">Cancel</button>
          <button class="primary" :disabled="submitting" @click="startScan">
            {{ submitting ? 'Starting...' : '🚀 Start Scan' }}
          </button>
        </div>
      </div>
    </transition>

    <!-- Scans Table -->
    <div class="panel">
      <h2>Scan Tasks</h2>
      <div class="table-shell" v-if="app.scans.length">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Status</th>
              <th>Mode</th>
              <th>Targets</th>
              <th>Sent</th>
              <th>Pingbacks</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="scan in app.scans" :key="scan.id">
              <td class="mono" :data-tooltip="scan.id">{{ shortId(scan.id) }}</td>
              <td><span :class="statusClass(scan.status)">{{ scan.status }}</span></td>
              <td>{{ scan.mode }}</td>
              <td>{{ scan.target_count }}</td>
              <td>
                {{ scan.request_sent }}
                <template v-if="progressPercent(scan) !== null">
                  <div class="scan-progress">
                    <div class="progress-bar" :style="{ width: progressPercent(scan) + '%' }"></div>
                  </div>
                </template>
              </td>
              <td>
                <span v-if="scan.pingback_count" class="badge badge-high">{{ scan.pingback_count }}</span>
                <span v-else class="muted">0</span>
              </td>
              <td class="mono">{{ formatTime(scan.created_at) }}</td>
              <td>
                <div class="action-row">
                  <button class="icon-button" data-tooltip="View results" @click="viewResults(scan.id)">📋</button>
                  <button
                    v-if="scan.status === 'running' || scan.status === 'waiting_callback'"
                    class="icon-button" data-tooltip="Stop scan"
                    @click="stopScan(scan.id)"
                  >⏹</button>
                  <button
                    v-if="confirmDelete === scan.id"
                    class="btn-danger btn-sm" @click="deleteScan(scan.id)"
                  >Confirm?</button>
                  <button
                    v-else class="icon-button" data-tooltip="Delete scan"
                    @click="confirmDelete = scan.id"
                  >🗑</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="empty-state" v-else>
        No scan tasks yet. Click "New Scan" to start.
      </div>
    </div>
  </div>
</template>

<style scoped>
.scans-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.action-bar {
  display: flex;
  gap: 10px;
}
.scan-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.scan-form h2 {
  margin-bottom: 0;
}
</style>
