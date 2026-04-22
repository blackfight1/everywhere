<script setup>
import { computed, onMounted, ref, reactive, watch } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';

const app = useAppStore();
const route = useRoute();

const filters = reactive({
  severity: '',
  protocol: '',
  scan_task_id: '',
  search: '',
});

const expandedId = ref(null);
const pingbacks = ref([]);
const loading = ref(false);

onMounted(async () => {
  if (route.query.scan_task_id) {
    filters.scan_task_id = route.query.scan_task_id;
  }
  await loadData();
});

watch(filters, () => loadData(), { deep: true });

async function loadData() {
  loading.value = true;
  try {
    pingbacks.value = await api.listPingbacks({
      severity: filters.severity,
      protocol: filters.protocol,
      scan_task_id: filters.scan_task_id,
    });
  } catch { /* ignore */ }
  loading.value = false;
}

const filtered = computed(() => {
  if (!filters.search) return pingbacks.value;
  const needle = filters.search.toLowerCase();
  return pingbacks.value.filter(p =>
    [p.target_url, p.payload_key, p.payload_value, p.remote_address, p.callback_protocol, p.severity]
      .join(' ').toLowerCase().includes(needle)
  );
});

const summaryStats = computed(() => {
  const s = { total: filtered.value.length, critical: 0, high: 0, medium: 0, low: 0 };
  filtered.value.forEach(p => { if (s[p.severity] !== undefined) s[p.severity]++; });
  return s;
});

function toggle(id) {
  expandedId.value = expandedId.value === id ? null : id;
}

function formatTime(t) {
  if (!t) return '-';
  return new Date(t).toLocaleString();
}

function sevClass(s) { return `badge badge-${s || 'info'}`; }
function protoClass(p) { return `badge protocol-${p || 'dns'}`; }
function shortId(id) { return id?.substring(0, 8) || '-'; }

function exportJSON() {
  const blob = new Blob([JSON.stringify(filtered.value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'pingbacks.json'; a.click();
  URL.revokeObjectURL(url);
}

function exportCSV() {
  if (!filtered.value.length) return;
  const headers = Object.keys(filtered.value[0]);
  const rows = filtered.value.map(p => headers.map(h => JSON.stringify(p[h] ?? '')).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'pingbacks.csv'; a.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <div class="results-page">
    <!-- Filters -->
    <div class="panel filter-panel">
      <div class="filter-grid">
        <div class="form-group">
          <label>Search</label>
          <input v-model="filters.search" placeholder="🔍 Filter by target, payload, IP..." />
        </div>
        <div class="form-group">
          <label>Severity</label>
          <select v-model="filters.severity">
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div class="form-group">
          <label>Protocol</label>
          <select v-model="filters.protocol">
            <option value="">All</option>
            <option value="dns">DNS</option>
            <option value="http">HTTP</option>
            <option value="smtp">SMTP</option>
            <option value="ldap">LDAP</option>
            <option value="ftp">FTP</option>
          </select>
        </div>
        <div class="form-group">
          <label>Scan Task ID</label>
          <input v-model="filters.scan_task_id" placeholder="Filter by scan..." />
        </div>
      </div>

      <div class="filter-summary">
        <span class="badge badge-info">{{ summaryStats.total }} results</span>
        <span class="badge badge-critical" v-if="summaryStats.critical">{{ summaryStats.critical }} critical</span>
        <span class="badge badge-high" v-if="summaryStats.high">{{ summaryStats.high }} high</span>
        <span class="badge badge-medium" v-if="summaryStats.medium">{{ summaryStats.medium }} medium</span>
        <span class="badge badge-low" v-if="summaryStats.low">{{ summaryStats.low }} low</span>
        <div class="filter-actions">
          <button class="ghost-button btn-sm" @click="exportJSON">📥 JSON</button>
          <button class="ghost-button btn-sm" @click="exportCSV">📥 CSV</button>
        </div>
      </div>
    </div>

    <!-- Results Table -->
    <div class="panel">
      <div class="table-shell" v-if="filtered.length">
        <table>
          <thead>
            <tr>
              <th class="fit"></th>
              <th>Time</th>
              <th>Protocol</th>
              <th>Payload Key</th>
              <th>Target</th>
              <th>Remote IP</th>
              <th>Severity</th>
              <th>Delay</th>
              <th>Own IP</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="item in filtered" :key="item.id">
              <tr class="result-row" :class="{ expanded: expandedId === item.id }" @click="toggle(item.id)">
                <td class="fit">{{ expandedId === item.id ? '▼' : '▶' }}</td>
                <td class="mono">{{ formatTime(item.received_at) }}</td>
                <td><span :class="protoClass(item.callback_protocol)">{{ item.callback_protocol }}</span></td>
                <td class="mono">{{ item.payload_key }}</td>
                <td class="mono truncate">{{ item.target_url }}</td>
                <td class="mono">{{ item.remote_address }}</td>
                <td><span :class="sevClass(item.severity)">{{ item.severity }}</span></td>
                <td>{{ item.delay_seconds ? item.delay_seconds.toFixed(1) + 's' : '-' }}</td>
                <td>{{ item.from_own_ip ? '⚠️ Yes' : '—' }}</td>
              </tr>
              <tr v-if="expandedId === item.id" class="detail-expand">
                <td colspan="9">
                  <div class="detail-panel">
                    <div class="detail-row">
                      <span class="detail-label">Pingback ID</span>
                      <span class="detail-value mono">{{ item.id }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Unique ID</span>
                      <span class="detail-value mono">{{ item.unique_id }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Scan Task</span>
                      <span class="detail-value mono">{{ item.scan_task_id }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Payload Type</span>
                      <span class="detail-value">{{ item.payload_type }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Payload Key</span>
                      <span class="detail-value mono">{{ item.payload_key }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Payload Value</span>
                      <span class="detail-value mono">{{ item.payload_value }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Target URL</span>
                      <span class="detail-value mono">{{ item.target_url }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Callback Protocol</span>
                      <span class="detail-value"><span :class="protoClass(item.callback_protocol)">{{ item.callback_protocol }}</span></span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Remote Address</span>
                      <span class="detail-value mono">{{ item.remote_address }}</span>
                    </div>
                    <div class="detail-row" v-if="item.reverse_dns">
                      <span class="detail-label">Reverse DNS</span>
                      <span class="detail-value mono">{{ item.reverse_dns }}</span>
                    </div>
                    <div class="detail-row" v-if="item.asn_info">
                      <span class="detail-label">ASN Info</span>
                      <span class="detail-value mono">{{ item.asn_info }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Sent At</span>
                      <span class="detail-value">{{ formatTime(item.sent_at) }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Received At</span>
                      <span class="detail-value">{{ formatTime(item.received_at) }}</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Delay</span>
                      <span class="detail-value">{{ item.delay_seconds ? item.delay_seconds.toFixed(2) + 's' : '-' }}</span>
                    </div>
                    <div class="detail-row" v-if="item.raw_request">
                      <span class="detail-label">Raw Callback</span>
                      <pre class="detail-value">{{ item.raw_request }}</pre>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
      <div class="empty-state" v-else-if="loading">Loading...</div>
      <div class="empty-state" v-else>No pingbacks found matching filters.</div>
    </div>
  </div>
</template>

<style scoped>
.results-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.filter-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.filter-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}
.filter-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.filter-actions {
  margin-left: auto;
  display: flex;
  gap: 6px;
}
.result-row {
  cursor: pointer;
}
.result-row:hover {
  background: var(--bg-active) !important;
}
.result-row.expanded {
  background: var(--bg-hover);
}
.truncate {
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.detail-expand > td {
  padding: 0 12px 12px;
  border-bottom: 2px solid var(--accent);
}
</style>
