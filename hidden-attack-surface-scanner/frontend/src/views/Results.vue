<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/index.js';

const route = useRoute();
const filters = reactive({ severity: '', protocol: '', scan_task_id: '', search: '' });
const expandedId = ref(null);
const pingbacks = ref([]);
const loading = ref(false);

onMounted(async () => { if (route.query.scan_task_id) filters.scan_task_id = route.query.scan_task_id; await loadData(); });
watch(filters, () => loadData(), { deep: true });
async function loadData() {
  loading.value = true;
  try { pingbacks.value = await api.listPingbacks({ severity: filters.severity, protocol: filters.protocol, scan_task_id: filters.scan_task_id }); }
  catch { pingbacks.value = []; }
  loading.value = false;
}

const filtered = computed(() => !filters.search ? pingbacks.value : pingbacks.value.filter((item) => [item.target_url, item.payload_key, item.payload_value, item.remote_address, item.callback_protocol, item.severity].join(' ').toLowerCase().includes(filters.search.toLowerCase())));
const summaryStats = computed(() => { const summary = { total: filtered.value.length, critical: 0, high: 0, medium: 0, low: 0 }; filtered.value.forEach((item) => { if (summary[item.severity] !== undefined) summary[item.severity] += 1; }); return summary; });
const ownIPCount = computed(() => filtered.value.filter((item) => item.from_own_ip).length);
function toggle(id) { expandedId.value = expandedId.value === id ? null : id; }
function formatTime(value) { if (!value) return '-'; return new Date(value).toLocaleString(); }
function sevClass(value) { return `badge badge-${value || 'info'}`; }
function protoClass(value) { return `badge protocol-${value || 'unknown'}`; }
function exportJSON() { const blob = new Blob([JSON.stringify(filtered.value, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'pingbacks.json'; anchor.click(); URL.revokeObjectURL(url); }
function exportCSV() { if (!filtered.value.length) return; const headers = Object.keys(filtered.value[0]); const rows = filtered.value.map((item) => headers.map((header) => JSON.stringify(item[header] ?? '')).join(',')); const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv' }); const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'pingbacks.csv'; anchor.click(); URL.revokeObjectURL(url); }
</script>

<template>
  <div class="results-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Callback evidence</h2>
          <p>Filter by scan, protocol, and severity, then expand a row to inspect the exact payload that produced the hit.</p>
        </div>
        <div class="action-row"><button class="ghost-button" @click="exportJSON">Export JSON</button><button class="ghost-button" @click="exportCSV">Export CSV</button></div>
      </div>

      <div class="stat-strip">
        <div class="stat-block"><span>Visible results</span><strong>{{ summaryStats.total }}</strong></div>
        <div class="stat-block"><span>Critical</span><strong>{{ summaryStats.critical }}</strong></div>
        <div class="stat-block"><span>High</span><strong>{{ summaryStats.high }}</strong></div>
        <div class="stat-block"><span>Own IP marked</span><strong>{{ ownIPCount }}</strong></div>
      </div>

      <div class="filter-grid" style="margin-top: 18px">
        <div class="form-group form-span-6"><label>Search</label><input v-model="filters.search" placeholder="Search target, payload key, value, callback IP, or severity" /></div>
        <div class="form-group form-span-2"><label>Severity</label><select v-model="filters.severity"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
        <div class="form-group form-span-2"><label>Protocol</label><select v-model="filters.protocol"><option value="">All</option><option value="dns">DNS</option><option value="http">HTTP</option><option value="smtp">SMTP</option><option value="ldap">LDAP</option><option value="ftp">FTP</option></select></div>
        <div class="form-group form-span-2"><label>Scan task</label><input v-model="filters.scan_task_id" placeholder="Optional scan id" /></div>
      </div>
    </section>

    <section class="panel" style="padding-top: 0">
      <div class="table-shell" v-if="filtered.length">
        <table>
          <thead><tr><th class="fit">Open</th><th>Time</th><th>Protocol</th><th>Payload</th><th>Target</th><th>Remote IP</th><th>Severity</th><th>Delay</th><th>Own IP</th></tr></thead>
          <tbody>
            <template v-for="item in filtered" :key="item.id">
              <tr @click="toggle(item.id)">
                <td class="fit">{{ expandedId === item.id ? 'Hide' : 'Open' }}</td>
                <td class="mono">{{ formatTime(item.received_at) }}</td>
                <td><span :class="protoClass(item.callback_protocol)">{{ item.callback_protocol }}</span></td>
                <td class="mono">{{ item.payload_key }}</td>
                <td class="mono truncate">{{ item.target_url }}</td>
                <td class="mono">{{ item.remote_address }}</td>
                <td><span :class="sevClass(item.severity)">{{ item.severity }}</span></td>
                <td>{{ item.delay_seconds ? item.delay_seconds.toFixed(1) + 's' : '-' }}</td>
                <td>{{ item.from_own_ip ? 'Yes' : 'No' }}</td>
              </tr>
              <tr v-if="expandedId === item.id"><td colspan="9"><div class="detail-panel"><div class="detail-row"><span class="detail-label">Pingback ID</span><span class="detail-value mono">{{ item.id }}</span></div><div class="detail-row"><span class="detail-label">Unique ID</span><span class="detail-value mono">{{ item.unique_id }}</span></div><div class="detail-row"><span class="detail-label">Scan task</span><span class="detail-value mono">{{ item.scan_task_id }}</span></div><div class="detail-row"><span class="detail-label">Payload type</span><span class="detail-value">{{ item.payload_type }}</span></div><div class="detail-row"><span class="detail-label">Payload key</span><span class="detail-value mono">{{ item.payload_key }}</span></div><div class="detail-row"><span class="detail-label">Payload value</span><span class="detail-value mono">{{ item.payload_value }}</span></div><div class="detail-row"><span class="detail-label">Target URL</span><span class="detail-value mono">{{ item.target_url }}</span></div><div class="detail-row"><span class="detail-label">Callback protocol</span><span class="detail-value"><span :class="protoClass(item.callback_protocol)">{{ item.callback_protocol }}</span></span></div><div class="detail-row"><span class="detail-label">Remote address</span><span class="detail-value mono">{{ item.remote_address }}</span></div><div class="detail-row" v-if="item.reverse_dns"><span class="detail-label">Reverse DNS</span><span class="detail-value mono">{{ item.reverse_dns }}</span></div><div class="detail-row" v-if="item.asn_info"><span class="detail-label">ASN info</span><span class="detail-value mono">{{ item.asn_info }}</span></div><div class="detail-row"><span class="detail-label">Sent at</span><span class="detail-value">{{ formatTime(item.sent_at) }}</span></div><div class="detail-row"><span class="detail-label">Received at</span><span class="detail-value">{{ formatTime(item.received_at) }}</span></div><div class="detail-row"><span class="detail-label">Delay</span><span class="detail-value">{{ item.delay_seconds ? item.delay_seconds.toFixed(2) + 's' : '-' }}</span></div><div class="detail-row" v-if="item.raw_request"><span class="detail-label">Raw callback</span><pre class="detail-value">{{ item.raw_request }}</pre></div></div></td></tr>
            </template>
          </tbody>
        </table>
      </div>
      <div v-else-if="loading" class="results-empty"><strong>Loading callback data.</strong><p class="muted">Fetching the latest pingbacks from the backend.</p></div>
      <div v-else class="results-empty"><strong>No pingbacks match the current filters.</strong><p class="muted">If you expected a hit, confirm the target really issued an outbound request and the polling window is still open.</p></div>
    </section>
  </div>
</template>
