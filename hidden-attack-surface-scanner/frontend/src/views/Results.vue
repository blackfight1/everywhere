<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/index.js';

const route = useRoute();
const filters = reactive({ severity: '', protocol: '', scan_task_id: '', search: '' });
const expandedId = ref(null);
const pingbacks = ref([]);
const loading = ref(false);

const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };

onMounted(async () => {
  if (route.query.scan_task_id) filters.scan_task_id = route.query.scan_task_id;
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
  } catch {
    pingbacks.value = [];
  }
  loading.value = false;
}

const grouped = computed(() => {
  const groups = new Map();
  for (const item of pingbacks.value) {
    const key = item.unique_id || item.id;
    if (!groups.has(key)) {
      groups.set(key, {
        id: key,
        unique_id: item.unique_id,
        scan_task_id: item.scan_task_id,
        target_url: item.target_url,
        payload_type: item.payload_type,
        payload_key: item.payload_key,
        payload_value: item.payload_value,
        severity: item.severity,
        latest_received_at: item.received_at,
        sent_at: item.sent_at,
        from_own_ip: item.from_own_ip,
        events: [],
      });
    }

    const group = groups.get(key);
    group.events.push(item);

    if (new Date(item.received_at || 0).getTime() > new Date(group.latest_received_at || 0).getTime()) {
      group.latest_received_at = item.received_at;
    }
    if ((severityRank[item.severity] || 0) > (severityRank[group.severity] || 0)) {
      group.severity = item.severity;
    }
    if (item.from_own_ip) {
      group.from_own_ip = true;
    }
  }

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      events: [...group.events].sort((a, b) => new Date(b.received_at || 0) - new Date(a.received_at || 0)),
    }))
    .sort((a, b) => new Date(b.latest_received_at || 0) - new Date(a.latest_received_at || 0));
});

const filteredGroups = computed(() => {
  const needle = filters.search.trim().toLowerCase();
  if (!needle) return grouped.value;

  return grouped.value.filter((group) =>
    [
      group.target_url,
      group.payload_key,
      group.payload_value,
      group.payload_type,
      group.severity,
      group.unique_id,
      ...group.events.flatMap((event) => [
        event.callback_protocol,
        event.remote_address,
        event.reverse_dns,
        event.raw_request,
      ]),
    ]
      .join(' ')
      .toLowerCase()
      .includes(needle)
  );
});

const visibleEvents = computed(() => filteredGroups.value.flatMap((group) => group.events));

const summaryStats = computed(() => {
  const summary = { total: filteredGroups.value.length, critical: 0, high: 0, medium: 0, low: 0 };
  filteredGroups.value.forEach((group) => {
    if (summary[group.severity] !== undefined) summary[group.severity] += 1;
  });
  return summary;
});

const ownIPCount = computed(() => filteredGroups.value.filter((group) => group.from_own_ip).length);

function toggle(id) {
  expandedId.value = expandedId.value === id ? null : id;
}

function formatTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

function sevClass(value) {
  return `badge badge-${value || 'info'}`;
}

function protoClass(value) {
  return `badge protocol-${value || 'unknown'}`;
}

function protocolList(group) {
  return [...new Set(group.events.map((event) => event.callback_protocol).filter(Boolean))];
}

function remoteSummary(group) {
  const remotes = [...new Set(group.events.map((event) => event.remote_address).filter(Boolean))];
  if (!remotes.length) return '-';
  if (remotes.length === 1) return remotes[0];
  return `${remotes[0]} +${remotes.length - 1}`;
}

function delaySummary(group) {
  const values = group.events.map((event) => Number(event.delay_seconds || 0)).filter((value) => value > 0);
  if (!values.length) return '-';
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (Math.abs(min - max) < 0.05) return `${min.toFixed(1)}s`;
  return `${min.toFixed(1)}-${max.toFixed(1)}s`;
}

function exportJSON() {
  const blob = new Blob([JSON.stringify(visibleEvents.value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'pingbacks.json';
  anchor.click();
  URL.revokeObjectURL(url);
}

function exportCSV() {
  if (!visibleEvents.value.length) return;
  const headers = Object.keys(visibleEvents.value[0]);
  const rows = visibleEvents.value.map((item) => headers.map((header) => JSON.stringify(item[header] ?? '')).join(','));
  const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'pingbacks.csv';
  anchor.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <div class="results-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Callback evidence</h2>
          <p>Each row represents one payload. Expand it to inspect every callback recorded for that payload across DNS, HTTP, and HTTPS.</p>
        </div>
        <div class="action-row">
          <button class="ghost-button" @click="exportJSON">Export JSON</button>
          <button class="ghost-button" @click="exportCSV">Export CSV</button>
        </div>
      </div>

      <div class="stat-strip">
        <div class="stat-block"><span>Visible payloads</span><strong>{{ summaryStats.total }}</strong></div>
        <div class="stat-block"><span>Critical</span><strong>{{ summaryStats.critical }}</strong></div>
        <div class="stat-block"><span>High</span><strong>{{ summaryStats.high }}</strong></div>
        <div class="stat-block"><span>Own IP marked</span><strong>{{ ownIPCount }}</strong></div>
      </div>

      <div class="filter-grid" style="margin-top: 18px">
        <div class="form-group form-span-6"><label>Search</label><input v-model="filters.search" placeholder="Search payload, target, protocol, callback IP, or raw callback data" /></div>
        <div class="form-group form-span-2"><label>Severity</label><select v-model="filters.severity"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
        <div class="form-group form-span-2"><label>Protocol</label><select v-model="filters.protocol"><option value="">All</option><option value="dns">DNS</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="smtp">SMTP</option><option value="ldap">LDAP</option><option value="ftp">FTP</option></select></div>
        <div class="form-group form-span-2"><label>Scan task</label><input v-model="filters.scan_task_id" placeholder="Optional scan id" /></div>
      </div>
    </section>

    <section class="panel" style="padding-top: 0">
      <div class="table-shell" v-if="filteredGroups.length">
        <table>
          <thead><tr><th class="fit">Open</th><th>Time</th><th>Protocols</th><th>Payload</th><th>Target</th><th>Remote IPs</th><th>Severity</th><th>Delay</th><th>Own IP</th></tr></thead>
          <tbody>
            <template v-for="group in filteredGroups" :key="group.id">
              <tr @click="toggle(group.id)">
                <td class="fit">{{ expandedId === group.id ? 'Hide' : 'Open' }}</td>
                <td class="mono">{{ formatTime(group.latest_received_at) }}</td>
                <td>
                  <div class="protocol-bar">
                    <span v-for="protocol in protocolList(group)" :key="group.id + protocol" :class="protoClass(protocol)">{{ protocol }}</span>
                  </div>
                </td>
                <td class="mono">{{ group.payload_key }}</td>
                <td class="mono truncate">{{ group.target_url }}</td>
                <td class="mono">{{ remoteSummary(group) }}</td>
                <td><span :class="sevClass(group.severity)">{{ group.severity }}</span></td>
                <td>{{ delaySummary(group) }}</td>
                <td>{{ group.from_own_ip ? 'Yes' : 'No' }}</td>
              </tr>
              <tr v-if="expandedId === group.id">
                <td colspan="9">
                  <div class="detail-panel" style="margin-bottom: 16px">
                    <div class="detail-row"><span class="detail-label">Unique ID</span><span class="detail-value mono">{{ group.unique_id }}</span></div>
                    <div class="detail-row"><span class="detail-label">Scan task</span><span class="detail-value mono">{{ group.scan_task_id }}</span></div>
                    <div class="detail-row"><span class="detail-label">Payload type</span><span class="detail-value">{{ group.payload_type }}</span></div>
                    <div class="detail-row"><span class="detail-label">Payload key</span><span class="detail-value mono">{{ group.payload_key }}</span></div>
                    <div class="detail-row"><span class="detail-label">Payload value</span><span class="detail-value mono">{{ group.payload_value }}</span></div>
                    <div class="detail-row"><span class="detail-label">Target URL</span><span class="detail-value mono">{{ group.target_url }}</span></div>
                  </div>

                  <div class="event-stack">
                    <article v-for="event in group.events" :key="event.id" class="event-card">
                      <div class="event-card-header">
                        <div class="protocol-bar">
                          <span :class="protoClass(event.callback_protocol)">{{ event.callback_protocol }}</span>
                          <span :class="sevClass(event.severity)">{{ event.severity }}</span>
                        </div>
                        <strong class="mono">{{ formatTime(event.received_at) }}</strong>
                      </div>

                      <div class="detail-panel">
                        <div class="detail-row"><span class="detail-label">Pingback ID</span><span class="detail-value mono">{{ event.id }}</span></div>
                        <div class="detail-row"><span class="detail-label">Remote address</span><span class="detail-value mono">{{ event.remote_address }}</span></div>
                        <div class="detail-row" v-if="event.reverse_dns"><span class="detail-label">Reverse DNS</span><span class="detail-value mono">{{ event.reverse_dns }}</span></div>
                        <div class="detail-row" v-if="event.asn_info"><span class="detail-label">ASN info</span><span class="detail-value mono">{{ event.asn_info }}</span></div>
                        <div class="detail-row"><span class="detail-label">Sent at</span><span class="detail-value">{{ formatTime(event.sent_at) }}</span></div>
                        <div class="detail-row"><span class="detail-label">Delay</span><span class="detail-value">{{ event.delay_seconds ? event.delay_seconds.toFixed(2) + 's' : '-' }}</span></div>
                      </div>

                      <div v-if="event.raw_request" class="detail-row" style="margin-top: 14px">
                        <span class="detail-label">Raw callback</span>
                        <pre class="detail-value">{{ event.raw_request }}</pre>
                      </div>
                    </article>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
      <div v-else-if="loading" class="results-empty"><strong>Loading callback data.</strong><p class="muted">Fetching the latest pingbacks from the backend.</p></div>
      <div v-else class="results-empty"><strong>No pingbacks match the current filters.</strong><p class="muted">If you expected a hit, confirm the target really issued an outbound request and the polling window is still open.</p></div>
    </section>
  </div>
</template>
