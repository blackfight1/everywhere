<script setup>
import { computed, onMounted } from 'vue';
import { useAppStore } from '../stores/app.js';
import { useRouter } from 'vue-router';

const app = useAppStore();
const router = useRouter();

onMounted(async () => {
  await Promise.all([app.loadStats(), app.loadScans()]);
});

const activeScans = computed(() =>
  (app.scans || []).filter((scan) => ['pending', 'running', 'waiting_callback'].includes(scan.status)).slice(0, 6)
);

const recent = computed(() => app.stats.recent || []);

const severityBreakdown = computed(() => {
  const map = { critical: 0, high: 0, medium: 0, low: 0 };
  recent.value.forEach((item) => {
    if (map[item.severity] !== undefined) map[item.severity] += 1;
  });
  return map;
});

const protocolBreakdown = computed(() => {
  const map = {};
  recent.value.forEach((item) => {
    const key = item.callback_protocol || 'unknown';
    map[key] = (map[key] || 0) + 1;
  });
  return Object.entries(map);
});

function formatTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

function severityClass(value) {
  return `badge badge-${value || 'info'}`;
}

function protocolClass(value) {
  return `badge protocol-${value || 'unknown'}`;
}

function scanBadge(status) {
  return `badge badge-${status || 'pending'}`;
}
</script>

<template>
  <div class="dashboard-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Operations overview</h2>
          <p>Monitor scan volume, live callback pressure, and the jobs currently consuming bandwidth.</p>
        </div>
        <div class="inline-actions">
          <button class="ghost-button" @click="router.push('/scans')">Open scans</button>
          <button class="primary" @click="router.push('/results')">Review results</button>
        </div>
      </div>

      <div class="stat-strip">
        <div class="stat-block"><span>Total scans</span><strong>{{ app.stats.scan_count || 0 }}</strong></div>
        <div class="stat-block"><span>Active scans</span><strong>{{ app.stats.active_count || 0 }}</strong></div>
        <div class="stat-block"><span>Total pingbacks</span><strong>{{ app.stats.pingback_count || 0 }}</strong></div>
        <div class="stat-block"><span>Recent callbacks</span><strong>{{ recent.length }}</strong></div>
      </div>
    </section>

    <div class="workspace-grid">
      <section class="panel">
        <div class="panel-header">
          <div>
            <h2>Recent pingbacks</h2>
            <p>The latest callback evidence received by the backend.</p>
          </div>
          <button class="ghost-button" @click="router.push('/results')">View all</button>
        </div>

        <div class="table-shell" v-if="recent.length">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Protocol</th>
                <th>Payload</th>
                <th>Target</th>
                <th>Remote IP</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in recent" :key="item.id">
                <td class="mono">{{ formatTime(item.received_at) }}</td>
                <td><span :class="protocolClass(item.callback_protocol)">{{ item.callback_protocol }}</span></td>
                <td class="mono">{{ item.payload_key }}</td>
                <td class="mono truncate">{{ item.target_url }}</td>
                <td class="mono">{{ item.remote_address }}</td>
                <td><span :class="severityClass(item.severity)">{{ item.severity }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>No callback evidence yet.</strong>
          <p class="muted">Start a scan and wait for the polling window to capture outbound interactions.</p>
        </div>
      </section>

      <div class="stack-panel">
        <section class="panel">
          <div class="panel-header">
            <div>
              <h2>Live queue</h2>
              <p>Scans still dispatching requests or waiting for late callbacks.</p>
            </div>
          </div>

          <div class="stack-list" v-if="activeScans.length">
            <div v-for="scan in activeScans" :key="scan.id" class="list-row">
              <div class="list-main">
                <strong class="mono">{{ scan.id.slice(0, 8) }}</strong>
                <span class="list-meta">{{ scan.mode }} mode ¡¤ {{ scan.target_count }} targets</span>
              </div>
              <span :class="scanBadge(scan.status)">{{ scan.status }}</span>
            </div>
          </div>
          <div v-else class="empty-state">
            <strong>No active queue.</strong>
            <p class="muted">There are no running or waiting scan tasks right now.</p>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2>Breakdown</h2>
              <p>Current severity and protocol mix from recent callback evidence.</p>
            </div>
          </div>

          <div class="key-list">
            <div class="kv-row"><span>Critical</span><strong>{{ severityBreakdown.critical }}</strong></div>
            <div class="kv-row"><span>High</span><strong>{{ severityBreakdown.high }}</strong></div>
            <div class="kv-row"><span>Medium</span><strong>{{ severityBreakdown.medium }}</strong></div>
            <div class="kv-row"><span>Low</span><strong>{{ severityBreakdown.low }}</strong></div>
          </div>

          <div class="tag-row" style="margin-top: 16px">
            <span v-for="[protocol, count] in protocolBreakdown" :key="protocol" :class="protocolClass(protocol)">{{ protocol }} ¡¤ {{ count }}</span>
            <span v-if="!protocolBreakdown.length" class="badge badge-info">no protocol data</span>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
