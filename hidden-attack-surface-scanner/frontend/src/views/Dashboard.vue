<script setup>
import { computed, onMounted } from 'vue';
import { useAppStore } from '../stores/app.js';
import { useRouter } from 'vue-router';

const app = useAppStore();
const router = useRouter();

onMounted(() => { app.loadStats(); });

const severityBreakdown = computed(() => {
  const map = { critical: 0, high: 0, medium: 0, low: 0 };
  (app.stats.recent || []).forEach(p => {
    if (map[p.severity] !== undefined) map[p.severity]++;
  });
  return map;
});

const protocolBreakdown = computed(() => {
  const map = {};
  (app.stats.recent || []).forEach(p => {
    const proto = p.callback_protocol || 'unknown';
    map[proto] = (map[proto] || 0) + 1;
  });
  return map;
});

function formatTime(t) {
  if (!t) return '-';
  const d = new Date(t);
  return d.toLocaleString();
}

function severityClass(s) {
  return `badge badge-${s || 'info'}`;
}

function protocolClass(p) {
  return `badge protocol-${p || 'dns'}`;
}
</script>

<template>
  <div class="dashboard">
    <!-- Metric Cards -->
    <div class="metric-grid">
      <article class="panel metric-card" @click="router.push('/scans')">
        <div class="metric-icon">🔍</div>
        <div class="metric-body">
          <span class="metric-label">Total Scans</span>
          <strong class="metric-value">{{ app.stats.scan_count }}</strong>
        </div>
      </article>

      <article class="panel metric-card accent" @click="router.push('/scans')">
        <div class="metric-icon">⚡</div>
        <div class="metric-body">
          <span class="metric-label">Active Scans</span>
          <strong class="metric-value">{{ app.stats.active_count }}</strong>
        </div>
      </article>

      <article class="panel metric-card" @click="router.push('/results')">
        <div class="metric-icon">🎯</div>
        <div class="metric-body">
          <span class="metric-label">Total Pingbacks</span>
          <strong class="metric-value">{{ app.stats.pingback_count }}</strong>
        </div>
      </article>

      <article class="panel metric-card">
        <div class="metric-icon">📊</div>
        <div class="metric-body">
          <span class="metric-label">Severity Distribution</span>
          <div class="severity-pills">
            <span class="badge badge-critical" v-if="severityBreakdown.critical">{{ severityBreakdown.critical }} Critical</span>
            <span class="badge badge-high" v-if="severityBreakdown.high">{{ severityBreakdown.high }} High</span>
            <span class="badge badge-medium" v-if="severityBreakdown.medium">{{ severityBreakdown.medium }} Medium</span>
            <span class="badge badge-low" v-if="severityBreakdown.low">{{ severityBreakdown.low }} Low</span>
            <span class="badge badge-info" v-if="!app.stats.recent?.length">No data yet</span>
          </div>
        </div>
      </article>
    </div>

    <!-- Protocol Breakdown -->
    <div class="panel" v-if="Object.keys(protocolBreakdown).length">
      <h2>Protocol Breakdown</h2>
      <div class="protocol-bar">
        <span v-for="(count, proto) in protocolBreakdown" :key="proto" :class="protocolClass(proto)">
          {{ proto.toUpperCase() }}: {{ count }}
        </span>
      </div>
    </div>

    <!-- Recent Pingbacks -->
    <div class="panel">
      <div class="section-header">
        <h2>Recent Pingbacks</h2>
        <button class="ghost-button" @click="router.push('/results')">View All →</button>
      </div>

      <div class="table-shell" v-if="app.stats.recent?.length">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Protocol</th>
              <th>Payload Key</th>
              <th>Target</th>
              <th>Remote IP</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in app.stats.recent" :key="item.id">
              <td class="mono">{{ formatTime(item.received_at) }}</td>
              <td><span :class="protocolClass(item.callback_protocol)">{{ item.callback_protocol }}</span></td>
              <td class="mono">{{ item.payload_key }}</td>
              <td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis">{{ item.target_url }}</td>
              <td class="mono">{{ item.remote_address }}</td>
              <td><span :class="severityClass(item.severity)">{{ item.severity }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="empty-state" v-else>
        No pingbacks received yet. Start a scan to begin detecting hidden attack surfaces.
      </div>
    </div>
  </div>
</template>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.metric-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
}

.metric-card {
  display: flex;
  align-items: center;
  gap: 16px;
  cursor: pointer;
  transition: transform var(--transition-fast), box-shadow var(--transition-fast);
}

.metric-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.metric-card.accent {
  border-color: var(--accent);
  box-shadow: var(--shadow-glow);
}

.metric-icon {
  font-size: 2rem;
  line-height: 1;
}

.metric-body {
  flex: 1;
}

.severity-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 6px;
}

.protocol-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.section-header {
  margin-bottom: 0;
}
</style>
