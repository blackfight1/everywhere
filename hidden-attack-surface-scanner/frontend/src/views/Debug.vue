<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue';
import { useWebSocketStore } from '../stores/websocket.js';
import { useAppStore } from '../stores/app.js';

const ws = useWebSocketStore();
const app = useAppStore();
const logContainer = ref(null);
const autoScroll = ref(true);
const levelFilter = ref('all');
const searchFilter = ref('');
const scanFilter = ref('');

onMounted(() => {
  app.loadScans();
});

const filteredLogs = computed(() => ws.logs.filter((entry) => {
  if (levelFilter.value !== 'all' && entry.level !== levelFilter.value) return false;
  if (scanFilter.value && entry.scan_id && !entry.scan_id.includes(scanFilter.value)) return false;
  if (searchFilter.value && !entry.message.toLowerCase().includes(searchFilter.value.toLowerCase())) return false;
  return true;
}));

const logStats = computed(() => {
  const stats = { total: ws.logs.length, debug: 0, info: 0, warn: 0, error: 0 };
  ws.logs.forEach((entry) => { if (stats[entry.level] !== undefined) stats[entry.level] += 1; });
  return stats;
});

watch(() => ws.logs.length, async () => {
  if (!autoScroll.value) return;
  await nextTick();
  if (logContainer.value) logContainer.value.scrollTop = logContainer.value.scrollHeight;
});

function levelClass(level) {
  return `log-level-${level}`;
}

function formatLogTime(value) {
  if (!value) return '';
  const date = new Date(value);
  return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
}

function clearLogs() {
  ws.clearLogs();
}

const activeScanIds = computed(() => app.scans
  .filter((scan) => scan.status === 'running' || scan.status === 'waiting_callback')
  .map((scan) => ({ id: scan.id, label: `${scan.id.substring(0, 8)} (${scan.status})` }))
);
</script>

<template>
  <div class="debug-page">
    <div class="panel debug-controls">
      <div class="panel-header" style="margin-bottom: 0">
        <div>
          <h2>Real-time Debug Log</h2>
          <p>WebSocket events, scan progress, and callback notifications as they reach the frontend.</p>
        </div>
        <div class="inline-actions">
          <span class="badge" :class="ws.connected ? 'badge-low' : 'badge-critical'">{{ ws.connected ? 'socket online' : 'socket offline' }}</span>
          <button class="ghost-button btn-sm" @click="clearLogs">Clear</button>
        </div>
      </div>

      <div class="debug-toolbar">
        <div class="form-group">
          <label>Level</label>
          <select v-model="levelFilter">
            <option value="all">All</option>
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warn">Warn</option>
            <option value="error">Error</option>
          </select>
        </div>
        <div class="form-group">
          <label>Search</label>
          <input v-model="searchFilter" placeholder="Filter log message text" />
        </div>
        <div class="form-group">
          <label>Scan task</label>
          <select v-model="scanFilter">
            <option value="">All scans</option>
            <option v-for="scan in activeScanIds" :key="scan.id" :value="scan.id">{{ scan.label }}</option>
          </select>
        </div>
        <label class="checkbox-label">
          <input v-model="autoScroll" type="checkbox" />
          Auto-scroll
        </label>
      </div>

      <div class="log-stats">
        <span class="badge badge-info">{{ logStats.total }} total</span>
        <span class="badge" :class="logStats.debug ? 'badge-low' : 'badge-info'">{{ logStats.debug }} debug</span>
        <span class="badge" :class="logStats.info ? 'badge-info' : 'badge-info'">{{ logStats.info }} info</span>
        <span class="badge" :class="logStats.warn ? 'badge-medium' : 'badge-info'">{{ logStats.warn }} warn</span>
        <span class="badge" :class="logStats.error ? 'badge-critical' : 'badge-info'">{{ logStats.error }} error</span>
      </div>
    </div>

    <div class="panel log-panel">
      <div ref="logContainer" class="log-viewer">
        <div v-if="!filteredLogs.length" class="empty-state">
          No log entries yet. Entries will appear as soon as the WebSocket receives events.
        </div>
        <div v-for="entry in filteredLogs" :key="entry.id" class="log-entry">
          <span class="log-time">{{ formatLogTime(entry.time) }}</span>
          <span :class="['log-badge', levelClass(entry.level)]">{{ entry.level.toUpperCase().padEnd(5) }}</span>
          <span v-if="entry.scan_id" class="log-scan mono">[{{ entry.scan_id.substring(0, 8) }}]</span>
          <span class="log-msg">{{ entry.message }}</span>
        </div>
      </div>
    </div>

    <div class="panel" v-if="activeScanIds.length">
      <div class="panel-header" style="margin-bottom: 12px">
        <div>
          <h2>Active Scan Progress</h2>
          <p>Current dispatch progress for scans that are still running or waiting for callbacks.</p>
        </div>
      </div>
      <div class="scan-progress-list">
        <div v-for="scan in app.scans.filter((item) => item.status === 'running' || item.status === 'waiting_callback')" :key="scan.id" class="scan-progress-item">
          <div class="scan-progress-info">
            <span class="mono">{{ scan.id.substring(0, 8) }}</span>
            <span class="badge" :class="`badge-${scan.status}`">{{ scan.status }}</span>
            <span class="muted">{{ scan.mode }} ¡¤ {{ scan.target_count }} targets ¡¤ {{ scan.request_sent }} sent</span>
          </div>
          <div class="scan-progress" v-if="scan._total">
            <div class="progress-bar" :style="{ width: Math.round((scan.request_sent / scan._total) * 100) + '%' }"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.debug-page { display: flex; flex-direction: column; gap: 20px; }
.debug-controls { display: flex; flex-direction: column; gap: 14px; }
.debug-toolbar { display: grid; grid-template-columns: 180px 1fr 220px auto; gap: 12px; align-items: end; }
.checkbox-label { display: flex; align-items: center; gap: 8px; white-space: nowrap; color: var(--text-secondary); }
.log-stats { display: flex; gap: 8px; flex-wrap: wrap; }
.log-panel { padding: 0; overflow: hidden; }
.log-viewer { max-height: 600px; min-height: 400px; background: rgba(8, 12, 17, 0.4); padding: 16px; overflow: auto; }
.log-entry { display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; border-top: 1px solid rgba(49, 80, 109, 0.24); }
.log-entry:first-child { border-top: 0; padding-top: 0; }
.log-time { color: var(--text-muted); font-size: 0.78rem; flex-shrink: 0; min-width: 90px; }
.log-badge { font-size: 0.75rem; font-weight: 700; flex-shrink: 0; min-width: 48px; }
.log-level-debug { color: #b8f0cf; }
.log-level-info { color: #b9dbff; }
.log-level-warn { color: #ffe8bf; }
.log-level-error { color: #ffd0ca; }
.log-scan { color: var(--accent); font-size: 0.78rem; flex-shrink: 0; }
.log-msg { color: var(--text-primary); word-break: break-all; }
.scan-progress-list { display: flex; flex-direction: column; gap: 12px; }
.scan-progress-item { display: flex; flex-direction: column; gap: 6px; }
.scan-progress-info { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
@media (max-width: 960px) { .debug-toolbar { grid-template-columns: 1fr; } }
</style>
