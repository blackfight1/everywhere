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

const filteredLogs = computed(() => {
  return ws.logs.filter(entry => {
    if (levelFilter.value !== 'all' && entry.level !== levelFilter.value) return false;
    if (scanFilter.value && entry.scan_id && !entry.scan_id.includes(scanFilter.value)) return false;
    if (searchFilter.value) {
      const needle = searchFilter.value.toLowerCase();
      if (!entry.message.toLowerCase().includes(needle)) return false;
    }
    return true;
  });
});

const logStats = computed(() => {
  const s = { total: ws.logs.length, debug: 0, info: 0, warn: 0, error: 0 };
  ws.logs.forEach(e => { if (s[e.level] !== undefined) s[e.level]++; });
  return s;
});

watch(() => ws.logs.length, async () => {
  if (autoScroll.value) {
    await nextTick();
    if (logContainer.value) {
      logContainer.value.scrollTop = logContainer.value.scrollHeight;
    }
  }
});

function levelClass(level) {
  return `log-level-${level}`;
}

function formatLogTime(t) {
  if (!t) return '';
  const d = new Date(t);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
}

function clearLogs() {
  ws.clearLogs();
}

const activeScanIds = computed(() => {
  return app.scans
    .filter(s => s.status === 'running' || s.status === 'waiting_callback')
    .map(s => ({ id: s.id, label: `${s.id.substring(0, 8)} (${s.status})` }));
});
</script>

<template>
  <div class="debug-page">
    <!-- Controls -->
    <div class="panel debug-controls">
      <div class="debug-header">
        <h2>🐛 Real-time Debug Log</h2>
        <div class="debug-status">
          <span class="ws-status" :class="{ online: ws.connected }">
            <span class="ws-dot"></span>
            {{ ws.connected ? 'WebSocket Connected' : 'Disconnected' }}
          </span>
        </div>
      </div>

      <div class="debug-toolbar">
        <div class="form-group">
          <label>Level</label>
          <select v-model="levelFilter">
            <option value="all">All Levels</option>
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warn">Warning</option>
            <option value="error">Error</option>
          </select>
        </div>

        <div class="form-group">
          <label>Search</label>
          <input v-model="searchFilter" placeholder="Filter messages..." />
        </div>

        <div class="form-group">
          <label>Scan Task</label>
          <select v-model="scanFilter">
            <option value="">All scans</option>
            <option v-for="s in activeScanIds" :key="s.id" :value="s.id">{{ s.label }}</option>
          </select>
        </div>

        <div class="debug-actions">
          <label class="checkbox-label">
            <input type="checkbox" v-model="autoScroll" />
            Auto-scroll
          </label>
          <button class="ghost-button btn-sm" @click="clearLogs">🗑 Clear</button>
        </div>
      </div>

      <!-- Log Stats -->
      <div class="log-stats">
        <span class="badge badge-info">{{ logStats.total }} total</span>
        <span class="badge" :class="logStats.debug ? 'badge-low' : ''">{{ logStats.debug }} debug</span>
        <span class="badge" :class="logStats.info ? 'badge-info' : ''">{{ logStats.info }} info</span>
        <span class="badge" :class="logStats.warn ? 'badge-medium' : ''">{{ logStats.warn }} warn</span>
        <span class="badge" :class="logStats.error ? 'badge-critical' : ''">{{ logStats.error }} error</span>
      </div>
    </div>

    <!-- Log Viewer -->
    <div class="panel log-panel">
      <div ref="logContainer" class="log-viewer">
        <div v-if="!filteredLogs.length" class="empty-state">
          No log entries yet. Logs will appear in real-time as WebSocket messages arrive.
        </div>
        <div
          v-for="entry in filteredLogs" :key="entry.id"
          class="log-entry"
        >
          <span class="log-time">{{ formatLogTime(entry.time) }}</span>
          <span :class="['log-badge', levelClass(entry.level)]">{{ entry.level.toUpperCase().padEnd(5) }}</span>
          <span v-if="entry.scan_id" class="log-scan mono">[{{ entry.scan_id.substring(0, 8) }}]</span>
          <span class="log-msg">{{ entry.message }}</span>
        </div>
      </div>
    </div>

    <!-- Active Scans Progress -->
    <div class="panel" v-if="activeScanIds.length">
      <h2>Active Scan Progress</h2>
      <div class="scan-progress-list">
        <div v-for="scan in app.scans.filter(s => s.status === 'running' || s.status === 'waiting_callback')" :key="scan.id" class="scan-progress-item">
          <div class="scan-progress-info">
            <span class="mono">{{ scan.id.substring(0, 8) }}</span>
            <span class="badge" :class="`badge-${scan.status}`">{{ scan.status }}</span>
            <span class="muted">{{ scan.mode }} · {{ scan.target_count }} targets · {{ scan.request_sent }} sent</span>
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
.debug-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
}
.debug-controls {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.debug-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.debug-header h2 {
  margin: 0;
}
.debug-toolbar {
  display: grid;
  grid-template-columns: 150px 1fr 200px auto;
  gap: 12px;
  align-items: end;
}
.debug-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}
.checkbox-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.85rem;
  color: var(--text-secondary);
  cursor: pointer;
  white-space: nowrap;
}
.log-stats {
  display: flex;
  gap: 8px;
}
.log-panel {
  padding: 0;
  overflow: hidden;
}
.log-panel .log-viewer {
  max-height: 600px;
  min-height: 400px;
  border: none;
  border-radius: var(--radius-lg);
}
.log-time {
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  flex-shrink: 0;
  min-width: 90px;
}
.log-badge {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  font-weight: 700;
  flex-shrink: 0;
  min-width: 48px;
}
.log-scan {
  color: var(--accent);
  font-size: 0.78rem;
  flex-shrink: 0;
}
.log-msg {
  color: var(--text-primary);
  word-break: break-all;
}
.scan-progress-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.scan-progress-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.scan-progress-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

@media (max-width: 960px) {
  .debug-toolbar {
    grid-template-columns: 1fr;
  }
}
</style>
