<script setup>
import { computed, onMounted, ref } from 'vue';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';
import { useToastStore } from '../stores/toast.js';

const app = useAppStore();
const toast = useToastStore();

const drafts = ref([]);
const selection = ref(new Set());
const importInput = ref(null);
const saving = ref(false);
const filters = ref({ search: '', type: 'all', group: 'all', status: 'all' });

onMounted(async () => {
  await app.loadPayloads();
  resetDrafts();
});

function resetDrafts() {
  drafts.value = app.payloads.map(p => ({ ...p, _key: p.id || tmpId() }));
  selection.value = new Set();
}

let _tmpCtr = 0;
function tmpId() { return `_new_${Date.now()}_${++_tmpCtr}`; }

function rk(item) { return item._key || item.id; }

const groups = computed(() => {
  const s = new Set();
  drafts.value.forEach(p => { if (p.group) s.add(p.group); });
  return [...s].sort();
});

const stats = computed(() => {
  const r = { total: drafts.value.length, active: 0, header: 0, param: 0, raw: 0 };
  drafts.value.forEach(p => {
    if (p.active) r.active++;
    if (r[p.type] !== undefined) r[p.type]++;
  });
  return r;
});

const filtered = computed(() => {
  const needle = filters.value.search.toLowerCase().trim();
  return drafts.value.filter(p => {
    if (filters.value.type !== 'all' && p.type !== filters.value.type) return false;
    if (filters.value.group !== 'all' && p.group !== filters.value.group) return false;
    if (filters.value.status === 'active' && !p.active) return false;
    if (filters.value.status === 'inactive' && p.active) return false;
    if (needle && ![p.key, p.value, p.group, p.comment, p.type].join(' ').toLowerCase().includes(needle)) return false;
    return true;
  });
});

const isDirty = computed(() => {
  const ser = (arr) => JSON.stringify(arr.map(p => ({ active: p.active, type: p.type, key: p.key, value: p.value, group: p.group, comment: p.comment })));
  return ser(drafts.value) !== ser(app.payloads);
});

function addRow() {
  drafts.value.unshift({ _key: tmpId(), id: '', active: true, type: 'header', key: '', value: 'https://%s/', group: 'standard', comment: '' });
}

function removeSelected() {
  if (!selection.value.size) return;
  drafts.value = drafts.value.filter(p => !selection.value.has(rk(p)));
  selection.value = new Set();
}

function toggleAll() {
  const keys = filtered.value.map(rk);
  if (keys.every(k => selection.value.has(k))) {
    keys.forEach(k => selection.value.delete(k));
  } else {
    keys.forEach(k => selection.value.add(k));
  }
  selection.value = new Set(selection.value);
}

function toggleSel(item) {
  const k = rk(item);
  if (selection.value.has(k)) selection.value.delete(k);
  else selection.value.add(k);
  selection.value = new Set(selection.value);
}

function moveItem(item, dir) {
  const idx = drafts.value.findIndex(p => rk(p) === rk(item));
  const to = idx + dir;
  if (to < 0 || to >= drafts.value.length) return;
  const arr = [...drafts.value];
  [arr[idx], arr[to]] = [arr[to], arr[idx]];
  drafts.value = arr;
}

function setModePreset(mode) {
  drafts.value.forEach(p => {
    if (mode === 'quick') {
      p.active = p.group === 'standard' && p.type === 'header';
    } else if (mode === 'full') {
      p.active = p.group === 'standard';
    } else if (mode === 'cracking') {
      p.active = true;
    } else if (mode === 'none') {
      p.active = false;
    }
  });
}

function enableGroup(group, active) {
  drafts.value.forEach(p => { if (p.group === group) p.active = active; });
}

async function save() {
  saving.value = true;
  try {
    const data = drafts.value.map(p => ({
      id: p.id || '',
      active: Boolean(p.active),
      type: String(p.type || 'header').trim().toLowerCase(),
      key: String(p.key || '').trim(),
      value: String(p.value || ''),
      group: String(p.group || '').trim(),
      comment: String(p.comment || ''),
    }));
    for (let i = 0; i < data.length; i++) {
      if (!data[i].key) { toast.error(`Row ${i + 1}: key cannot be empty`); return; }
      if (!data[i].value) { toast.error(`Row ${i + 1}: value cannot be empty`); return; }
    }
    await api.updatePayloads(data);
    await app.loadPayloads();
    resetDrafts();
    toast.success('Payload configuration saved');
  } catch (e) { toast.error(e.message); }
  finally { saving.value = false; }
}

function discard() { resetDrafts(); toast.info('Changes discarded'); }

function openImport() { importInput.value?.click(); }

async function doImport(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  try {
    await api.importPayloads(file);
    await app.loadPayloads();
    resetDrafts();
    toast.success(`Imported payloads from ${file.name}`);
  } catch (e) { toast.error(e.message); }
}

function doExport() { api.exportPayloads(); }
</script>

<template>
  <div class="payloads-page">
    <!-- Header -->
    <div class="section-header">
      <div>
        <h2>Payload Configuration</h2>
        <p class="muted">Configure header, URL parameter, and raw-request payloads. Use preset buttons for quick mode selection.</p>
      </div>
      <div class="action-row">
        <button class="ghost-button" @click="addRow">+ Add</button>
        <button class="ghost-button" :disabled="!selection.size" @click="removeSelected">🗑 Delete ({{ selection.size }})</button>
        <button class="ghost-button" @click="openImport">📥 Import</button>
        <button class="ghost-button" @click="doExport">📤 Export</button>
        <button class="ghost-button" :disabled="!isDirty" @click="discard">↩ Discard</button>
        <button class="primary" :disabled="!isDirty || saving" @click="save">{{ saving ? 'Saving...' : '💾 Save' }}</button>
      </div>
    </div>

    <input ref="importInput" type="file" accept=".csv,.yaml,.yml" class="hidden-input" @change="doImport" />

    <!-- Mode Presets -->
    <div class="panel preset-bar">
      <span class="preset-label">Mode Presets:</span>
      <button class="btn-sm ghost-button" @click="setModePreset('quick')">⚡ Quick</button>
      <button class="btn-sm ghost-button" @click="setModePreset('full')">🔥 Full</button>
      <button class="btn-sm ghost-button" @click="setModePreset('cracking')">💥 Cracking</button>
      <button class="btn-sm ghost-button" @click="setModePreset('none')">○ None</button>
      <span class="preset-sep">|</span>
      <span class="preset-label">Groups:</span>
      <template v-for="g in groups" :key="g">
        <button class="btn-sm ghost-button" @click="enableGroup(g, true)">✓ {{ g }}</button>
        <button class="btn-sm ghost-button" @click="enableGroup(g, false)">✗ {{ g }}</button>
      </template>
    </div>

    <!-- Stats -->
    <div class="stats-row">
      <div class="mini-stat"><span>Total</span><strong>{{ stats.total }}</strong></div>
      <div class="mini-stat"><span>Active</span><strong>{{ stats.active }}</strong></div>
      <div class="mini-stat"><span>Header</span><strong>{{ stats.header }}</strong></div>
      <div class="mini-stat"><span>Param</span><strong>{{ stats.param }}</strong></div>
      <div class="mini-stat"><span>Raw</span><strong>{{ stats.raw }}</strong></div>
    </div>

    <!-- Hint strip -->
    <div class="hint-strip">
      <span><code>%s</code> = Interactsh domain</span>
      <span><code>%h</code> = target host</span>
      <span><code>%o</code> = default origin</span>
      <span><code>%r</code> = default referer</span>
    </div>

    <!-- Filters -->
    <div class="toolbar-grid">
      <input v-model="filters.search" placeholder="🔍 Search key, value, group, comment..." />
      <select v-model="filters.type">
        <option value="all">All types</option>
        <option value="header">header</option>
        <option value="param">param</option>
        <option value="raw">raw</option>
      </select>
      <select v-model="filters.group">
        <option value="all">All groups</option>
        <option v-for="g in groups" :key="g" :value="g">{{ g }}</option>
      </select>
      <select v-model="filters.status">
        <option value="all">All rows</option>
        <option value="active">Active only</option>
        <option value="inactive">Inactive only</option>
      </select>
    </div>

    <!-- Table -->
    <div class="table-shell">
      <table class="payload-table">
        <thead>
          <tr>
            <th class="fit"><input type="checkbox" :checked="filtered.length > 0 && filtered.every(p => selection.has(rk(p)))" @change="toggleAll" /></th>
            <th class="fit">On</th>
            <th class="fit">Type</th>
            <th>Key</th>
            <th>Value</th>
            <th>Group</th>
            <th>Comment</th>
            <th class="fit">Order</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in filtered" :key="rk(item)"
            :class="{ inactive: !item.active, selected: selection.has(rk(item)) }"
          >
            <td class="fit"><input type="checkbox" :checked="selection.has(rk(item))" @change="toggleSel(item)" /></td>
            <td class="fit"><input type="checkbox" v-model="item.active" /></td>
            <td class="fit">
              <select v-model="item.type">
                <option value="header">header</option>
                <option value="param">param</option>
                <option value="raw">raw</option>
              </select>
            </td>
            <td><input v-model="item.key" class="mono" placeholder="Header/param/raw key" /></td>
            <td><textarea v-model="item.value" class="mono value-editor" rows="2"></textarea></td>
            <td><input v-model="item.group" placeholder="standard / cracking_the_lens" /></td>
            <td><input v-model="item.comment" placeholder="Description..." /></td>
            <td class="fit">
              <div class="order-buttons">
                <button class="icon-button" @click="moveItem(item, -1)" title="Move up">↑</button>
                <button class="icon-button" @click="moveItem(item, 1)" title="Move down">↓</button>
              </div>
            </td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="8" class="empty-state">No payloads match filters.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.payloads-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.preset-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
}
.preset-label {
  color: var(--text-muted);
  font-size: 0.82rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.preset-sep {
  color: var(--border-strong);
  margin: 0 4px;
}
</style>
