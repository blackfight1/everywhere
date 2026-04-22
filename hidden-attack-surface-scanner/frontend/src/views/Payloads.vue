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

onMounted(async () => { await app.loadPayloads(); resetDrafts(); });
function resetDrafts() { drafts.value = app.payloads.map((p) => ({ ...p, _key: p.id || tmpId() })); selection.value = new Set(); }
let tmpCounter = 0;
function tmpId() { return `_new_${Date.now()}_${++tmpCounter}`; }
function rowKey(item) { return item._key || item.id; }

const groups = computed(() => [...new Set(drafts.value.map((item) => item.group).filter(Boolean))].sort());
const stats = computed(() => {
  const result = { total: drafts.value.length, active: 0, header: 0, param: 0, raw: 0 };
  drafts.value.forEach((item) => { if (item.active) result.active += 1; if (result[item.type] !== undefined) result[item.type] += 1; });
  return result;
});
const filtered = computed(() => {
  const needle = filters.value.search.toLowerCase().trim();
  return drafts.value.filter((item) => {
    if (filters.value.type !== 'all' && item.type !== filters.value.type) return false;
    if (filters.value.group !== 'all' && item.group !== filters.value.group) return false;
    if (filters.value.status === 'active' && !item.active) return false;
    if (filters.value.status === 'inactive' && item.active) return false;
    if (needle && ![item.key, item.value, item.group, item.comment, item.type].join(' ').toLowerCase().includes(needle)) return false;
    return true;
  });
});
const isDirty = computed(() => JSON.stringify(drafts.value.map(clean)) !== JSON.stringify(app.payloads.map(clean)));
function clean(item) { return { active: item.active, type: item.type, key: item.key, value: item.value, group: item.group, comment: item.comment }; }
function addRow() { drafts.value.unshift({ _key: tmpId(), id: '', active: true, type: 'header', key: '', value: 'https://%s/', group: 'standard', comment: '' }); }
function removeSelected() { if (!selection.value.size) return; drafts.value = drafts.value.filter((item) => !selection.value.has(rowKey(item))); selection.value = new Set(); }
function toggleAll() { const next = new Set(selection.value); const keys = filtered.value.map(rowKey); const full = keys.every((key) => next.has(key)); keys.forEach((key) => full ? next.delete(key) : next.add(key)); selection.value = next; }
function toggleSel(item) { const next = new Set(selection.value); const key = rowKey(item); next.has(key) ? next.delete(key) : next.add(key); selection.value = next; }
function moveItem(item, direction) { const index = drafts.value.findIndex((row) => rowKey(row) === rowKey(item)); const target = index + direction; if (target < 0 || target >= drafts.value.length) return; const copy = [...drafts.value]; [copy[index], copy[target]] = [copy[target], copy[index]]; drafts.value = copy; }
function setModePreset(mode) { drafts.value.forEach((item) => { if (mode === 'quick') item.active = item.group === 'standard' && item.type === 'header'; else if (mode === 'full') item.active = item.group === 'standard'; else if (mode === 'cracking') item.active = true; else if (mode === 'none') item.active = false; }); }
function enableGroup(group, active) { drafts.value.forEach((item) => { if (item.group === group) item.active = active; }); }
async function save() {
  saving.value = true;
  try {
    const data = drafts.value.map((item) => ({ id: item.id || '', active: Boolean(item.active), type: String(item.type || 'header').trim().toLowerCase(), key: String(item.key || '').trim(), value: String(item.value || ''), group: String(item.group || '').trim(), comment: String(item.comment || '') }));
    for (let i = 0; i < data.length; i += 1) { if (!data[i].key) { toast.error(`Row ${i + 1}: key cannot be empty`); return; } if (!data[i].value) { toast.error(`Row ${i + 1}: value cannot be empty`); return; } }
    await api.updatePayloads(data); await app.loadPayloads(); resetDrafts(); toast.success('Payload configuration saved');
  } catch (e) { toast.error(e.message); } finally { saving.value = false; }
}
function discard() { resetDrafts(); toast.info('Changes discarded'); }
function openImport() { importInput.value?.click(); }
async function doImport(event) { const file = event.target.files?.[0]; event.target.value = ''; if (!file) return; try { await api.importPayloads(file); await app.loadPayloads(); resetDrafts(); toast.success(`Imported payloads from ${file.name}`); } catch (e) { toast.error(e.message); } }
function doExport() { api.exportPayloads(); }
</script>

<template>
  <div class="payloads-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Payload workspace</h2>
          <p>Edit the active payload set, apply mode presets, and keep standard headers separate from raw request variants.</p>
        </div>
        <div class="action-row">
          <button class="ghost-button" @click="addRow">Add row</button>
          <button class="ghost-button" :disabled="!selection.size" @click="removeSelected">Delete selected</button>
          <button class="ghost-button" @click="openImport">Import</button>
          <button class="ghost-button" @click="doExport">Export</button>
          <button class="ghost-button" :disabled="!isDirty" @click="discard">Discard</button>
          <button class="primary" :disabled="!isDirty || saving" @click="save">{{ saving ? 'Saving...' : 'Save payloads' }}</button>
        </div>
      </div>

      <input ref="importInput" type="file" accept=".csv,.yaml,.yml" class="hidden-input" @change="doImport" />

      <div class="tag-row" style="margin-bottom: 14px">
        <button class="btn-sm" @click="setModePreset('quick')">Preset quick</button>
        <button class="btn-sm" @click="setModePreset('full')">Preset full</button>
        <button class="btn-sm" @click="setModePreset('cracking')">Preset cracking</button>
        <button class="btn-sm" @click="setModePreset('none')">Disable all</button>
        <button v-for="group in groups" :key="group + '-on'" class="btn-sm" @click="enableGroup(group, true)">{{ group }} on</button>
        <button v-for="group in groups" :key="group + '-off'" class="btn-sm" @click="enableGroup(group, false)">{{ group }} off</button>
      </div>

      <div class="stats-row">
        <div class="mini-stat"><span>Total</span><strong>{{ stats.total }}</strong></div>
        <div class="mini-stat"><span>Active</span><strong>{{ stats.active }}</strong></div>
        <div class="mini-stat"><span>Header</span><strong>{{ stats.header }}</strong></div>
        <div class="mini-stat"><span>Param</span><strong>{{ stats.param }}</strong></div>
        <div class="mini-stat"><span>Raw</span><strong>{{ stats.raw }}</strong></div>
      </div>

      <div class="hint-strip">
        <span><code>%s</code> generated OOB domain</span>
        <span><code>%h</code> target hostname</span>
        <span><code>%o</code> scan default origin</span>
        <span><code>%r</code> scan default referer</span>
      </div>

      <div class="toolbar-grid">
        <div class="form-group form-span-6"><label>Search</label><input v-model="filters.search" placeholder="Find by key, value, group, or comment" /></div>
        <div class="form-group form-span-2"><label>Type</label><select v-model="filters.type"><option value="all">All</option><option value="header">header</option><option value="param">param</option><option value="raw">raw</option></select></div>
        <div class="form-group form-span-2"><label>Group</label><select v-model="filters.group"><option value="all">All</option><option v-for="group in groups" :key="group" :value="group">{{ group }}</option></select></div>
        <div class="form-group form-span-2"><label>Status</label><select v-model="filters.status"><option value="all">All</option><option value="active">Active</option><option value="inactive">Inactive</option></select></div>
      </div>
    </section>

    <section class="panel" style="padding-top: 0">
      <div class="table-shell">
        <table class="payload-table">
          <thead><tr><th class="fit"><input type="checkbox" :checked="filtered.length > 0 && filtered.every((item) => selection.has(rowKey(item)))" @change="toggleAll" /></th><th class="fit">On</th><th class="fit">Type</th><th>Key</th><th>Value</th><th>Group</th><th>Comment</th><th class="fit">Order</th></tr></thead>
          <tbody>
            <tr v-for="item in filtered" :key="rowKey(item)" :class="{ selected: selection.has(rowKey(item)), inactive: !item.active }">
              <td class="fit"><input type="checkbox" :checked="selection.has(rowKey(item))" @change="toggleSel(item)" /></td>
              <td class="fit"><input v-model="item.active" type="checkbox" /></td>
              <td class="fit"><select v-model="item.type"><option value="header">header</option><option value="param">param</option><option value="raw">raw</option></select></td>
              <td><input v-model="item.key" class="mono" placeholder="Header / param / raw key" /></td>
              <td><textarea v-model="item.value" class="mono" rows="2"></textarea></td>
              <td><input v-model="item.group" placeholder="standard / cracking_the_lens" /></td>
              <td><input v-model="item.comment" placeholder="Operator note" /></td>
              <td class="fit"><div class="order-buttons"><button class="icon-button" @click="moveItem(item, -1)">Up</button><button class="icon-button" @click="moveItem(item, 1)">Down</button></div></td>
            </tr>
            <tr v-if="!filtered.length"><td colspan="8" class="empty-state">No payloads match the current filter set.</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>
