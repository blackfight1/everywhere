<script setup>
import { computed, onMounted, reactive, ref } from "vue";

const state = reactive({
  stats: { scan_count: 0, active_count: 0, pingback_count: 0, recent: [] },
  scans: [],
  payloads: [],
  pingbacks: [],
  settings: null
});

const activeTab = ref("dashboard");
const payloadImportInput = ref(null);
const payloadDrafts = ref([]);
const payloadSelection = ref([]);
const payloadNotice = ref("");
const payloadError = ref("");

const scanForm = reactive({
  targets: "https://example.com",
  mode: "quick",
  concurrency: 10,
  rate_limit: 20,
  callback_timeout_minutes: 30,
  proxy: "",
  default_origin: "",
  default_referer: ""
});

const payloadFilters = reactive({
  search: "",
  type: "all",
  group: "all",
  status: "all"
});

function createTempID() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `tmp-${crypto.randomUUID()}`;
  }
  return `tmp-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function rowKey(item) {
  return item.id || item._tempId;
}

function withEditorMeta(item) {
  return {
    ...item,
    _tempId: item.id || createTempID()
  };
}

function sanitizePayload(item) {
  return {
    id: item.id || "",
    active: Boolean(item.active),
    type: String(item.type || "header").trim().toLowerCase(),
    key: String(item.key || "").trim(),
    value: String(item.value || ""),
    group: String(item.group || "").trim(),
    comment: String(item.comment || "")
  };
}

function serializePayloads(items) {
  return JSON.stringify(items.map((item) => sanitizePayload(item)));
}

const payloadDirty = computed(() => serializePayloads(payloadDrafts.value) !== serializePayloads(state.payloads));

const payloadGroups = computed(() => {
  const groups = new Set();
  payloadDrafts.value.forEach((item) => {
    const group = String(item.group || "").trim();
    if (group) {
      groups.add(group);
    }
  });
  return Array.from(groups).sort();
});

const payloadStats = computed(() => {
  const stats = {
    total: payloadDrafts.value.length,
    active: 0,
    header: 0,
    param: 0,
    raw: 0
  };
  payloadDrafts.value.forEach((item) => {
    if (item.active) {
      stats.active += 1;
    }
    if (stats[item.type] !== undefined) {
      stats[item.type] += 1;
    }
  });
  return stats;
});

const filteredPayloads = computed(() => {
  const needle = payloadFilters.search.trim().toLowerCase();
  return payloadDrafts.value.filter((item) => {
    if (payloadFilters.type !== "all" && item.type !== payloadFilters.type) {
      return false;
    }
    if (payloadFilters.group !== "all" && item.group !== payloadFilters.group) {
      return false;
    }
    if (payloadFilters.status === "active" && !item.active) {
      return false;
    }
    if (payloadFilters.status === "inactive" && item.active) {
      return false;
    }
    if (!needle) {
      return true;
    }
    return [item.key, item.value, item.group, item.comment, item.type]
      .join(" ")
      .toLowerCase()
      .includes(needle);
  });
});

const visibleRowKeys = computed(() => filteredPayloads.value.map((item) => rowKey(item)));
const selectedVisibleCount = computed(() => {
  const visible = new Set(visibleRowKeys.value);
  return payloadSelection.value.filter((key) => visible.has(key)).length;
});
const allVisibleSelected = computed(() => visibleRowKeys.value.length > 0 && selectedVisibleCount.value === visibleRowKeys.value.length);

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(path, {
    ...options,
    headers
  });
  if (!response.ok) {
    const rawText = await response.text();
    try {
      const parsed = JSON.parse(rawText);
      throw new Error(parsed.error || rawText || `Request failed: ${response.status}`);
    } catch (error) {
      if (error instanceof Error && error.message) {
        throw error;
      }
      throw new Error(rawText || `Request failed: ${response.status}`);
    }
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function refreshAll() {
  await Promise.all([loadStats(), loadScans(), loadPayloads({ preserveDrafts: true }), loadPingbacks(), loadSettings()]);
}

async function loadStats() {
  state.stats = await api("/api/stats");
}

async function loadScans() {
  state.scans = await api("/api/scans");
}

async function loadPayloads(options = {}) {
  const payloads = await api("/api/payloads");
  state.payloads = payloads;
  if (!options.preserveDrafts || !payloadDirty.value) {
    payloadDrafts.value = payloads.map((item) => withEditorMeta(item));
    payloadSelection.value = [];
  } else {
    prunePayloadSelection();
  }
}

async function loadPingbacks() {
  state.pingbacks = await api("/api/pingbacks");
}

async function loadSettings() {
  state.settings = await api("/api/settings");
}

async function startScan() {
  const payload = {
    targets: scanForm.targets
      .split("\n")
      .map((item) => item.trim())
      .filter(Boolean),
    mode: scanForm.mode,
    concurrency: Number(scanForm.concurrency),
    rate_limit: Number(scanForm.rate_limit),
    callback_timeout_minutes: Number(scanForm.callback_timeout_minutes),
    proxy: scanForm.proxy,
    default_origin: scanForm.default_origin,
    default_referer: scanForm.default_referer
  };
  await api("/api/scan", { method: "POST", body: JSON.stringify(payload) });
  await refreshAll();
  activeTab.value = "results";
}

async function stopScan(id) {
  await api(`/api/scan/${id}/stop`, { method: "POST" });
  await refreshAll();
}

function prunePayloadSelection() {
  const validKeys = new Set(payloadDrafts.value.map((item) => rowKey(item)));
  payloadSelection.value = payloadSelection.value.filter((key) => validKeys.has(key));
}

function clearPayloadFeedback() {
  payloadNotice.value = "";
  payloadError.value = "";
}

function addPayloadRow() {
  clearPayloadFeedback();
  payloadDrafts.value.unshift(
    withEditorMeta({
      id: "",
      active: true,
      type: "header",
      key: "",
      value: "https://%s/",
      group: "standard",
      comment: ""
    })
  );
}

function toggleVisibleSelection() {
  if (allVisibleSelected.value) {
    const hidden = new Set(visibleRowKeys.value);
    payloadSelection.value = payloadSelection.value.filter((key) => !hidden.has(key));
    return;
  }

  const selected = new Set(payloadSelection.value);
  visibleRowKeys.value.forEach((key) => selected.add(key));
  payloadSelection.value = Array.from(selected);
}

function toggleRowSelection(item) {
  const key = rowKey(item);
  const selected = new Set(payloadSelection.value);
  if (selected.has(key)) {
    selected.delete(key);
  } else {
    selected.add(key);
  }
  payloadSelection.value = Array.from(selected);
}

function isSelected(item) {
  return payloadSelection.value.includes(rowKey(item));
}

function deleteSelectedPayloads() {
  clearPayloadFeedback();
  if (payloadSelection.value.length === 0) {
    return;
  }
  const selected = new Set(payloadSelection.value);
  payloadDrafts.value = payloadDrafts.value.filter((item) => !selected.has(rowKey(item)));
  payloadSelection.value = [];
}

function movePayload(item, direction) {
  const index = payloadDrafts.value.findIndex((entry) => rowKey(entry) === rowKey(item));
  if (index < 0) {
    return;
  }
  const nextIndex = index + direction;
  if (nextIndex < 0 || nextIndex >= payloadDrafts.value.length) {
    return;
  }
  const reordered = [...payloadDrafts.value];
  const [moved] = reordered.splice(index, 1);
  reordered.splice(nextIndex, 0, moved);
  payloadDrafts.value = reordered;
}

function discardPayloadChanges() {
  clearPayloadFeedback();
  payloadDrafts.value = state.payloads.map((item) => withEditorMeta(item));
  payloadSelection.value = [];
}

function validatePayloads(items) {
  const allowedTypes = new Set(["header", "param", "raw"]);
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const row = index + 1;
    if (!allowedTypes.has(item.type)) {
      throw new Error(`Row ${row}: unsupported payload type "${item.type}".`);
    }
    if (!item.key) {
      throw new Error(`Row ${row}: key cannot be empty.`);
    }
    if (!item.value) {
      throw new Error(`Row ${row}: value cannot be empty.`);
    }
  }
}

async function savePayloads() {
  clearPayloadFeedback();
  try {
    const payloads = payloadDrafts.value.map((item) => sanitizePayload(item));
    validatePayloads(payloads);
    await api("/api/payloads", { method: "PUT", body: JSON.stringify(payloads) });
    await loadPayloads();
    payloadNotice.value = "Payload configuration saved.";
  } catch (error) {
    payloadError.value = error instanceof Error ? error.message : String(error);
  }
}

function openPayloadImport() {
  payloadImportInput.value?.click();
}

async function importPayloads(event) {
  clearPayloadFeedback();
  const [file] = Array.from(event.target.files || []);
  event.target.value = "";
  if (!file) {
    return;
  }
  try {
    const body = new FormData();
    body.append("file", file);
    await api("/api/payloads/import", {
      method: "POST",
      body
    });
    await loadPayloads();
    payloadNotice.value = `Imported payloads from ${file.name}.`;
  } catch (error) {
    payloadError.value = error instanceof Error ? error.message : String(error);
  }
}

function exportPayloads() {
  window.open("/api/payloads/export", "_blank", "noopener");
}

function connectWS() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${protocol}://${window.location.host}/api/ws`);
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "pingback" && message.data) {
      state.pingbacks.unshift(message.data);
      state.stats.pingback_count += 1;
    }
    if (message.type === "task_status") {
      refreshAll();
    }
  };
}

onMounted(async () => {
  await refreshAll();
  connectWS();
});
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <h1>Hidden Attack Surface Scanner</h1>
      <button :class="{ active: activeTab === 'dashboard' }" @click="activeTab = 'dashboard'">Dashboard</button>
      <button :class="{ active: activeTab === 'scans' }" @click="activeTab = 'scans'">Scans</button>
      <button :class="{ active: activeTab === 'payloads' }" @click="activeTab = 'payloads'">Payloads</button>
      <button :class="{ active: activeTab === 'results' }" @click="activeTab = 'results'">Results</button>
      <button :class="{ active: activeTab === 'settings' }" @click="activeTab = 'settings'">Settings</button>
    </aside>

    <main class="content">
      <section v-if="activeTab === 'dashboard'" class="panel-grid">
        <article class="panel metric">
          <label>Total Scans</label>
          <strong>{{ state.stats.scan_count }}</strong>
        </article>
        <article class="panel metric">
          <label>Active Scans</label>
          <strong>{{ state.stats.active_count }}</strong>
        </article>
        <article class="panel metric">
          <label>Pingbacks</label>
          <strong>{{ state.stats.pingback_count }}</strong>
        </article>
        <article class="panel wide">
          <h2>Recent Pingbacks</h2>
          <table>
            <thead>
              <tr>
                <th>Protocol</th>
                <th>Payload</th>
                <th>Target</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in state.stats.recent" :key="item.id">
                <td>{{ item.callback_protocol }}</td>
                <td>{{ item.payload_key }}</td>
                <td>{{ item.target_url }}</td>
                <td>{{ item.severity }}</td>
              </tr>
            </tbody>
          </table>
        </article>
      </section>

      <section v-if="activeTab === 'scans'" class="panel-grid">
        <article class="panel form-card">
          <h2>Create Scan</h2>
          <label>Targets</label>
          <textarea v-model="scanForm.targets" rows="8"></textarea>
          <label>Mode</label>
          <select v-model="scanForm.mode">
            <option value="quick">quick</option>
            <option value="full">full</option>
            <option value="cracking">cracking</option>
            <option value="custom">custom</option>
          </select>
          <label>Concurrency</label>
          <input v-model="scanForm.concurrency" type="number" min="1" />
          <label>Rate Limit</label>
          <input v-model="scanForm.rate_limit" type="number" min="0" />
          <label>Callback Timeout Minutes</label>
          <input v-model="scanForm.callback_timeout_minutes" type="number" min="1" />
          <label>Proxy</label>
          <input v-model="scanForm.proxy" placeholder="http://127.0.0.1:8080 or socks5://127.0.0.1:1080" />
          <label>Default Origin</label>
          <input v-model="scanForm.default_origin" />
          <label>Default Referer</label>
          <input v-model="scanForm.default_referer" />
          <button class="primary" @click="startScan">Start Scan</button>
        </article>
        <article class="panel wide">
          <h2>Scan Tasks</h2>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Mode</th>
                <th>Requests</th>
                <th>Pingbacks</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in state.scans" :key="item.id">
                <td class="mono">{{ item.id }}</td>
                <td>{{ item.status }}</td>
                <td>{{ item.mode }}</td>
                <td>{{ item.request_sent }}</td>
                <td>{{ item.pingback_count }}</td>
                <td><button class="ghost-button" @click="stopScan(item.id)">Stop</button></td>
              </tr>
            </tbody>
          </table>
        </article>
      </section>

      <section v-if="activeTab === 'payloads'" class="panel payload-workbench">
        <div class="section-header">
          <div>
            <h2>Payloads</h2>
            <p class="muted">
              Configure header, URL parameter, and raw-request payloads with the same workflow Burp users expect:
              enable, edit inline, reorder, import, export, and save as one payload set.
            </p>
          </div>
          <div class="action-row">
            <button class="ghost-button" @click="addPayloadRow">Add Payload</button>
            <button class="ghost-button" :disabled="payloadSelection.length === 0" @click="deleteSelectedPayloads">
              Delete Selected
            </button>
            <button class="ghost-button" :disabled="!payloadDirty" @click="discardPayloadChanges">Discard Changes</button>
            <button class="ghost-button" @click="openPayloadImport">Import</button>
            <button class="ghost-button" @click="exportPayloads">Export</button>
            <button class="primary" :disabled="!payloadDirty" @click="savePayloads">Save Payloads</button>
          </div>
        </div>

        <input
          ref="payloadImportInput"
          accept=".csv,.yaml,.yml"
          class="hidden-input"
          type="file"
          @change="importPayloads"
        />

        <div class="stats-row">
          <div class="mini-stat">
            <span>Total</span>
            <strong>{{ payloadStats.total }}</strong>
          </div>
          <div class="mini-stat">
            <span>Active</span>
            <strong>{{ payloadStats.active }}</strong>
          </div>
          <div class="mini-stat">
            <span>Header</span>
            <strong>{{ payloadStats.header }}</strong>
          </div>
          <div class="mini-stat">
            <span>Param</span>
            <strong>{{ payloadStats.param }}</strong>
          </div>
          <div class="mini-stat">
            <span>Raw</span>
            <strong>{{ payloadStats.raw }}</strong>
          </div>
        </div>

        <div class="hint-strip">
          <span><code>%s</code> = generated Interactsh domain</span>
          <span><code>%h</code> = current target host</span>
          <span><code>%o</code> = default origin from scan task</span>
          <span><code>%r</code> = default referer from scan task</span>
        </div>

        <div class="toolbar-grid">
          <input v-model="payloadFilters.search" placeholder="Search key, value, group, or comment" />
          <select v-model="payloadFilters.type">
            <option value="all">All types</option>
            <option value="header">header</option>
            <option value="param">param</option>
            <option value="raw">raw</option>
          </select>
          <select v-model="payloadFilters.group">
            <option value="all">All groups</option>
            <option v-for="group in payloadGroups" :key="group" :value="group">{{ group }}</option>
          </select>
          <select v-model="payloadFilters.status">
            <option value="all">All rows</option>
            <option value="active">Active only</option>
            <option value="inactive">Inactive only</option>
          </select>
        </div>

        <div v-if="payloadError" class="banner error">{{ payloadError }}</div>
        <div v-else-if="payloadNotice" class="banner success">{{ payloadNotice }}</div>

        <div class="table-shell">
          <table class="payload-table">
            <thead>
              <tr>
                <th class="fit">
                  <input :checked="allVisibleSelected" type="checkbox" @change="toggleVisibleSelection" />
                </th>
                <th class="fit">Enabled</th>
                <th class="fit">Type</th>
                <th>Key</th>
                <th>Value</th>
                <th>Group</th>
                <th>Comment</th>
                <th class="fit">Order</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in filteredPayloads" :key="rowKey(item)" :class="{ inactive: !item.active, selected: isSelected(item) }">
                <td class="fit">
                  <input :checked="isSelected(item)" type="checkbox" @change="toggleRowSelection(item)" />
                </td>
                <td class="fit">
                  <input v-model="item.active" type="checkbox" />
                </td>
                <td class="fit">
                  <select v-model="item.type">
                    <option value="header">header</option>
                    <option value="param">param</option>
                    <option value="raw">raw</option>
                  </select>
                </td>
                <td>
                  <input v-model="item.key" class="mono" placeholder="Header name, param key, or raw variant key" />
                </td>
                <td>
                  <textarea v-model="item.value" class="mono value-editor" rows="2"></textarea>
                </td>
                <td>
                  <input v-model="item.group" placeholder="standard or cracking_the_lens" />
                </td>
                <td>
                  <input v-model="item.comment" placeholder="Operator note" />
                </td>
                <td class="fit">
                  <div class="order-buttons">
                    <button class="icon-button" title="Move up" @click="movePayload(item, -1)">Up</button>
                    <button class="icon-button" title="Move down" @click="movePayload(item, 1)">Down</button>
                  </div>
                </td>
              </tr>
              <tr v-if="filteredPayloads.length === 0">
                <td class="empty-state" colspan="8">No payloads match the current filters.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section v-if="activeTab === 'results'" class="panel">
        <h2>Pingbacks</h2>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Protocol</th>
              <th>Payload</th>
              <th>Target</th>
              <th>IP</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in state.pingbacks" :key="item.id">
              <td>{{ item.received_at }}</td>
              <td>{{ item.callback_protocol }}</td>
              <td>{{ item.payload_key }}</td>
              <td>{{ item.target_url }}</td>
              <td>{{ item.remote_address }}</td>
              <td>{{ item.severity }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section v-if="activeTab === 'settings'" class="panel">
        <h2>Settings</h2>
        <pre>{{ JSON.stringify(state.settings, null, 2) }}</pre>
      </section>
    </main>
  </div>
</template>
