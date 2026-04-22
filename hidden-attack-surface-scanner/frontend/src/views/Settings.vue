<script setup>
import { onMounted, reactive, ref } from 'vue';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';
import { useToastStore } from '../stores/toast.js';

const app = useAppStore();
const toast = useToastStore();
const saving = ref(false);

const form = reactive({
  interactsh_server: '',
  interactsh_token: '',
  default_concurrency: 10,
  default_rate_limit: 20,
  default_timeout_minutes: 1440,
  default_origin: '',
  default_referer: '',
  own_ip_action: 'mark',
});

onMounted(async () => {
  await app.loadSettings();
  if (app.settings) {
    form.interactsh_server = app.settings.interactsh?.server_url || '';
    form.interactsh_token = app.settings.interactsh?.token || '';
    form.default_concurrency = app.settings.scanner?.default_concurrency || 10;
    form.default_rate_limit = app.settings.scanner?.default_rate_limit || 20;
    form.default_timeout_minutes = app.settings.scanner?.default_timeout_minutes || 1440;
    form.default_origin = app.settings.scanner?.default_origin || '';
    form.default_referer = app.settings.scanner?.default_referer || '';
    form.own_ip_action = app.settings.own_ip?.action || 'mark';
  }
});

async function saveSettings() {
  saving.value = true;
  try {
    const payload = {
      interactsh: {
        server_url: form.interactsh_server,
        token: form.interactsh_token,
      },
      scanner: {
        default_concurrency: Number(form.default_concurrency),
        default_rate_limit: Number(form.default_rate_limit),
        default_timeout_minutes: Number(form.default_timeout_minutes),
        default_origin: form.default_origin,
        default_referer: form.default_referer,
      },
      own_ip: {
        action: form.own_ip_action,
      },
    };
    await api.updateSettings(payload);
    await app.loadSettings();
    toast.success('Settings saved');
  } catch (e) {
    toast.error(e.message);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="settings-page">
    <!-- Interactsh Settings -->
    <div class="panel settings-section">
      <div class="settings-title">
        <h2>🌐 Interactsh / OOB Configuration</h2>
        <p class="muted">Configure the out-of-band callback server. Leave empty to use public servers (oast.pro, oast.live, etc).</p>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Interactsh Server URL</label>
          <input v-model="form.interactsh_server" placeholder="oob.yourdomain.com (empty = public servers)" />
          <small class="muted">Self-hosted server domain. Leave blank for public Interactsh servers.</small>
        </div>
        <div class="form-group">
          <label>Interactsh Token</label>
          <input v-model="form.interactsh_token" type="password" placeholder="Authentication token" />
          <small class="muted">Required for self-hosted servers with token auth.</small>
        </div>
      </div>
    </div>

    <!-- Scanner Defaults -->
    <div class="panel settings-section">
      <div class="settings-title">
        <h2>⚡ Scanner Defaults</h2>
        <p class="muted">Default values for new scan tasks. Can be overridden per scan.</p>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Default Concurrency</label>
          <input v-model.number="form.default_concurrency" type="number" min="1" max="500" />
          <small class="muted">Number of parallel goroutines sending requests.</small>
        </div>
        <div class="form-group">
          <label>Default Rate Limit (QPS)</label>
          <input v-model.number="form.default_rate_limit" type="number" min="0" />
          <small class="muted">Max requests per second. 0 = unlimited.</small>
        </div>
        <div class="form-group">
          <label>Default Callback Timeout (minutes)</label>
          <input v-model.number="form.default_timeout_minutes" type="number" min="1" />
          <small class="muted">How long to wait for OOB callbacks after all requests are sent.</small>
        </div>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label>Default Origin <small>(for %o placeholder)</small></label>
          <input v-model="form.default_origin" placeholder="https://example.com" />
        </div>
        <div class="form-group">
          <label>Default Referer <small>(for %r placeholder)</small></label>
          <input v-model="form.default_referer" placeholder="https://example.com/" />
        </div>
      </div>
    </div>

    <!-- Interactions Settings (like Burp plugin) -->
    <div class="panel settings-section">
      <div class="settings-title">
        <h2>🎯 Interaction Settings</h2>
        <p class="muted">Configure how pingbacks from your own IP address should be handled.</p>
      </div>

      <div class="form-group">
        <label>Action for pingback from own IP</label>
        <div class="radio-group">
          <label class="radio-label">
            <input type="radio" v-model="form.own_ip_action" value="report" />
            <div>
              <strong>Report</strong>
              <small class="muted">Don't treat it in any special way, report it like any other pingback.</small>
            </div>
          </label>
          <label class="radio-label">
            <input type="radio" v-model="form.own_ip_action" value="mark" />
            <div>
              <strong>Report, but mark as own IP</strong>
              <small class="muted">Report it but flag it as from_own_ip so you can filter it out.</small>
            </div>
          </label>
          <label class="radio-label">
            <input type="radio" v-model="form.own_ip_action" value="drop" />
            <div>
              <strong>Don't report</strong>
              <small class="muted">Silently discard pingbacks that come from your own IP.</small>
            </div>
          </label>
        </div>
      </div>
    </div>

    <!-- Current Config (read-only) -->
    <div class="panel settings-section">
      <div class="settings-title">
        <h2>📋 Current Server Configuration</h2>
        <p class="muted">Raw configuration currently loaded on the backend.</p>
      </div>
      <pre class="config-dump">{{ JSON.stringify(app.settings, null, 2) }}</pre>
    </div>

    <!-- Save -->
    <div class="form-actions">
      <button class="primary" :disabled="saving" @click="saveSettings">
        {{ saving ? 'Saving...' : '💾 Save Settings' }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  gap: 20px;
  max-width: 900px;
}
.settings-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.settings-title h2 {
  margin-bottom: 4px;
}
.settings-title .muted {
  margin: 0;
}
.radio-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: 8px;
}
.radio-label {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: border-color var(--transition-fast), background var(--transition-fast);
}
.radio-label:hover {
  border-color: var(--accent);
  background: var(--accent-dim);
}
.radio-label input[type="radio"] {
  margin-top: 3px;
  accent-color: var(--accent);
}
.radio-label div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.radio-label strong {
  font-size: 0.9rem;
}
.radio-label small {
  font-size: 0.8rem;
}
.config-dump {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 16px;
  max-height: 300px;
  overflow: auto;
}
</style>
