<script setup>
import { onMounted, reactive, ref } from 'vue';
import { api } from '../api/index.js';
import { useAppStore } from '../stores/app.js';
import { useToastStore } from '../stores/toast.js';

const app = useAppStore();
const toast = useToastStore();
const saving = ref(false);
const testingNotification = ref(false);
const form = reactive({
  interactsh_server: '',
  interactsh_token: '',
  default_concurrency: 10,
  default_rate_limit: 20,
  default_timeout_minutes: 1440,
  default_origin: '',
  default_referer: '',
  own_ip_action: 'mark',
  notification_enabled: false,
  feishu_webhook: '',
  frontend_base_url: '',
});

onMounted(async () => {
  await app.loadSettings();
  if (!app.settings) return;
  form.interactsh_server = app.settings.interactsh?.server_url || '';
  form.interactsh_token = app.settings.interactsh?.token || '';
  form.default_concurrency = app.settings.scanner?.default_concurrency || 10;
  form.default_rate_limit = app.settings.scanner?.default_rate_limit || 20;
  form.default_timeout_minutes = app.settings.scanner?.default_timeout_minutes || 1440;
  form.default_origin = app.settings.scanner?.default_origin || '';
  form.default_referer = app.settings.scanner?.default_referer || '';
  form.own_ip_action = app.settings.own_ip?.action || 'mark';
  form.notification_enabled = app.settings.notification?.enabled || false;
  form.feishu_webhook = app.settings.notification?.feishu_webhook || '';
  form.frontend_base_url = app.settings.notification?.frontend_base_url || '';
});

async function saveSettings() {
  saving.value = true;
  try {
    await api.updateSettings({
      interactsh: { server_url: form.interactsh_server, token: form.interactsh_token },
      scanner: { default_concurrency: Number(form.default_concurrency), default_rate_limit: Number(form.default_rate_limit), default_timeout_minutes: Number(form.default_timeout_minutes), default_origin: form.default_origin, default_referer: form.default_referer },
      own_ip: { action: form.own_ip_action },
      notification: { enabled: form.notification_enabled, feishu_webhook: form.feishu_webhook, frontend_base_url: form.frontend_base_url },
    });
    await app.loadSettings();
    toast.success('Settings saved');
  } catch (e) {
    toast.error(e.message);
  } finally {
    saving.value = false;
  }
}

async function sendTestNotification() {
  testingNotification.value = true;
  try {
    const res = await api.testNotification({
      enabled: form.notification_enabled,
      feishu_webhook: form.feishu_webhook,
      frontend_base_url: form.frontend_base_url,
    });
    toast.success(res.response ? `Test sent: ${res.response}` : 'Test notification sent');
  } catch (e) {
    toast.error(e.message);
  } finally {
    testingNotification.value = false;
  }
}
</script>

<template>
  <div class="settings-page">
    <section class="panel">
      <div class="panel-header"><div><h2>Interactsh and OOB defaults</h2><p>Use a public Interactsh backend by leaving these values empty, or point the scanner to your own server and token.</p></div></div>
      <div class="form-grid">
        <div class="form-group form-span-6"><label>Interactsh server URL</label><input v-model="form.interactsh_server" placeholder="oob.example.com" /><small>Leave empty to use the public Interactsh pool.</small></div>
        <div class="form-group form-span-6"><label>Interactsh token</label><input v-model="form.interactsh_token" type="password" placeholder="Optional authentication token" /></div>
        <div class="form-group form-span-4"><label>Default concurrency</label><input v-model.number="form.default_concurrency" type="number" min="1" max="500" /></div>
        <div class="form-group form-span-4"><label>Default rate limit</label><input v-model.number="form.default_rate_limit" type="number" min="0" /></div>
        <div class="form-group form-span-4"><label>Default timeout (minutes)</label><input v-model.number="form.default_timeout_minutes" type="number" min="1" /></div>
        <div class="form-group form-span-6"><label>Default origin</label><input v-model="form.default_origin" placeholder="https://example.com" /></div>
        <div class="form-group form-span-6"><label>Default referer</label><input v-model="form.default_referer" placeholder="https://example.com/" /></div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header"><div><h2>Own-IP handling</h2><p>Choose how the backend should treat callbacks that appear to come from your own infrastructure.</p></div></div>
      <div class="tag-row" style="margin-bottom: 16px"><button class="btn-sm" :class="{ primary: form.own_ip_action === 'report' }" @click="form.own_ip_action = 'report'">Report</button><button class="btn-sm" :class="{ primary: form.own_ip_action === 'mark' }" @click="form.own_ip_action = 'mark'">Mark</button><button class="btn-sm" :class="{ primary: form.own_ip_action === 'drop' }" @click="form.own_ip_action = 'drop'">Drop</button></div>
      <div class="key-list"><div class="kv-row"><span>Report</span><span class="muted">Store the callback normally.</span></div><div class="kv-row"><span>Mark</span><span class="muted">Store it, but label it as from_own_ip.</span></div><div class="kv-row"><span>Drop</span><span class="muted">Ignore it and keep it out of the results list.</span></div></div>
    </section>

    <section class="panel">
      <div class="panel-header"><div><h2>Notifications</h2><p>Feishu card alerts cover both high-value findings and scan runtime failures.</p></div></div>
      <div class="form-grid">
        <div class="form-group form-span-3"><label>Enable notifications</label><div class="tag-row"><button class="btn-sm" :class="{ primary: form.notification_enabled }" @click="form.notification_enabled = true">Enabled</button><button class="btn-sm" :class="{ primary: !form.notification_enabled }" @click="form.notification_enabled = false">Disabled</button></div><small>DNS-only findings do not notify. HTTP/HTTPS findings do.</small></div>
        <div class="form-group form-span-9"><label>Feishu webhook</label><input v-model="form.feishu_webhook" type="password" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." /><small>The backend sends structured cards for finding alerts and scan runtime failures.</small></div>
        <div class="form-group form-span-6"><label>Frontend base URL</label><input v-model="form.frontend_base_url" placeholder="http://154.219.112.133:8082" /><small>Optional. If set, the Feishu message includes a direct link to the Results page.</small></div>
        <div class="form-group form-span-6"><label>Notification policy</label><div class="key-list"><div class="kv-row"><span>Initial alert</span><span class="muted">First confirmed HTTP/HTTPS finding for the same target + payload.</span></div><div class="kv-row"><span>Upgrade alert</span><span class="muted">Confidence upgrades from confirmed to strong after DNS joins the same finding.</span></div><div class="kv-row"><span>Runtime failure</span><span class="muted">A scan task enters failed state or crashes with a panic.</span></div><div class="kv-row"><span>Noisy cases</span><span class="muted">DNS-only findings are stored, but not pushed to Feishu.</span></div></div></div>
      </div>
      <div class="form-actions" style="margin-top: 16px"><button class="ghost-button" :disabled="testingNotification" @click="sendTestNotification">{{ testingNotification ? 'Sending test...' : 'Send Feishu card test' }}</button></div>
    </section>

    <section class="panel">
      <div class="panel-header"><div><h2>Current backend configuration</h2><p>Raw settings currently loaded by the server.</p></div></div>
      <pre>{{ JSON.stringify(app.settings, null, 2) }}</pre>
    </section>

    <div class="form-actions"><button class="primary" :disabled="saving" @click="saveSettings">{{ saving ? 'Saving...' : 'Save settings' }}</button></div>
  </div>
</template>
