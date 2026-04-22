<script setup>
import { computed, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { routes } from './router/index.js';
import { useAppStore } from './stores/app.js';
import { useWebSocketStore } from './stores/websocket.js';
import { useToastStore } from './stores/toast.js';

const router = useRouter();
const route = useRoute();
const app = useAppStore();
const ws = useWebSocketStore();
const toast = useToastStore();

const routeCopy = {
  dashboard: 'Recent activity, active scans, and callback pressure.',
  scans: 'Create scan jobs, monitor dispatch progress, and stop noisy runs.',
  payloads: 'Control the exact headers, params, and raw variants used by the scanner.',
  results: 'Inspect callbacks, pivot to the originating payload, and export evidence.',
  settings: 'Set OOB defaults, scan limits, and own-IP handling behavior.',
  debug: 'Read websocket logs and server-side scan events as they arrive.',
};

const activeLabel = computed(() => route.meta?.title || 'Dashboard');
const activeCopy = computed(() => routeCopy[route.name] || 'Operate the scanner from a single control surface.');
const navItems = computed(() => routes.filter((item) => item.name !== 'debug'));

onMounted(async () => {
  await app.refreshAll();
  ws.connect();
  ws.onMessage((msg) => app.handleWsMessage(msg));
});

function navTo(name) {
  router.push({ name });
}
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="sidebar-brand" @click="navTo('dashboard')">
        <span class="brand-mark">HS</span>
        <div class="brand-copy">
          <strong>Hidden Surface Scanner</strong>
          <small>OOB-first detection workspace</small>
        </div>
      </div>

      <nav class="sidebar-nav">
        <button
          v-for="r in navItems"
          :key="r.name"
          :class="['nav-button', { active: route.name === r.name }]"
          @click="navTo(r.name)"
        >
          <span class="nav-icon">{{ r.meta.icon }}</span>
          <span class="nav-text">{{ r.meta.title }}</span>
        </button>
      </nav>

      <div class="sidebar-summary">
        <div class="summary-row">
          <span>WebSocket</span>
          <strong :class="['status-inline', ws.connected ? 'is-online' : 'is-offline']">
            {{ ws.connected ? 'online' : 'offline' }}
          </strong>
        </div>
        <div class="summary-row">
          <span>Active scans</span>
          <strong>{{ app.stats.active_count || 0 }}</strong>
        </div>
        <div class="summary-row">
          <span>Pingbacks</span>
          <strong>{{ app.stats.pingback_count || 0 }}</strong>
        </div>
      </div>
    </aside>

    <main class="content">
      <header class="page-header">
        <div class="page-heading">
          <span class="page-kicker">{{ activeLabel }}</span>
          <h1 class="page-title">{{ activeLabel }}</h1>
          <p class="page-copy">{{ activeCopy }}</p>
        </div>

        <div class="header-strip">
          <div class="header-chip">
            <span>Scans</span>
            <strong>{{ app.stats.scan_count || 0 }}</strong>
          </div>
          <div class="header-chip">
            <span>Active</span>
            <strong>{{ app.stats.active_count || 0 }}</strong>
          </div>
          <div class="header-chip accent">
            <span>Pingbacks</span>
            <strong>{{ app.stats.pingback_count || 0 }}</strong>
          </div>
        </div>
      </header>

      <div class="page-body">
        <router-view v-slot="{ Component }">
          <transition name="tab-content" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </div>
    </main>

    <div class="toast-container">
      <div
        v-for="t in toast.items"
        :key="t.id"
        :class="['toast', `toast-${t.type}`]"
        @click="toast.remove(t.id)"
      >
        {{ t.message }}
      </div>
    </div>
  </div>
</template>
