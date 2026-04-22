<script setup>
import { onMounted } from 'vue';
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
        <span class="brand-icon">⬡</span>
        <div class="brand-text">
          <strong>HASS</strong>
          <small>Hidden Attack Surface Scanner</small>
        </div>
      </div>

      <nav class="sidebar-nav">
        <button
          v-for="r in routes"
          :key="r.name"
          :class="{ active: route.name === r.name }"
          @click="navTo(r.name)"
        >
          <span class="nav-icon">{{ r.meta.icon }}</span>
          <span>{{ r.meta.title }}</span>
        </button>
      </nav>

      <div class="sidebar-footer">
        <div class="ws-status" :class="{ online: ws.connected }">
          <span class="ws-dot"></span>
          {{ ws.connected ? 'Connected' : 'Disconnected' }}
        </div>
      </div>
    </aside>

    <main class="content">
      <header class="page-header">
        <h1 class="page-title">{{ route.meta?.title || 'Dashboard' }}</h1>
        <div class="header-actions">
          <span class="header-stat" data-tooltip="Active scans">
            🔍 {{ app.stats.active_count }} active
          </span>
          <span class="header-stat" data-tooltip="Total pingbacks">
            🎯 {{ app.stats.pingback_count }} pingbacks
          </span>
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

    <!-- Toast notifications -->
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
