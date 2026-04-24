import { defineStore } from 'pinia';
import { ref, reactive } from 'vue';
import { api } from '../api/index.js';

export const useAppStore = defineStore('app', () => {
    const stats = ref({ scan_count: 0, active_count: 0, pingback_count: 0, recent: [] });
    const scans = ref([]);
    const payloads = ref([]);
    const pingbacks = ref([]);
    const settings = ref(null);
    const loading = reactive({ stats: false, scans: false, payloads: false, pingbacks: false, settings: false });

    async function loadStats() {
        loading.stats = true;
        try { stats.value = await api.getStats(); } catch { /* ignore */ }
        loading.stats = false;
    }

    async function loadScans() {
        loading.scans = true;
        try { scans.value = await api.listScans(); } catch { /* ignore */ }
        loading.scans = false;
    }

    async function loadPayloads() {
        loading.payloads = true;
        try { payloads.value = await api.listPayloads(); } catch { /* ignore */ }
        loading.payloads = false;
    }

    async function loadPingbacks(params = {}) {
        loading.pingbacks = true;
        try { pingbacks.value = await api.listPingbacks(params); } catch { /* ignore */ }
        loading.pingbacks = false;
    }

    async function loadSettings() {
        loading.settings = true;
        try { settings.value = await api.getSettings(); } catch { /* ignore */ }
        loading.settings = false;
    }

    async function refreshAll() {
        await Promise.all([loadStats(), loadScans(), loadPayloads(), loadPingbacks(), loadSettings()]);
    }

    function handleWsMessage(msg) {
        const scanID = msg.scan_id || msg.task_id;

        if (msg.type === 'pingback' || msg.type === 'new_pingback') {
            if (msg.data) {
                pingbacks.value.unshift(msg.data);
                stats.value.pingback_count = (stats.value.pingback_count || 0) + 1;
                if (stats.value.recent) {
                    stats.value.recent.unshift(msg.data);
                    if (stats.value.recent.length > 10) stats.value.recent = stats.value.recent.slice(0, 10);
                }
            }
        }
        if (msg.type === 'task_status' || msg.type === 'scan_status') {
            loadScans();
            loadStats();
        }
        if (msg.type === 'scan_progress') {
            const scan = scans.value.find(s => s.id === scanID);
            if (scan) {
                scan.request_sent = msg.sent;
                scan._total = msg.total;
                scan.estimated_requests = msg.estimated_requests ?? scan.estimated_requests;
                scan.status = msg.status || scan.status;
                scan.target_count = msg.target_count ?? scan.target_count;
                scan.batch_size = msg.batch_size ?? scan.batch_size;
                scan.batch_count = msg.batch_count ?? scan.batch_count;
                scan.current_batch = msg.current_batch ?? scan.current_batch;
                scan.completed_targets = msg.completed_targets ?? scan.completed_targets;
                scan.current_target = msg.current_target ?? scan.current_target;
                scan.current_stage = msg.current_stage ?? scan.current_stage;
            }
        }
    }

    return {
        stats, scans, payloads, pingbacks, settings, loading,
        loadStats, loadScans, loadPayloads, loadPingbacks, loadSettings,
        refreshAll, handleWsMessage,
    };
});
