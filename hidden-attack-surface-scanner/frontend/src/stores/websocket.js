import { defineStore } from 'pinia';
import { ref } from 'vue';

export const useWebSocketStore = defineStore('websocket', () => {
    const connected = ref(false);
    const logs = ref([]);
    const maxLogs = 2000;
    let ws = null;
    let reconnectTimer = null;
    let shouldReconnect = false;
    const listeners = new Set();

    function addLog(level, message, meta = {}) {
        const entry = {
            id: Date.now() + Math.random(),
            time: new Date().toISOString(),
            level,
            message,
            ...meta,
        };
        logs.value.push(entry);
        if (logs.value.length > maxLogs) {
            logs.value = logs.value.slice(-maxLogs);
        }
    }

    function connect() {
        if (ws && ws.readyState <= 1) return;
        shouldReconnect = true;

        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${protocol}://${window.location.host}/api/ws`);

        ws.onopen = () => {
            connected.value = true;
            addLog('info', 'WebSocket connected');
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                const scanID = msg.scan_id || msg.task_id;
                listeners.forEach(fn => fn(msg));

                if (msg.type === 'scan_progress') {
                    const batch = msg.batch_count ? ` batch ${msg.current_batch || 0}/${msg.batch_count}` : '';
                    const target = msg.current_target ? ` target ${msg.current_target}` : '';
                    const stage = msg.current_stage ? ` stage ${msg.current_stage}` : '';
                    const completed = msg.target_count ? ` hosts ${msg.completed_targets || 0}/${msg.target_count}` : '';
                    addLog('debug', `Scan ${scanID}:${batch}${completed}${stage}${target} requests ${msg.sent}/${msg.total}`, { scan_id: scanID });
                } else if (msg.type === 'new_pingback' || msg.type === 'pingback') {
                    const pb = msg.data || {};
                    addLog('warn', `Pingback [${pb.callback_protocol}] from ${pb.target_url} via ${pb.payload_key} (${pb.severity})`, { scan_id: pb.scan_task_id });
                } else if (msg.type === 'scan_status' || msg.type === 'task_status') {
                    addLog('info', `Scan ${scanID || ''} status: ${msg.status || 'updated'}`, { scan_id: scanID });
                } else if (msg.type === 'log' || msg.type === 'scan_log') {
                    addLog(msg.level || 'debug', msg.message || JSON.stringify(msg), { ...msg, scan_id: scanID });
                } else if (msg.type === 'connected') {
                    addLog('info', 'Server confirmed connection');
                }
            } catch {
                addLog('debug', `WS raw: ${event.data}`);
            }
        };

        ws.onclose = () => {
            connected.value = false;
            if (shouldReconnect) {
                addLog('warn', 'WebSocket disconnected, reconnecting in 3s...');
                scheduleReconnect();
            }
        };

        ws.onerror = () => {
            addLog('error', 'WebSocket error');
        };
    }

    function scheduleReconnect() {
        if (!shouldReconnect || reconnectTimer) return;
        reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            connect();
        }, 3000);
    }

    function disconnect() {
        shouldReconnect = false;
        connected.value = false;
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
        if (ws) {
            try { ws.close(); } catch { /* ignore */ }
            ws = null;
        }
    }

    function onMessage(fn) {
        listeners.add(fn);
        return () => listeners.delete(fn);
    }

    function clearLogs() {
        logs.value = [];
    }

    return { connected, logs, connect, disconnect, onMessage, clearLogs, addLog };
});
