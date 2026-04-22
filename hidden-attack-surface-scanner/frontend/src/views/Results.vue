<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { api } from '../api/index.js';

const route = useRoute();

const queryFilters = reactive({ severity: '', protocol: '', scan_task_id: '' });
const ui = reactive({ search: '', view: 'findings', hideDnsOnly: false });

const expandedFindingId = ref(null);
const expandedEventId = ref(null);
const openTargetIds = ref([]);
const copiedKey = ref('');
const pingbacks = ref([]);
const loading = ref(false);

const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
const confidenceRank = { strong: 3, confirmed: 2, possible: 1, observed: 0 };
const protocolRank = { https: 5, http: 4, dns: 3, smtp: 2, ldap: 1, ftp: 0 };

onMounted(async () => {
  if (route.query.scan_task_id) queryFilters.scan_task_id = route.query.scan_task_id;
  await loadData();
});

watch(queryFilters, () => loadData(), { deep: true });

async function loadData() {
  loading.value = true;
  try {
    pingbacks.value = await api.listPingbacks({
      severity: queryFilters.severity,
      protocol: queryFilters.protocol,
      scan_task_id: queryFilters.scan_task_id,
    });
  } catch {
    pingbacks.value = [];
  }
  loading.value = false;
}

function normalizeProtocol(value) {
  return String(value || '').trim().toLowerCase();
}

function protocolLabel(value) {
  const normalized = normalizeProtocol(value);
  return normalized ? normalized.toUpperCase() : 'UNKNOWN';
}

function sevClass(value) {
  return `badge badge-${value || 'info'}`;
}

function protoClass(value) {
  return `badge protocol-${normalizeProtocol(value) || 'unknown'}`;
}

function confidenceClass(value) {
  return `badge badge-confidence-${value || 'observed'}`;
}

function confidenceLabel(value) {
  switch (value) {
    case 'strong':
      return 'Strong';
    case 'confirmed':
      return 'Confirmed';
    case 'possible':
      return 'Possible';
    default:
      return 'Observed';
  }
}

function formatTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

function delaySummary(events) {
  const values = events.map((event) => Number(event.delay_seconds || 0)).filter((value) => value > 0);
  if (!values.length) return '-';
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (Math.abs(min - max) < 0.05) return `${min.toFixed(1)}s`;
  return `${min.toFixed(1)}-${max.toFixed(1)}s`;
}

function remoteSummary(remotes) {
  if (!remotes.length) return '-';
  if (remotes.length === 1) return remotes[0];
  return `${remotes[0]} +${remotes.length - 1}`;
}

function sortByTimeDesc(items, field = 'received_at') {
  return [...items].sort((a, b) => new Date(b[field] || 0) - new Date(a[field] || 0));
}

function summarizeBucket(protocol, events) {
  const sortedEvents = sortByTimeDesc(events);
  const remotes = [...new Set(sortedEvents.map((event) => event.remote_address).filter(Boolean))];
  const severity = sortedEvents.reduce((best, event) =>
    (severityRank[event.severity] || 0) > (severityRank[best] || 0) ? event.severity : best
  , sortedEvents[0]?.severity || 'low');

  return {
    protocol,
    label: protocolLabel(protocol),
    count: sortedEvents.length,
    events: sortedEvents,
    remotes,
    remoteSummary: remoteSummary(remotes),
    severity,
    firstSeenAt: sortedEvents[sortedEvents.length - 1]?.received_at || '',
    lastSeenAt: sortedEvents[0]?.received_at || '',
    sampleRaw: sortedEvents.find((event) => event.raw_request)?.raw_request || '',
  };
}

function buildEvidence(protocols) {
  const hasDNS = protocols.includes('dns');
  const hasWeb = protocols.includes('http') || protocols.includes('https');

  if (hasDNS && hasWeb) return 'DNS + HTTP/HTTPS';
  if (hasDNS) return 'DNS only';
  if (protocols.length === 1) return `${protocolLabel(protocols[0])} only`;
  return protocols.map((protocol) => protocolLabel(protocol)).join(' + ');
}

function buildConfidence(protocols) {
  const hasDNS = protocols.includes('dns');
  const hasWeb = protocols.includes('http') || protocols.includes('https');

  if (hasDNS && hasWeb) return 'strong';
  if (hasWeb) return 'confirmed';
  if (hasDNS) return 'possible';
  return 'observed';
}

const payloadGroups = computed(() => {
  const groups = new Map();

  for (const item of pingbacks.value) {
    const key = item.unique_id || item.id;
    if (!groups.has(key)) {
      groups.set(key, {
        id: key,
        unique_id: item.unique_id,
        scan_task_id: item.scan_task_id,
        target_url: item.target_url,
        payload_type: item.payload_type,
        payload_key: item.payload_key,
        payload_value: item.payload_value,
        from_own_ip: item.from_own_ip,
        severity: item.severity,
        latest_received_at: item.received_at,
        events: [],
      });
    }

    const group = groups.get(key);
    group.events.push(item);

    if (new Date(item.received_at || 0).getTime() > new Date(group.latest_received_at || 0).getTime()) {
      group.latest_received_at = item.received_at;
    }
    if ((severityRank[item.severity] || 0) > (severityRank[group.severity] || 0)) {
      group.severity = item.severity;
    }
    if (item.from_own_ip) {
      group.from_own_ip = true;
    }
  }

  return Array.from(groups.values())
    .map((group) => {
      const events = sortByTimeDesc(group.events);
      const buckets = new Map();
      for (const event of events) {
        const protocol = normalizeProtocol(event.callback_protocol) || 'unknown';
        if (!buckets.has(protocol)) buckets.set(protocol, []);
        buckets.get(protocol).push(event);
      }

      const protocolBuckets = Array.from(buckets.entries())
        .map(([protocol, items]) => summarizeBucket(protocol, items))
        .sort((a, b) => (protocolRank[b.protocol] || 0) - (protocolRank[a.protocol] || 0));

      const protocols = protocolBuckets.map((bucket) => bucket.protocol);
      const webBucket = protocolBuckets.find((bucket) => bucket.protocol === 'https') || protocolBuckets.find((bucket) => bucket.protocol === 'http');
      const remotes = [...new Set(events.map((event) => event.remote_address).filter(Boolean))];
      const trigger = events.find((event) => event.trigger_raw_request || event.replay_command || event.trigger_url) || events[0] || {};

      return {
        ...group,
        events,
        protocolBuckets,
        protocols,
        evidence: buildEvidence(protocols),
        confidence: buildConfidence(protocols),
        bestRemote: webBucket?.remoteSummary || remoteSummary(remotes),
        delay: delaySummary(events),
        triggerMethod: trigger.trigger_method || '',
        triggerURL: trigger.trigger_url || '',
        triggerRawRequest: trigger.trigger_raw_request || '',
        replayCommand: trigger.replay_command || '',
        triggerResponseStatus: trigger.trigger_response_status ?? null,
      };
    })
    .sort((a, b) => {
      if ((confidenceRank[b.confidence] || 0) !== (confidenceRank[a.confidence] || 0)) {
        return (confidenceRank[b.confidence] || 0) - (confidenceRank[a.confidence] || 0);
      }
      if ((severityRank[b.severity] || 0) !== (severityRank[a.severity] || 0)) {
        return (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
      }
      return new Date(b.latest_received_at || 0) - new Date(a.latest_received_at || 0);
    });
});

function findingSearchText(finding) {
  return [
    finding.scan_task_id,
    finding.target_url,
    finding.payload_key,
    finding.payload_value,
    finding.payload_type,
    finding.evidence,
    finding.confidence,
    finding.severity,
    finding.bestRemote,
    finding.triggerMethod,
    finding.triggerURL,
    finding.triggerRawRequest,
    finding.replayCommand,
    ...finding.protocolBuckets.flatMap((bucket) => [
      bucket.protocol,
      bucket.remoteSummary,
      ...bucket.remotes,
      ...bucket.events.flatMap((event) => [event.reverse_dns, event.raw_request]),
    ]),
  ]
    .join(' ')
    .toLowerCase();
}

const filteredFindings = computed(() => {
  const needle = ui.search.trim().toLowerCase();

  return payloadGroups.value.filter((finding) => {
    if (ui.hideDnsOnly && finding.confidence === 'possible') return false;
    if (!needle) return true;
    return findingSearchText(finding).includes(needle);
  });
});

const targetGroups = computed(() => {
  const groups = new Map();

  for (const finding of filteredFindings.value) {
    const key = `${finding.scan_task_id || 'global'}::${finding.target_url}`;
    if (!groups.has(key)) {
      groups.set(key, {
        id: key,
        scan_task_id: finding.scan_task_id,
        target_url: finding.target_url,
        findings: [],
      });
    }
    groups.get(key).findings.push(finding);
  }

  return Array.from(groups.values())
    .map((group) => {
      const findings = [...group.findings].sort((a, b) => {
        if ((confidenceRank[b.confidence] || 0) !== (confidenceRank[a.confidence] || 0)) {
          return (confidenceRank[b.confidence] || 0) - (confidenceRank[a.confidence] || 0);
        }
        if ((severityRank[b.severity] || 0) !== (severityRank[a.severity] || 0)) {
          return (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
        }
        return new Date(b.latest_received_at || 0) - new Date(a.latest_received_at || 0);
      });

      return {
        ...group,
        findings,
        findingCount: findings.length,
        strongCount: findings.filter((finding) => finding.confidence === 'strong').length,
        confirmedCount: findings.filter((finding) => finding.confidence === 'confirmed').length,
        possibleCount: findings.filter((finding) => finding.confidence === 'possible').length,
        latestSeenAt: findings[0]?.latest_received_at || '',
      };
    })
    .sort((a, b) => {
      const leftScore = a.strongCount * 100 + a.confirmedCount * 10 + a.findingCount;
      const rightScore = b.strongCount * 100 + b.confirmedCount * 10 + b.findingCount;
      if (rightScore !== leftScore) return rightScore - leftScore;
      return new Date(b.latestSeenAt || 0) - new Date(a.latestSeenAt || 0);
    });
});

watch(targetGroups, (groups) => {
  if (!groups.length) {
    openTargetIds.value = [];
    return;
  }

  const current = openTargetIds.value.filter((id) => groups.some((group) => group.id === id));
  if (current.length) {
    openTargetIds.value = current;
    return;
  }

  openTargetIds.value = [groups[0].id];
}, { immediate: true });

function eventSearchText(event) {
  return [
    event.scan_task_id,
    event.target_url,
    event.payload_key,
    event.payload_value,
    event.payload_type,
    event.callback_protocol,
    event.remote_address,
    event.reverse_dns,
    event.raw_request,
    event.trigger_method,
    event.trigger_url,
    event.trigger_raw_request,
    event.replay_command,
    event.severity,
    event.unique_id,
  ]
    .join(' ')
    .toLowerCase();
}

const filteredEvents = computed(() => {
  const needle = ui.search.trim().toLowerCase();
  if (!needle) return pingbacks.value;
  return pingbacks.value.filter((event) => eventSearchText(event).includes(needle));
});

const summaryStats = computed(() => {
  if (ui.view === 'events') {
    return {
      total: filteredEvents.value.length,
      label: 'Visible events',
      strong: filteredEvents.value.filter((event) => ['http', 'https'].includes(normalizeProtocol(event.callback_protocol))).length,
      strongLabel: 'HTTP/HTTPS',
      possible: filteredEvents.value.filter((event) => normalizeProtocol(event.callback_protocol) === 'dns').length,
      possibleLabel: 'DNS',
      ownIP: filteredEvents.value.filter((event) => event.from_own_ip).length,
      ownLabel: 'Own IP marked',
    };
  }

  const visibleTargets = targetGroups.value.length;
  return {
    total: filteredFindings.value.length,
    label: 'Visible findings',
    strong: filteredFindings.value.filter((finding) => finding.confidence === 'strong').length,
    strongLabel: 'Strong',
    possible: filteredFindings.value.filter((finding) => finding.confidence === 'possible').length,
    possibleLabel: 'DNS only',
    ownIP: visibleTargets,
    ownLabel: 'Targets',
  };
});

const searchPlaceholder = computed(() =>
  ui.view === 'events'
    ? 'Search raw events, callback IPs, payloads, or raw callback data'
    : 'Search targets, payloads, confidence, protocols, or raw callback data'
);

const exportRows = computed(() => {
  if (ui.view === 'events') return filteredEvents.value;

  return filteredFindings.value.map((finding) => ({
    id: finding.id,
    scan_task_id: finding.scan_task_id,
    target_url: finding.target_url,
    payload_type: finding.payload_type,
    payload_key: finding.payload_key,
    payload_value: finding.payload_value,
    trigger_method: finding.triggerMethod,
    trigger_url: finding.triggerURL,
    trigger_response_status: finding.triggerResponseStatus,
    evidence: finding.evidence,
    confidence: finding.confidence,
    protocols: finding.protocolBuckets.map((bucket) => `${bucket.label} x${bucket.count}`).join(' | '),
    best_remote: finding.bestRemote,
    severity: finding.severity,
    delay: finding.delay,
    latest_received_at: finding.latest_received_at,
    own_ip: finding.from_own_ip,
  }));
});

function exportJSON() {
  const blob = new Blob([JSON.stringify(exportRows.value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = ui.view === 'events' ? 'pingback-events.json' : 'pingback-findings.json';
  anchor.click();
  URL.revokeObjectURL(url);
}

function exportCSV() {
  if (!exportRows.value.length) return;
  const headers = Object.keys(exportRows.value[0]);
  const rows = exportRows.value.map((item) => headers.map((header) => JSON.stringify(item[header] ?? '')).join(','));
  const blob = new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = ui.view === 'events' ? 'pingback-events.csv' : 'pingback-findings.csv';
  anchor.click();
  URL.revokeObjectURL(url);
}

function toggleFinding(id) {
  expandedFindingId.value = expandedFindingId.value === id ? null : id;
}

function toggleEvent(id) {
  expandedEventId.value = expandedEventId.value === id ? null : id;
}

function toggleTarget(id) {
  if (openTargetIds.value.includes(id)) {
    openTargetIds.value = openTargetIds.value.filter((item) => item !== id);
    return;
  }
  openTargetIds.value = [...openTargetIds.value, id];
}

function isTargetOpen(id) {
  return openTargetIds.value.includes(id);
}

async function copyText(key, value) {
  if (!value) return;
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = value;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'absolute';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    copiedKey.value = key;
    window.setTimeout(() => {
      if (copiedKey.value === key) copiedKey.value = '';
    }, 1800);
  } catch {
    copiedKey.value = '';
  }
}
</script>

<template>
  <div class="results-page">
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Callback evidence</h2>
          <p v-if="ui.view === 'findings'">Default to findings, not raw noise. Targets are grouped first, then each payload shows its DNS and HTTP/HTTPS evidence together.</p>
          <p v-else>Raw event mode keeps the original callback log for deeper triage. Use it only when you need exact callback timing and raw payload traces.</p>
        </div>
        <div class="action-row">
          <div class="mode-switch">
            <button class="btn-sm" :class="{ active: ui.view === 'findings' }" @click="ui.view = 'findings'">Findings</button>
            <button class="btn-sm" :class="{ active: ui.view === 'events' }" @click="ui.view = 'events'">Events</button>
          </div>
          <button class="ghost-button" @click="exportJSON">Export JSON</button>
          <button class="ghost-button" @click="exportCSV">Export CSV</button>
        </div>
      </div>

      <div class="stat-strip">
        <div class="stat-block"><span>{{ summaryStats.label }}</span><strong>{{ summaryStats.total }}</strong></div>
        <div class="stat-block"><span>{{ summaryStats.strongLabel }}</span><strong>{{ summaryStats.strong }}</strong></div>
        <div class="stat-block"><span>{{ summaryStats.possibleLabel }}</span><strong>{{ summaryStats.possible }}</strong></div>
        <div class="stat-block"><span>{{ summaryStats.ownLabel }}</span><strong>{{ summaryStats.ownIP }}</strong></div>
      </div>

      <div class="filter-grid" style="margin-top: 18px">
        <div class="form-group form-span-6"><label>Search</label><input v-model="ui.search" :placeholder="searchPlaceholder" /></div>
        <div class="form-group form-span-2"><label>Severity</label><select v-model="queryFilters.severity"><option value="">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
        <div class="form-group form-span-2"><label>Protocol</label><select v-model="queryFilters.protocol"><option value="">All</option><option value="dns">DNS</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="smtp">SMTP</option><option value="ldap">LDAP</option><option value="ftp">FTP</option></select></div>
        <div class="form-group form-span-2"><label>Scan task</label><input v-model="queryFilters.scan_task_id" placeholder="Optional scan id" /></div>
      </div>

      <div class="hint-strip" style="margin-top: 14px" v-if="ui.view === 'findings'">
        <label class="toggle-chip"><input v-model="ui.hideDnsOnly" type="checkbox" /> Hide DNS-only findings</label>
        <span class="muted">Use this when you only want stronger SSRF evidence and do not want DNS-only rows to dominate the page.</span>
      </div>
    </section>

    <section class="panel" style="padding-top: 0" v-if="ui.view === 'findings'">
      <div v-if="targetGroups.length" class="target-stack">
        <article v-for="group in targetGroups" :key="group.id" class="target-card">
          <button class="target-header" @click="toggleTarget(group.id)">
            <div class="target-copy">
              <strong class="mono">{{ group.target_url }}</strong>
              <div class="tag-row">
                <span class="badge badge-info">Findings {{ group.findingCount }}</span>
                <span class="badge badge-confidence-strong">Strong {{ group.strongCount }}</span>
                <span class="badge badge-confidence-confirmed">Confirmed {{ group.confirmedCount }}</span>
                <span class="badge badge-confidence-possible">DNS only {{ group.possibleCount }}</span>
              </div>
            </div>
            <div class="target-meta">
              <span class="mono">{{ formatTime(group.latestSeenAt) }}</span>
              <span class="target-toggle">{{ isTargetOpen(group.id) ? 'Hide' : 'Open' }}</span>
            </div>
          </button>

          <div v-if="isTargetOpen(group.id)" class="target-body">
            <div class="table-shell">
              <table>
                <thead><tr><th class="fit">Open</th><th>Payload</th><th>Evidence</th><th>Confidence</th><th>Protocols</th><th>Best Remote</th><th>Severity</th><th>Delay</th><th>Last Seen</th></tr></thead>
                <tbody>
                  <template v-for="finding in group.findings" :key="finding.id">
                    <tr @click="toggleFinding(finding.id)">
                      <td class="fit">{{ expandedFindingId === finding.id ? 'Hide' : 'Open' }}</td>
                      <td>
                        <div class="finding-main">
                          <strong class="mono">{{ finding.payload_key }}</strong>
                          <small>{{ finding.payload_type }}</small>
                        </div>
                      </td>
                      <td><span class="badge badge-info">{{ finding.evidence }}</span></td>
                      <td><span :class="confidenceClass(finding.confidence)">{{ confidenceLabel(finding.confidence) }}</span></td>
                      <td>
                        <div class="protocol-bar">
                          <span v-for="bucket in finding.protocolBuckets" :key="finding.id + bucket.protocol" :class="protoClass(bucket.protocol)">{{ bucket.label }} x{{ bucket.count }}</span>
                        </div>
                      </td>
                      <td class="mono">{{ finding.bestRemote }}</td>
                      <td><span :class="sevClass(finding.severity)">{{ finding.severity }}</span></td>
                      <td>{{ finding.delay }}</td>
                      <td class="mono">{{ formatTime(finding.latest_received_at) }}</td>
                    </tr>
                    <tr v-if="expandedFindingId === finding.id">
                      <td colspan="9">
                        <div class="detail-panel" style="margin-bottom: 16px">
                          <div class="detail-row"><span class="detail-label">Scan task</span><span class="detail-value mono">{{ finding.scan_task_id }}</span></div>
                          <div class="detail-row"><span class="detail-label">Unique ID</span><span class="detail-value mono">{{ finding.unique_id }}</span></div>
                          <div class="detail-row"><span class="detail-label">Payload value</span><span class="detail-value mono">{{ finding.payload_value }}</span></div>
                          <div class="detail-row"><span class="detail-label">Target URL</span><span class="detail-value mono">{{ finding.target_url }}</span></div>
                        </div>

                        <div class="bucket-card" style="margin-bottom: 16px" v-if="finding.triggerRawRequest || finding.replayCommand">
                          <div class="bucket-header">
                            <div>
                              <strong>Trigger request</strong>
                              <div class="tag-row" style="margin-top: 8px">
                                <span class="badge badge-info">{{ finding.triggerMethod || 'REQUEST' }}</span>
                                <span class="badge badge-info" v-if="finding.triggerResponseStatus">Response {{ finding.triggerResponseStatus }}</span>
                              </div>
                            </div>
                            <div class="action-row">
                              <button class="btn-sm" @click.stop="copyText('finding-raw-' + finding.id, finding.triggerRawRequest)" :disabled="!finding.triggerRawRequest">{{ copiedKey === 'finding-raw-' + finding.id ? 'Copied Raw' : 'Copy Raw HTTP' }}</button>
                              <button class="btn-sm" @click.stop="copyText('finding-replay-' + finding.id, finding.replayCommand)" :disabled="!finding.replayCommand">{{ copiedKey === 'finding-replay-' + finding.id ? 'Copied Replay' : 'Copy Replay' }}</button>
                            </div>
                          </div>

                          <div class="detail-panel">
                            <div class="detail-row"><span class="detail-label">Request URL</span><span class="detail-value mono">{{ finding.triggerURL || finding.target_url }}</span></div>
                            <div class="detail-row"><span class="detail-label">Replay mode</span><span class="detail-value">{{ finding.replayCommand ? 'Ready' : 'Raw only' }}</span></div>
                          </div>

                          <div v-if="finding.triggerRawRequest" class="detail-row" style="margin-top: 14px">
                            <span class="detail-label">Raw trigger request</span>
                            <pre class="detail-value">{{ finding.triggerRawRequest }}</pre>
                          </div>

                          <div v-if="finding.replayCommand" class="detail-row" style="margin-top: 14px">
                            <span class="detail-label">Replay command</span>
                            <pre class="detail-value">{{ finding.replayCommand }}</pre>
                          </div>
                        </div>

                        <div class="bucket-grid">
                          <article v-for="bucket in finding.protocolBuckets" :key="finding.id + '-' + bucket.protocol" class="bucket-card">
                            <div class="bucket-header">
                              <div class="protocol-bar">
                                <span :class="protoClass(bucket.protocol)">{{ bucket.label }}</span>
                                <span :class="sevClass(bucket.severity)">{{ bucket.severity }}</span>
                              </div>
                              <strong>{{ bucket.count }} event<span v-if="bucket.count !== 1">s</span></strong>
                            </div>

                            <div class="detail-panel">
                              <div class="detail-row"><span class="detail-label">Remote summary</span><span class="detail-value mono">{{ bucket.remoteSummary }}</span></div>
                              <div class="detail-row"><span class="detail-label">First seen</span><span class="detail-value">{{ formatTime(bucket.firstSeenAt) }}</span></div>
                              <div class="detail-row"><span class="detail-label">Last seen</span><span class="detail-value">{{ formatTime(bucket.lastSeenAt) }}</span></div>
                              <div class="detail-row"><span class="detail-label">Distinct remotes</span><span class="detail-value">{{ bucket.remotes.length }}</span></div>
                            </div>

                            <details class="raw-details">
                              <summary>Show raw events ({{ bucket.events.length }})</summary>
                              <div class="raw-event-list">
                                <article v-for="event in bucket.events" :key="event.id" class="raw-event-card">
                                  <div class="event-card-header">
                                    <div class="protocol-bar">
                                      <span :class="protoClass(event.callback_protocol)">{{ protocolLabel(event.callback_protocol) }}</span>
                                      <span :class="sevClass(event.severity)">{{ event.severity }}</span>
                                    </div>
                                    <strong class="mono">{{ formatTime(event.received_at) }}</strong>
                                  </div>

                                  <div class="detail-panel">
                                    <div class="detail-row"><span class="detail-label">Pingback ID</span><span class="detail-value mono">{{ event.id }}</span></div>
                                    <div class="detail-row"><span class="detail-label">Remote address</span><span class="detail-value mono">{{ event.remote_address || '-' }}</span></div>
                                    <div class="detail-row" v-if="event.reverse_dns"><span class="detail-label">Reverse DNS</span><span class="detail-value mono">{{ event.reverse_dns }}</span></div>
                                    <div class="detail-row" v-if="event.asn_info"><span class="detail-label">ASN info</span><span class="detail-value mono">{{ event.asn_info }}</span></div>
                                    <div class="detail-row"><span class="detail-label">Delay</span><span class="detail-value">{{ event.delay_seconds ? event.delay_seconds.toFixed(2) + 's' : '-' }}</span></div>
                                  </div>

                                  <div v-if="event.raw_request" class="detail-row" style="margin-top: 14px">
                                    <span class="detail-label">Raw callback</span>
                                    <pre class="detail-value">{{ event.raw_request }}</pre>
                                  </div>
                                </article>
                              </div>
                            </details>
                          </article>
                        </div>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
            </div>
          </div>
        </article>
      </div>
      <div v-else-if="loading" class="results-empty"><strong>Loading findings.</strong><p class="muted">Fetching the latest callback evidence from the backend.</p></div>
      <div v-else class="results-empty"><strong>No findings match the current filters.</strong><p class="muted">Try widening the scan scope or disabling the DNS-only suppression toggle.</p></div>
    </section>

    <section class="panel" style="padding-top: 0" v-else>
      <div class="table-shell" v-if="filteredEvents.length">
        <table>
          <thead><tr><th class="fit">Open</th><th>Time</th><th>Protocol</th><th>Payload</th><th>Target</th><th>Remote IP</th><th>Severity</th><th>Delay</th></tr></thead>
          <tbody>
            <template v-for="event in filteredEvents" :key="event.id">
              <tr @click="toggleEvent(event.id)">
                <td class="fit">{{ expandedEventId === event.id ? 'Hide' : 'Open' }}</td>
                <td class="mono">{{ formatTime(event.received_at) }}</td>
                <td><span :class="protoClass(event.callback_protocol)">{{ protocolLabel(event.callback_protocol) }}</span></td>
                <td class="mono">{{ event.payload_key }}</td>
                <td class="mono truncate">{{ event.target_url }}</td>
                <td class="mono">{{ event.remote_address || '-' }}</td>
                <td><span :class="sevClass(event.severity)">{{ event.severity }}</span></td>
                <td>{{ event.delay_seconds ? event.delay_seconds.toFixed(2) + 's' : '-' }}</td>
              </tr>
              <tr v-if="expandedEventId === event.id">
                <td colspan="8">
                  <div class="detail-panel">
                    <div class="detail-row"><span class="detail-label">Pingback ID</span><span class="detail-value mono">{{ event.id }}</span></div>
                    <div class="detail-row"><span class="detail-label">Unique ID</span><span class="detail-value mono">{{ event.unique_id }}</span></div>
                    <div class="detail-row"><span class="detail-label">Scan task</span><span class="detail-value mono">{{ event.scan_task_id }}</span></div>
                    <div class="detail-row"><span class="detail-label">Target URL</span><span class="detail-value mono">{{ event.target_url }}</span></div>
                    <div class="detail-row"><span class="detail-label">Payload value</span><span class="detail-value mono">{{ event.payload_value }}</span></div>
                    <div class="detail-row"><span class="detail-label">Remote address</span><span class="detail-value mono">{{ event.remote_address || '-' }}</span></div>
                    <div class="detail-row" v-if="event.reverse_dns"><span class="detail-label">Reverse DNS</span><span class="detail-value mono">{{ event.reverse_dns }}</span></div>
                    <div class="detail-row" v-if="event.asn_info"><span class="detail-label">ASN info</span><span class="detail-value mono">{{ event.asn_info }}</span></div>
                  </div>

                  <div class="bucket-card" style="margin-top: 14px" v-if="event.trigger_raw_request || event.replay_command">
                    <div class="bucket-header">
                      <div>
                        <strong>Trigger request</strong>
                        <div class="tag-row" style="margin-top: 8px">
                          <span class="badge badge-info">{{ event.trigger_method || 'REQUEST' }}</span>
                          <span class="badge badge-info" v-if="event.trigger_response_status">Response {{ event.trigger_response_status }}</span>
                        </div>
                      </div>
                      <div class="action-row">
                        <button class="btn-sm" @click.stop="copyText('event-raw-' + event.id, event.trigger_raw_request)" :disabled="!event.trigger_raw_request">{{ copiedKey === 'event-raw-' + event.id ? 'Copied Raw' : 'Copy Raw HTTP' }}</button>
                        <button class="btn-sm" @click.stop="copyText('event-replay-' + event.id, event.replay_command)" :disabled="!event.replay_command">{{ copiedKey === 'event-replay-' + event.id ? 'Copied Replay' : 'Copy Replay' }}</button>
                      </div>
                    </div>

                    <div class="detail-panel">
                      <div class="detail-row"><span class="detail-label">Request URL</span><span class="detail-value mono">{{ event.trigger_url || event.target_url }}</span></div>
                      <div class="detail-row"><span class="detail-label">Replay mode</span><span class="detail-value">{{ event.replay_command ? 'Ready' : 'Raw only' }}</span></div>
                    </div>

                    <div v-if="event.trigger_raw_request" class="detail-row" style="margin-top: 14px">
                      <span class="detail-label">Raw trigger request</span>
                      <pre class="detail-value">{{ event.trigger_raw_request }}</pre>
                    </div>

                    <div v-if="event.replay_command" class="detail-row" style="margin-top: 14px">
                      <span class="detail-label">Replay command</span>
                      <pre class="detail-value">{{ event.replay_command }}</pre>
                    </div>
                  </div>

                  <div v-if="event.raw_request" class="detail-row" style="margin-top: 14px">
                    <span class="detail-label">Raw callback</span>
                    <pre class="detail-value">{{ event.raw_request }}</pre>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
      <div v-else-if="loading" class="results-empty"><strong>Loading raw events.</strong><p class="muted">Fetching the latest callback log from the backend.</p></div>
      <div v-else class="results-empty"><strong>No raw events match the current filters.</strong><p class="muted">If you expected a hit, confirm the target really issued an outbound request and the polling window is still open.</p></div>
    </section>
  </div>
</template>
