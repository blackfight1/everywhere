import { createRouter, createWebHistory } from 'vue-router';

const routes = [
    { path: '/', name: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: 'Dashboard', icon: '📊' } },
    { path: '/scans', name: 'scans', component: () => import('../views/Scans.vue'), meta: { title: 'Scans', icon: '🔍' } },
    { path: '/payloads', name: 'payloads', component: () => import('../views/Payloads.vue'), meta: { title: 'Payloads', icon: '💉' } },
    { path: '/results', name: 'results', component: () => import('../views/Results.vue'), meta: { title: 'Results', icon: '🎯' } },
    { path: '/settings', name: 'settings', component: () => import('../views/Settings.vue'), meta: { title: 'Settings', icon: '⚙️' } },
    { path: '/debug', name: 'debug', component: () => import('../views/Debug.vue'), meta: { title: 'Debug Log', icon: '🐛' } },
];

const router = createRouter({
    history: createWebHistory(),
    routes,
});

export default router;
export { routes };
