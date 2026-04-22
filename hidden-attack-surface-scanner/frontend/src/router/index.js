import { createRouter, createWebHistory } from 'vue-router';

const routes = [
    { path: '/', name: 'dashboard', component: () => import('../views/Dashboard.vue'), meta: { title: 'Dashboard', icon: 'DB' } },
    { path: '/scans', name: 'scans', component: () => import('../views/Scans.vue'), meta: { title: 'Scans', icon: 'SC' } },
    { path: '/payloads', name: 'payloads', component: () => import('../views/Payloads.vue'), meta: { title: 'Payloads', icon: 'PL' } },
    { path: '/results', name: 'results', component: () => import('../views/Results.vue'), meta: { title: 'Results', icon: 'RS' } },
    { path: '/settings', name: 'settings', component: () => import('../views/Settings.vue'), meta: { title: 'Settings', icon: 'CF' } },
    { path: '/debug', name: 'debug', component: () => import('../views/Debug.vue'), meta: { title: 'Debug Log', icon: 'LG' } },
];

const router = createRouter({
    history: createWebHistory(),
    routes,
});

export default router;
export { routes };
