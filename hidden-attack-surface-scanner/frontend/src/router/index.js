import { createRouter, createWebHistory } from 'vue-router';
import { useAuthStore } from '../stores/auth.js';
import { pinia } from '../stores/pinia.js';

const routes = [
    { path: '/login', name: 'login', component: () => import('../views/Login.vue'), meta: { title: 'Login', public: true, publicOnly: true } },
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

router.beforeEach(async (to) => {
    const auth = useAuthStore(pinia);
    if (!auth.checked) {
        await auth.checkSession();
    }

    if (to.meta?.publicOnly && auth.authenticated) {
        return { name: 'dashboard' };
    }

    if (!to.meta?.public && !auth.authenticated) {
        return { name: 'login', query: { redirect: to.fullPath } };
    }

    return true;
});

export default router;
export { routes };
