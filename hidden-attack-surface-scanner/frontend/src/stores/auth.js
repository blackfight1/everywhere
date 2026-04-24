import { defineStore } from 'pinia';
import { ref } from 'vue';
import { api } from '../api/index.js';

export const useAuthStore = defineStore('auth', () => {
    const authenticated = ref(false);
    const checked = ref(false);
    const username = ref('');

    async function checkSession() {
        try {
            const data = await api.getSession();
            authenticated.value = !!data.authenticated;
            username.value = data.username || '';
        } catch {
            authenticated.value = false;
            username.value = '';
        } finally {
            checked.value = true;
        }
    }

    async function login(usernameInput, passwordInput) {
        const data = await api.login(usernameInput, passwordInput);
        authenticated.value = !!data.authenticated;
        username.value = data.username || '';
        checked.value = true;
        return data;
    }

    async function logout() {
        try {
            await api.logout();
        } finally {
            authenticated.value = false;
            username.value = '';
            checked.value = true;
        }
    }

    return { authenticated, checked, username, checkSession, login, logout };
});
