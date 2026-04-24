<script setup>
import { reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useAuthStore } from '../stores/auth.js';
import { useToastStore } from '../stores/toast.js';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const toast = useToastStore();

const submitting = ref(false);
const form = reactive({
  username: 'leftshoulder',
  password: '',
});

async function submit() {
  submitting.value = true;
  try {
    await auth.login(form.username, form.password);
    const redirect = typeof route.query.redirect === 'string' && route.query.redirect ? route.query.redirect : '/';
    router.push(redirect);
  } catch (e) {
    toast.error(e.message || 'Login failed');
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="login-shell">
    <section class="login-panel">
      <div class="login-copy">
        <span class="page-kicker">Restricted Access</span>
        <h1 class="login-title">Hidden Surface Scanner</h1>
        <p class="page-copy">Public exposure is now gated behind a session. Sign in before opening dashboards, results, payload controls, or live scan activity.</p>
      </div>

      <div class="form-grid">
        <div class="form-group form-span-12">
          <label>Username</label>
          <input v-model="form.username" autocomplete="username" @keyup.enter="submit" />
        </div>
        <div class="form-group form-span-12">
          <label>Password</label>
          <input v-model="form.password" type="password" autocomplete="current-password" @keyup.enter="submit" />
        </div>
      </div>

      <div class="form-actions" style="margin-top: 10px">
        <button class="primary login-button" :disabled="submitting" @click="submit">
          {{ submitting ? 'Signing in...' : 'Sign in' }}
        </button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.login-shell { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
.login-panel { width: min(460px, 100%); padding: 34px; border-radius: 28px; border: 1px solid rgba(49,80,109,.42); background: linear-gradient(180deg, rgba(17,25,34,.96), rgba(10,15,21,.96)); box-shadow: 0 22px 70px rgba(0,0,0,.35); }
.login-copy { display: grid; gap: 10px; margin-bottom: 24px; }
.login-title { margin: 0; font-size: clamp(2rem, 5vw, 2.8rem); letter-spacing: -.05em; }
.login-button { width: 100%; justify-content: center; }
</style>
