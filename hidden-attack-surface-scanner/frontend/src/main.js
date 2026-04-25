import { createApp } from 'vue';
import router from './router/index.js';
import App from './App.vue';
import './style.css';
import { pinia } from './stores/pinia.js';
import { useAuthStore } from './stores/auth.js';

const auth = useAuthStore(pinia);

async function bootstrap() {
    await auth.checkSession();

    const app = createApp(App);
    app.use(pinia);
    app.use(router);
    await router.isReady();
    app.mount('#app');
}

bootstrap();
