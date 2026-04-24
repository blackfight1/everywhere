import { createApp } from 'vue';
import router from './router/index.js';
import App from './App.vue';
import './style.css';
import { pinia } from './stores/pinia.js';

const app = createApp(App);
app.use(pinia);
app.use(router);
app.mount('#app');
