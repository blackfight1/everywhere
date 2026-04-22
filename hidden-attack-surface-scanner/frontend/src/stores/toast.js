import { defineStore } from 'pinia';
import { ref, reactive } from 'vue';

export const useToastStore = defineStore('toast', () => {
    const items = ref([]);
    let _id = 0;

    function add(message, type = 'info', duration = 4000) {
        const id = ++_id;
        items.value.push({ id, message, type });
        if (duration > 0) {
            setTimeout(() => remove(id), duration);
        }
    }

    function remove(id) {
        items.value = items.value.filter(t => t.id !== id);
    }

    function success(msg) { add(msg, 'success'); }
    function error(msg) { add(msg, 'error', 6000); }
    function info(msg) { add(msg, 'info'); }

    return { items, add, remove, success, error, info };
});
