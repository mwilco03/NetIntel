import { writable } from 'svelte/store';

export type View = 'dashboard' | 'entities' | 'sources';

export const currentView = writable<View>('dashboard');
export const scanData = writable<any>(null);
export const dashboardStats = writable<any>(null);
export const loading = writable<boolean>(false);
