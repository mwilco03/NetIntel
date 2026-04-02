<script lang="ts">
  import { currentView } from '../lib/stores';
  import type { View } from '../lib/stores';
  import { importFile, clearData, ExportJSON, ExportCSV } from '../lib/api';

  const navItems: { id: View; label: string; icon: string }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: '#' },
    { id: 'entities', label: 'Entities', icon: '=' },
    { id: 'sources', label: 'Sources', icon: '^' },
  ];

  function navigate(view: View) {
    currentView.set(view);
  }
</script>

<aside class="sidebar">
  <div class="sidebar-brand">
    <span class="brand-text">NetIntel</span>
  </div>

  <nav class="sidebar-nav">
    {#each navItems as item}
      <button
        class="nav-item"
        class:active={$currentView === item.id}
        on:click={() => navigate(item.id)}
      >
        <span class="nav-icon">{item.icon}</span>
        <span>{item.label}</span>
      </button>
    {/each}
  </nav>

  <div class="sidebar-actions">
    <button class="btn" on:click={importFile} style="width:100%">+ Import</button>
    <button class="btn" on:click={ExportJSON} style="width:100%">Export JSON</button>
    <button class="btn" on:click={ExportCSV} style="width:100%">Export CSV</button>
    <button class="btn" on:click={clearData} style="width:100%; color: var(--danger);">Clear Data</button>
  </div>
</aside>

<style>
  .sidebar {
    width: 200px;
    background: var(--bg-secondary);
    border-right: 1px solid var(--bg-tertiary);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .sidebar-brand {
    padding: 1rem;
    border-bottom: 1px solid var(--bg-tertiary);
  }
  .brand-text {
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--accent);
  }

  .sidebar-nav {
    flex: 1;
    padding: .5rem;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: .5rem;
    width: 100%;
    padding: .5rem .75rem;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text-secondary);
    font-size: .85rem;
    cursor: pointer;
    text-align: left;
    transition: background .1s, color .1s;
  }
  .nav-item:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }
  .nav-item.active {
    background: rgba(88, 166, 255, .1);
    color: var(--accent);
  }
  .nav-icon {
    font-family: var(--font-mono);
    font-weight: 700;
    width: 1.5rem;
    text-align: center;
  }

  .sidebar-actions {
    padding: .75rem;
    border-top: 1px solid var(--bg-tertiary);
    display: flex;
    flex-direction: column;
    gap: .5rem;
  }
</style>
