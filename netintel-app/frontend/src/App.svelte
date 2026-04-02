<script lang="ts">
  import { onMount } from 'svelte';
  import { currentView, scanData } from './lib/stores';
  import { loadData, importFile } from './lib/api';
  import Sidebar from './components/Sidebar.svelte';
  import Dashboard from './components/dashboard/Dashboard.svelte';
  import EntityGrid from './components/entities/EntityGrid.svelte';
  import Sources from './components/Sources.svelte';

  onMount(async () => {
    await loadData();
  });

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    // Wails handles native file drops differently
  }

  function handleDragOver(e: DragEvent) {
    e.preventDefault();
  }
</script>

<div class="app-layout" on:drop={handleDrop} on:dragover={handleDragOver}>
  <Sidebar />
  <main class="main-content">
    {#if $currentView === 'dashboard'}
      <Dashboard />
    {:else if $currentView === 'entities'}
      <EntityGrid />
    {:else if $currentView === 'sources'}
      <Sources />
    {/if}

    {#if !$scanData || !$scanData.hosts || $scanData.hosts.length === 0}
      <div class="empty-state">
        <div class="empty-icon">&#x1F50D;</div>
        <h2>No Scan Data</h2>
        <p>Import an nmap XML or Nessus file to get started.</p>
        <button class="btn btn-primary" on:click={importFile}>Import File</button>
      </div>
    {/if}
  </main>
</div>

<style>
  .empty-state {
    text-align: center;
    padding: 4rem 2rem;
    color: var(--text-secondary);
  }
  .empty-icon {
    font-size: 3rem;
    margin-bottom: 1rem;
  }
  .empty-state h2 {
    color: var(--text-primary);
    margin-bottom: .5rem;
  }
  .empty-state p {
    margin-bottom: 1.5rem;
  }
</style>
