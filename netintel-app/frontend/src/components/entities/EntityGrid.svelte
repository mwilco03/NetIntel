<script lang="ts">
  import { scanData } from '../../lib/stores';
  import EntityCard from './EntityCard.svelte';

  let searchQuery = '';
  let groupBy = 'none';
  let sortBy = 'risk';

  $: hosts = ($scanData?.hosts || []);

  $: filtered = hosts.filter(h => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      h.ip?.toLowerCase().includes(q) ||
      h.hostname?.toLowerCase().includes(q) ||
      h.ports?.some(p => String(p.port).includes(q) || p.svc?.toLowerCase().includes(q)) ||
      h.os?.[0]?.name?.toLowerCase().includes(q)
    );
  });

  $: sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'risk') return (b.riskScore || 0) - (a.riskScore || 0);
    if (sortBy === 'ip') return a.ip.localeCompare(b.ip);
    if (sortBy === 'ports') return (b.ports?.length || 0) - (a.ports?.length || 0);
    return 0;
  });
</script>

{#if hosts.length > 0}
<div>
  <div class="toolbar">
    <h2 class="section-title" style="margin:0">Entities ({filtered.length})</h2>
    <div class="toolbar-controls">
      <input
        type="text"
        class="search-input"
        placeholder="Search IP, hostname, port, service..."
        bind:value={searchQuery}
      />
      <select class="select" bind:value={sortBy}>
        <option value="risk">Sort: Risk</option>
        <option value="ip">Sort: IP</option>
        <option value="ports">Sort: Ports</option>
      </select>
    </div>
  </div>

  <div class="entity-grid">
    {#each sorted as host (host.ip)}
      <EntityCard {host} />
    {/each}
  </div>
</div>
{/if}

<style>
  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
    gap: 1rem;
    flex-wrap: wrap;
  }
  .toolbar-controls {
    display: flex;
    gap: .5rem;
    align-items: center;
  }
  .search-input {
    padding: .4rem .75rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-size: .85rem;
    width: 300px;
    outline: none;
  }
  .search-input:focus {
    border-color: var(--accent);
  }
  .select {
    padding: .4rem .75rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-size: .85rem;
    outline: none;
  }
</style>
