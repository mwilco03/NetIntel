<script lang="ts">
  import { scanData } from '../lib/stores';
</script>

<div>
  <h2 class="section-title">Sources</h2>

  {#if $scanData?.sources?.length > 0}
    <div class="sources-grid">
      {#each $scanData.sources as source}
        <div class="source-card">
          <div class="source-head">
            <span class="source-type badge" class:badge-medium={source.type === 'nmap'} class:badge-high={source.type === 'nessus'}>
              {source.type.toUpperCase()}
            </span>
            <span class="source-name">{source.name}</span>
          </div>
          <div class="source-meta">
            <div>
              <span class="meta-label">Hosts</span>
              <span class="meta-value">{source.hosts}</span>
            </div>
            {#if source.timestamp}
              <div>
                <span class="meta-label">Scanned</span>
                <span class="meta-value">{source.timestamp}</span>
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <p style="color: var(--text-secondary);">No scan sources imported yet.</p>
  {/if}
</div>

<style>
  .sources-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
  }
  .source-card {
    background: var(--bg-primary);
    border: 1px solid var(--bg-tertiary);
    border-radius: 8px;
    padding: 1rem;
  }
  .source-head {
    display: flex;
    align-items: center;
    gap: .75rem;
    margin-bottom: .75rem;
  }
  .source-name {
    font-weight: 600;
    color: var(--text-primary);
    word-break: break-all;
  }
  .source-meta {
    display: flex;
    gap: 2rem;
  }
  .meta-label {
    font-size: .75rem;
    text-transform: uppercase;
    color: var(--text-muted);
    display: block;
  }
  .meta-value {
    font-weight: 600;
    color: var(--text-primary);
  }
</style>
