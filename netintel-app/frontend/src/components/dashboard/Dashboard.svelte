<script lang="ts">
  import { dashboardStats, scanData } from '../../lib/stores';
</script>

{#if $dashboardStats && $scanData?.hosts?.length > 0}
<div>
  <h2 class="section-title">Dashboard</h2>

  <div class="stats-grid">
    <div class="stat-card success">
      <div class="stat-label">Total Hosts</div>
      <div class="stat-value">{$dashboardStats.totalHosts}</div>
    </div>
    <div class="stat-card info">
      <div class="stat-label">Hosts Up</div>
      <div class="stat-value">{$dashboardStats.hostsUp}</div>
    </div>
    <div class="stat-card warning">
      <div class="stat-label">Open Ports</div>
      <div class="stat-value">{$dashboardStats.totalPorts}</div>
    </div>
    <div class="stat-card danger">
      <div class="stat-label">Cleartext</div>
      <div class="stat-value">{$dashboardStats.cleartextCount}</div>
    </div>
    <div class="stat-card info">
      <div class="stat-label">Avg Risk</div>
      <div class="stat-value">{$dashboardStats.avgRisk}</div>
    </div>
  </div>

  {#if $dashboardStats.severityCounts}
    <div class="stats-grid" style="margin-bottom: 1.5rem;">
      <div class="stat-card danger">
        <div class="stat-label">Critical</div>
        <div class="stat-value">{$dashboardStats.severityCounts.Critical || 0}</div>
      </div>
      <div class="stat-card warning">
        <div class="stat-label">High</div>
        <div class="stat-value">{$dashboardStats.severityCounts.High || 0}</div>
      </div>
      <div class="stat-card info">
        <div class="stat-label">Medium</div>
        <div class="stat-value">{$dashboardStats.severityCounts.Medium || 0}</div>
      </div>
      <div class="stat-card success">
        <div class="stat-label">Low</div>
        <div class="stat-value">{$dashboardStats.severityCounts.Low || 0}</div>
      </div>
    </div>
  {/if}

  <div class="dashboard-panels">
    <div class="panel">
      <h3 class="panel-title">Top Risks</h3>
      <table>
        <thead>
          <tr><th>Host</th><th>Risk</th></tr>
        </thead>
        <tbody>
          {#each $dashboardStats.topRisks || [] as entry}
            <tr>
              <td style="font-family: var(--font-mono);">
                {entry.ip}
                {#if entry.hostname}
                  <span style="color: var(--text-secondary); font-family: inherit; margin-left: .5rem;">{entry.hostname}</span>
                {/if}
              </td>
              <td>
                <span class="badge" class:badge-critical={entry.risk >= 70} class:badge-high={entry.risk >= 50 && entry.risk < 70} class:badge-medium={entry.risk >= 25 && entry.risk < 50} class:badge-low={entry.risk < 25}>
                  {entry.risk}
                </span>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="panel">
      <h3 class="panel-title">OS Distribution</h3>
      {#each Object.entries($dashboardStats.osDist || {}) as [os, count]}
        <div class="os-row">
          <span class="os-name">{os}</span>
          <span class="badge badge-medium">{count}</span>
        </div>
      {/each}
    </div>
  </div>
</div>
{/if}

<style>
  .dashboard-panels {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .panel {
    background: var(--bg-primary);
    border: 1px solid var(--bg-tertiary);
    border-radius: 8px;
    padding: 1rem;
  }
  .panel-title {
    font-size: .9rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: .75rem;
    text-transform: uppercase;
    letter-spacing: .05em;
  }
  .os-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: .4rem 0;
  }
  .os-name {
    text-transform: capitalize;
    color: var(--text-secondary);
  }
</style>
