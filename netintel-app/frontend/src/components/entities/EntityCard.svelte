<script lang="ts">
  export let host: any;

  const CLEARTEXT_PORTS = new Set([21, 23, 80, 110, 143, 161, 389, 512, 513, 514, 8080, 8000, 8888]);
  const CLEARTEXT_SVCS = new Set(['ftp', 'telnet', 'http', 'pop3', 'imap', 'snmp', 'ldap', 'rsh', 'rlogin', 'rexec', 'http-proxy']);

  function isCleartext(port: any): boolean {
    return CLEARTEXT_PORTS.has(port.port) || CLEARTEXT_SVCS.has(port.svc?.toLowerCase());
  }

  function osIcon(host: any): { cls: string; label: string } {
    const os = host.os?.[0]?.name || '';
    if (/windows|microsoft/i.test(os)) return { cls: 'win', label: 'W' };
    if (/linux|ubuntu|debian|centos|fedora|redhat/i.test(os)) return { cls: 'lin', label: 'L' };
    if (/cisco|juniper|arista|palo|fortinet|router|switch/i.test(os)) return { cls: 'net', label: 'N' };
    return { cls: '', label: '?' };
  }

  function riskClass(score: number): string {
    if (score >= 70) return 'badge-critical';
    if (score >= 50) return 'badge-high';
    if (score >= 25) return 'badge-medium';
    return 'badge-low';
  }

  $: openPorts = (host.ports || []).filter((p: any) => p.state === 'open');
  $: icon = osIcon(host);
</script>

<div class="entity">
  <div class="entity-head">
    <div class="entity-icon {icon.cls}">[{icon.label}]</div>
    <div class="entity-info">
      <div class="entity-ip">{host.ip}</div>
      {#if host.hostname}
        <div class="entity-host">{host.hostname}</div>
      {/if}
      {#if host.os?.[0]?.name}
        <div class="entity-os">{host.os[0].name}</div>
      {/if}
    </div>
    <span class="badge {riskClass(host.riskScore)}">{host.riskScore}</span>
  </div>

  <div class="entity-body">
    <div class="entity-stats">
      <div class="entity-stat">
        <b>{openPorts.length}</b>
        <span>Ports</span>
      </div>
      <div class="entity-stat">
        <b>{host.cleartextCount || 0}</b>
        <span>Cleartext</span>
      </div>
      <div class="entity-stat">
        <b>{host.nessusFindings?.length || 0}</b>
        <span>Findings</span>
      </div>
    </div>

    <div class="ports">
      {#each openPorts.slice(0, 12) as port}
        <span class="port" class:open={!isCleartext(port)} class:cleartext={isCleartext(port)}>
          {port.port}/{port.proto}
          {#if port.svc}
            <span style="color: var(--text-muted); margin-left: 2px;">{port.svc}</span>
          {/if}
        </span>
      {/each}
      {#if openPorts.length > 12}
        <span class="port">+{openPorts.length - 12} more</span>
      {/if}
    </div>
  </div>

  {#if host.mac}
    <div class="entity-foot">
      <span>{host.mac}</span>
      {#if host.macVendor}
        <span>{host.macVendor}</span>
      {/if}
    </div>
  {/if}
</div>

<style>
  .entity {
    background: var(--bg-primary);
    border: 1px solid var(--bg-tertiary);
    border-radius: 8px;
    overflow: hidden;
    transition: border-color .15s;
  }
  .entity:hover {
    border-color: var(--border);
  }

  .entity-head {
    padding: 1rem;
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    border-bottom: 1px solid var(--bg-tertiary);
  }

  .entity-icon {
    width: 44px;
    height: 44px;
    border-radius: 8px;
    background: var(--bg-tertiary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-size: 1.1rem;
    font-family: var(--font-mono);
    font-weight: 700;
  }
  .entity-icon.win { background: rgba(0,120,212,.2); color: #0078d4; }
  .entity-icon.lin { background: rgba(255,165,0,.2); color: #ffa500; }
  .entity-icon.net { background: rgba(88,166,255,.2); color: var(--accent); }

  .entity-info { flex: 1; min-width: 0; }
  .entity-ip {
    font-family: var(--font-mono);
    font-weight: 600;
    color: var(--text-primary);
  }
  .entity-host {
    font-size: .8rem;
    color: var(--text-secondary);
  }
  .entity-os {
    font-size: .75rem;
    color: var(--text-muted);
    margin-top: .25rem;
  }

  .entity-body { padding: 1rem; }

  .entity-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: .5rem;
    margin-bottom: .75rem;
    text-align: center;
  }
  .entity-stat {
    background: var(--bg-secondary);
    padding: .5rem;
    border-radius: 4px;
  }
  .entity-stat b {
    display: block;
    font-size: 1.1rem;
    color: var(--text-primary);
  }
  .entity-stat span {
    font-size: .7rem;
    color: var(--text-secondary);
    text-transform: uppercase;
  }

  .ports {
    display: flex;
    flex-wrap: wrap;
    gap: .3rem;
  }

  .entity-foot {
    padding: .75rem 1rem;
    border-top: 1px solid var(--bg-tertiary);
    background: var(--bg-secondary);
    display: flex;
    justify-content: space-between;
    font-size: .75rem;
    font-family: var(--font-mono);
    color: var(--text-muted);
  }
</style>
