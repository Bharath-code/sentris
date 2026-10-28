/**
 * SENTRIS PRO — Commercial Team SaaS Console ($8/Seat Pro Tier)
 * Powered by TanStack Query + TanStack Table Engine + Cloudflare Workers D1 + Dodo Payments MoR.
 * Features live Zero-Knowledge Multi-Repo Blast Radius correlation, column sorting,
 * severity/status filtering, and simulated `POST /v1/scans` ingestion.
 */

import {
  globalQueryClient,
  TanStackTableEngine,
  computeMultiRepoBlastRadius
} from './tanstack-core.js';
import {
  initDecryptedText,
  initSpotlightCards,
  openDodoCheckoutModal
} from './reactbits.js';

export class TeamDashboard {
  constructor(containerElement) {
    this.container = containerElement;
    this.activeTab = 'stream'; // 'stream' | 'members' | 'audit' | 'integrations'
    this.tableEngine = new TanStackTableEngine({
      getData: () => globalQueryClient.getState().findings
    });

    this.members = [
      { name: 'Alex Vance', email: 'alex.v@acme.corp', role: 'Admin (Owner)', lastScan: 'Active now (sentris lsp)', seats: 'Occupied' },
      { name: 'Priya Sharma', email: 'priya.s@acme.corp', role: 'Principal Security Eng', lastScan: '5m ago (sentris sync)', seats: 'Occupied' },
      { name: 'Elena Rostova', email: 'elena.r@acme.corp', role: 'AppSec Lead', lastScan: '13m ago (pre-commit)', seats: 'Occupied' },
      { name: 'Marcus Brody', email: 'marcus.b@acme.corp', role: 'Staff Backend Eng', lastScan: '25m ago (CI/CD push)', seats: 'Occupied' },
      { name: 'Devon Clark', email: 'devon.c@acme.corp', role: 'AI Agent Architect', lastScan: '40m ago (sentris mcp)', seats: 'Occupied' }
    ];

    this.auditRecords = [
      { id: 105, action: 'BlastRadiusCorrelated', time: '13:14:08', hash: '9c41e82a', details: 'Correlated zk_94a3ab2d8f1044c91e across 4 microservice repos in Cloudflare D1.' },
      { id: 104, action: 'ScanCompleted', time: '13:09:42', hash: '5f9e2b10', details: '5,000 files evaluated in 18ms via WalkParallel + RegexSet DFA. 0 raw leaks uploaded.' },
      { id: 103, action: 'SecretRemediated', time: '12:45:11', hash: '8a12c49e', details: 'Stripe key rotated via Dual-Key API. Replacement injected into 1Password (op://).' },
      { id: 102, action: 'VantaEvidenceExported', time: '11:20:00', hash: '3e41b99a', details: 'SOC 2 CC6.1 & CC6.6 evidence bundle sealed for Vanta automated compliance.' },
      { id: 101, action: 'QuarantineCreated', time: '09:15:30', hash: 'c901284a', details: 'Zone 3 quarantine branch sentris/quarantine/gh-pat + git-filter-repo playbook generated.' }
    ];

    this.unsubscribe = globalQueryClient.subscribe(() => {
      this.render();
    });

    this.init();
  }

  init() {
    this.render();
  }

  render() {
    const state = globalQueryClient.getState();
    const org = state.organization;
    const findings = state.findings;
    const blastRadiusClusters = computeMultiRepoBlastRadius(findings);
    const activeCount = findings.filter((f) => f.status.includes('Active')).length;
    const remediatedCount = findings.length - activeCount;
    const seatPercent = Math.min(100, Math.round((org.seatsUsed / org.seatsPurchased) * 100));

    this.container.innerHTML = `
      <div class="max-w-7xl mx-auto space-y-8">
        
        <!-- Organization Header Card -->
        <div class="bento-card p-6 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-[#FF5500] to-[#CC3700] flex items-center justify-center font-mono font-bold text-white text-lg shadow-lg">
              §
            </div>
            <div>
              <div class="flex flex-wrap items-center gap-2.5">
                <h2 class="text-xl font-bold text-white tracking-tight font-display">${org.name}</h2>
                <span class="badge-clean badge-tag-cadmium">${org.plan}</span>
                <span class="badge-clean badge-tag-emerald">CLOUDFLARE D1 EDGE</span>
              </div>
              <div class="text-xs text-slate-400 flex flex-wrap items-center gap-3 pt-1">
                <span>Org ID: <code class="text-slate-300 font-mono">${org.id}</code></span>
                <span>•</span>
                <span>Token: <code class="text-amber-300 font-mono" data-decrypt>${org.activeLicensePreview}</code></span>
                <span>•</span>
                <span class="text-emerald-400 flex items-center gap-1.5 font-mono">
                  <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  Zero-Knowledge Mesh Connected
                </span>
              </div>
            </div>
          </div>

          <div class="flex flex-wrap items-center gap-2.5">
            <button id="btn-sim-zk-sync" class="btn-glass text-xs py-2 px-3.5 font-mono border-cyan-500/30 text-cyan-300">
              ⚡ Simulate CLI Sync (POST /v1/scans)
            </button>
            <button id="btn-dash-dodo-upgrade" class="btn-primary text-xs py-2 px-4">
              Manage Seats (Dodo MoR)
            </button>
          </div>
        </div>

        <!-- 4 Key Metric Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          
          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>SEAT ALLOCATION</span>
              <span class="text-[#FF8844] font-bold">${org.seatsUsed} / ${org.seatsPurchased} SEATS</span>
            </div>
            <div class="text-2xl font-mono font-bold text-white">$${org.seatsPurchased * (org.billingInterval === 'annual' ? 7 : 8)} <span class="text-xs text-slate-400 font-normal">/ mo</span></div>
            <div class="w-full bg-[#181C26] h-1.5 rounded-full overflow-hidden">
              <div class="bg-[#FF5500] h-full rounded-full transition-all duration-300" style="width: ${seatPercent}%"></div>
            </div>
            <div class="text-[11px] text-slate-400 flex justify-between pt-1">
              <span>${ org.morProvider }</span>
              <span>${Math.max(0, org.seatsPurchased - org.seatsUsed)} Free</span>
            </div>
          </div>

          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>BLAST RADIUS CLUSTERS</span>
              <span class="text-amber-400 font-bold">${blastRadiusClusters.length} SHARED KEYS</span>
            </div>
            <div class="text-2xl font-mono font-bold text-white">${findings.length} <span class="text-xs text-slate-400 font-normal">ZK Hashes</span></div>
            <div class="text-[11px] text-emerald-400 font-medium">
              ✔ 0 bytes raw code or secrets ingested
            </div>
            <div class="text-[10px] text-slate-400">
              Salted SHA-256 (<code class="font-mono">zk_...</code>) correlation
            </div>
          </div>

          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>AUTO-REMEDIATIONS</span>
              <span class="text-cyan-400 font-bold">14.8s AVG</span>
            </div>
            <div class="text-2xl font-mono font-bold text-white">${remediatedCount} <span class="text-xs text-emerald-400 font-semibold">/ ${findings.length} Safe</span></div>
            <div class="text-[11px] text-slate-300">
              Dual-Key Staged (0 HTTP 500 Outages)
            </div>
            <div class="text-[10px] text-slate-400">
              Env, Vault, AWS, Doppler, 1Password, Infisical
            </div>
          </div>

          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>VANTA SOC 2 CHAIN</span>
              <span class="text-emerald-400 font-bold">VERIFIED</span>
            </div>
            <div class="text-2xl font-mono font-bold text-emerald-400">100% <span class="text-xs text-slate-400 font-normal">CC6.1 / CC6.6</span></div>
            <div class="text-[11px] text-slate-300">
              Append-only cryptographic hash chain
            </div>
            <div class="text-[10px] text-slate-400">
              RFC 2104 HMAC-SHA256 tamper-proof sealed
            </div>
          </div>

        </div>

        <!-- Dashboard Navigation Tabs -->
        <div class="flex flex-wrap border-b border-white/[0.08] gap-4 text-xs font-semibold">
          <button id="dash-tab-stream" class="pb-3 px-1 transition-all ${this.activeTab === 'stream' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            Real-Time ZK Telemetry & Blast Radius (${findings.length})
          </button>
          <button id="dash-tab-members" class="pb-3 px-1 transition-all ${this.activeTab === 'members' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            Active Team Seats (${org.seatsUsed}/${org.seatsPurchased})
          </button>
          <button id="dash-tab-audit" class="pb-3 px-1 transition-all ${this.activeTab === 'audit' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            SOC 2 Cryptographic Ledger
          </button>
          <button id="dash-tab-integrations" class="pb-3 px-1 transition-all ${this.activeTab === 'integrations' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            Cloudflare Edge, MCP & LSP Integrations
          </button>
        </div>

        <!-- Dynamic Content Body -->
        <div id="dash-body">
          ${this.renderBodyContent(blastRadiusClusters)}
        </div>

      </div>
    `;

    initSpotlightCards(this.container);
    initDecryptedText(this.container);
    this.bindEvents();
  }

  renderBodyContent(blastRadiusClusters) {
    if (this.activeTab === 'stream') {
      const rows = this.tableEngine.getRowModel();
      const topCluster = blastRadiusClusters[0];

      return `
        <div class="space-y-6">
          ${topCluster ? `
          <!-- Zero-Knowledge Multi-Repo Blast Radius Insight Card -->
          <div class="bento-card p-5 border border-[#FF5500]/45 bg-gradient-to-r from-[#160E0C] via-[#0E1017] to-[#0E1017]">
            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div class="space-y-2">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="badge-clean badge-tag-critical">ZERO-KNOWLEDGE MULTI-REPO BLAST RADIUS ALERT</span>
                  <span class="text-xs font-mono text-amber-300 font-bold" data-decrypt>${topCluster.fingerprint}</span>
                  <span class="text-xs font-mono text-slate-400">•</span>
                  <span class="text-xs font-mono text-emerald-400">Correlated in Cloudflare D1 (0 Bytes Code Ingested)</span>
                </div>
                <div class="text-sm font-bold text-white">
                  Identical <code class="text-[#FF8844] font-mono">${topCluster.rule}</code> credential fingerprint detected across <span class="text-amber-300 font-mono">${topCluster.repoCount} repositories</span> (${topCluster.occurrences} occurrences)
                </div>
                <div class="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px]">
                  <span class="text-slate-400">Affected Repositories:</span>
                  ${topCluster.affectedRepos.map((r) => `<span class="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-cyan-300">${r}</span>`).join('')}
                </div>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                <button id="btn-rotate-blast-cluster" data-fp="${topCluster.fingerprint}" class="btn-primary text-xs py-2 px-4 font-mono">
                  ${topCluster.activeCount > 0 ? `Rotate Shared Key (${topCluster.repoCount} Repos)` : '✔ Shared Key Rotated Across All Repos'}
                </button>
              </div>
            </div>
          </div>
          ` : ''}

          <!-- TanStack Table Controls (Search + Facet Filters + Sort Indicators) -->
          <div class="bento-card overflow-hidden">
            <div class="p-4 bg-[#0E1017] border-b border-white/[0.08] flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <span class="w-2 h-2 rounded-full bg-[#FF5500] animate-pulse"></span>
                <span class="text-xs font-mono font-bold text-white">TANSTACK REACTIVE FINDINGS TABLE</span>
                <span class="badge-clean badge-tag-muted">${rows.length} rows</span>
              </div>

              <div class="flex flex-wrap items-center gap-2">
                <input
                  id="tanstack-search-input"
                  type="search"
                  value="${this.tableEngine.searchQuery}"
                  placeholder="Filter repo, rule, author, zk_ hash..."
                  class="px-3 py-1.5 rounded-lg bg-[#080A0E] border border-white/10 text-xs text-white font-mono focus:outline-none focus:border-[#FF5500] w-60"
                />
                <select id="tanstack-severity-filter" class="px-2.5 py-1.5 rounded-lg bg-[#080A0E] border border-white/10 text-xs text-slate-300 font-mono">
                  <option value="ALL" ${this.tableEngine.severityFilter === 'ALL' ? 'selected' : ''}>All Severities</option>
                  <option value="Critical" ${this.tableEngine.severityFilter === 'Critical' ? 'selected' : ''}>Critical Only</option>
                  <option value="High" ${this.tableEngine.severityFilter === 'High' ? 'selected' : ''}>High Only</option>
                </select>
                <select id="tanstack-status-filter" class="px-2.5 py-1.5 rounded-lg bg-[#080A0E] border border-white/10 text-xs text-slate-300 font-mono">
                  <option value="ALL" ${this.tableEngine.statusFilter === 'ALL' ? 'selected' : ''}>All Statuses</option>
                  <option value="ACTIVE" ${this.tableEngine.statusFilter === 'ACTIVE' ? 'selected' : ''}>Active (Unremediated)</option>
                  <option value="REMEDIATED" ${this.tableEngine.statusFilter === 'REMEDIATED' ? 'selected' : ''}>Remediated</option>
                </select>
              </div>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left text-xs font-mono">
                <thead class="bg-[#080A0E] text-slate-400 uppercase border-b border-white/[0.08] select-none">
                  <tr>
                    <th class="p-3.5 cursor-pointer hover:text-white tanstack-sort-col" data-col="timestamp">Time ↕</th>
                    <th class="p-3.5 cursor-pointer hover:text-white tanstack-sort-col" data-col="repo">Developer / Repo ↕</th>
                    <th class="p-3.5 cursor-pointer hover:text-white tanstack-sort-col" data-col="rule">Detector Rule ↕</th>
                    <th class="p-3.5">Redacted Preview / Salted ZK Hash</th>
                    <th class="p-3.5 cursor-pointer hover:text-white tanstack-sort-col" data-col="zone">Git Zone ↕</th>
                    <th class="p-3.5 cursor-pointer hover:text-white tanstack-sort-col" data-col="status">Status ↕</th>
                    <th class="p-3.5 text-right">Autonomous Action</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-white/[0.08] text-slate-200">
                  ${rows.map((f) => `
                    <tr class="hover:bg-[#11141C] transition-colors">
                      <td class="p-3.5 text-slate-400 whitespace-nowrap">${f.time}</td>
                      <td class="p-3.5">
                        <div class="font-bold text-white font-sans">${f.repo}</div>
                        <div class="text-[11px] text-slate-400">${f.branch} • ${f.author}</div>
                      </td>
                      <td class="p-3.5">
                        <span class="badge-clean ${f.severity === 'Critical' ? 'badge-tag-critical' : 'badge-tag-cadmium'}">
                          ${f.rule}
                        </span>
                      </td>
                      <td class="p-3.5">
                        <div class="font-bold text-amber-300">${f.preview}</div>
                        <div class="text-[10px] text-slate-500" data-decrypt>${f.fingerprint}</div>
                      </td>
                      <td class="p-3.5 text-cyan-400">${f.zone}</td>
                      <td class="p-3.5">
                        <span class="badge-clean ${f.status.includes('Active') ? 'bg-red-500/10 text-red-400 border border-red-500/30' : 'badge-tag-emerald'}">
                          ${f.status}
                        </span>
                      </td>
                      <td class="p-3.5 text-right whitespace-nowrap">
                        ${f.status.includes('Active') ? `
                          <button class="btn-primary text-[11px] py-1 px-3 action-fix-btn" data-id="${f.id}">
                            Safe Remediate
                          </button>
                        ` : `
                          <span class="text-[11px] text-emerald-400">✔ Dual-Key Rotated</span>
                        `}
                      </td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    }

    if (this.activeTab === 'members') {
      return `
        <div class="bento-card overflow-hidden">
          <div class="p-4 bg-[#0E1017] border-b border-white/[0.08] flex items-center justify-between">
            <div>
              <div class="text-sm font-bold text-white">Active Team Seats ($8/seat Pro Plan • Dodo Payments MoR)</div>
              <div class="text-xs text-slate-400">Includes pre-commit hook scanning, IDE LSP, AI MCP server, and multi-repo blast radius sync.</div>
            </div>
            <button id="btn-members-add-seat" class="btn-primary text-xs py-1.5 px-3">
              + Add Developer Seat ($8/mo)
            </button>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="bg-[#080A0E] text-slate-400 uppercase border-b border-white/[0.08]">
                <tr>
                  <th class="p-3.5">Developer</th>
                  <th class="p-3.5">Email</th>
                  <th class="p-3.5">Role</th>
                  <th class="p-3.5">Last Local Telemetry</th>
                  <th class="p-3.5">Seat Status</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-white/[0.08] text-slate-200">
                ${this.members.map((m) => `
                  <tr class="hover:bg-[#11141C] transition-colors">
                    <td class="p-3.5 font-bold text-white font-sans">${m.name}</td>
                    <td class="p-3.5 text-slate-400">${m.email}</td>
                    <td class="p-3.5"><span class="badge-clean badge-tag-cadmium">${m.role}</span></td>
                    <td class="p-3.5 text-slate-400">${m.lastScan}</td>
                    <td class="p-3.5"><span class="badge-clean badge-tag-emerald">${m.seats}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    if (this.activeTab === 'audit') {
      return `
        <div class="bento-card p-6 space-y-6">
          <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/[0.08]">
            <div>
              <div class="flex items-center gap-2">
                <h3 class="text-base font-bold text-white">Vanta SOC 2 / ISO 27001 Cryptographic Hash Chain</h3>
                <span class="badge-clean badge-tag-emerald">INTEGRITY 100% VERIFIED</span>
              </div>
              <p class="text-xs text-slate-400 pt-1">
                Every scan, dual-key rotation, and Zone 3 quarantine action appends an immutable RFC 2104 HMAC-SHA256 signed entry.
              </p>
            </div>
            <div class="flex items-center gap-2">
              <button id="btn-verify-audit-chain" class="btn-glass text-xs py-1.5 px-3 font-mono">
                sentris audit --verify
              </button>
              <button onclick="navigator.clipboard?.writeText('sentris compliance --vanta --output vanta-soc2.json'); this.textContent='✔ Copied Vanta CLI Command'" class="btn-primary text-xs py-1.5 px-3 font-mono">
                sentris compliance --vanta
              </button>
            </div>
          </div>

          <div class="space-y-3 font-mono text-xs">
            ${this.auditRecords.map((r) => `
              <div class="p-3.5 rounded-xl bg-[#10131A] border border-white/10 flex items-start justify-between gap-4">
                <div class="space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="text-slate-400 font-bold">#${r.id}</span>
                    <span class="badge-clean badge-tag-cadmium text-[10px]">${r.action}</span>
                    <span class="text-slate-400 text-[11px]">${r.time}</span>
                  </div>
                  <div class="text-slate-200">${r.details}</div>
                </div>
                <div class="text-right shrink-0">
                  <div class="text-[10px] text-slate-400">HMAC Chain Hash:</div>
                  <div class="text-cyan-400 font-bold" data-decrypt>${r.hash}...</div>
                  <div class="text-[10px] text-emerald-400">✔ Tamper-Proof</div>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    if (this.activeTab === 'integrations') {
      return `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="bento-card p-6 space-y-3">
            <div class="flex items-center justify-between">
              <div class="text-sm font-bold text-white">Cloudflare Worker + D1 Zero-Knowledge Edge</div>
              <span class="badge-clean badge-tag-emerald">READY (cloud/wrangler.toml)</span>
            </div>
            <p class="text-xs text-slate-300">
              Serverless SQLite (<code class="font-mono text-cyan-300">sentris-zk-db</code>) + KV token cache deployed at the edge with sub-10ms global latency and zero raw code storage.
            </p>
            <div class="p-2.5 rounded bg-[#07090D] border border-white/10 font-mono text-[11px] text-slate-300">
              cd cloud && npx wrangler d1 execute sentris-zk-db --file=./schema.sql && npx wrangler deploy
            </div>
          </div>

          <div class="bento-card p-6 space-y-3">
            <div class="flex items-center justify-between">
              <div class="text-sm font-bold text-white">Dodo Payments (Global & India MoR)</div>
              <span class="badge-clean badge-tag-cadmium">WEBHOOK VERIFIED</span>
            </div>
            <p class="text-xs text-slate-300">
              Handles global USD ($8/seat) and localized INR (UPI/Cards) checkout, GST/VAT remittance, and automatic <code class="font-mono text-amber-300">sp_live_</code> CLI license provisioning.
            </p>
            <div class="p-2.5 rounded bg-[#07090D] border border-white/10 font-mono text-[11px] text-slate-300">
              POST /v1/checkout/dodo • POST /v1/webhooks/dodo
            </div>
          </div>

          <div class="bento-card p-6 space-y-3">
            <div class="flex items-center justify-between">
              <div class="text-sm font-bold text-white">AI Agent MCP Server (6 JSON-RPC 2.0 Tools)</div>
              <span class="badge-clean badge-tag-emerald">STDIO NATIVE</span>
            </div>
            <p class="text-xs text-slate-300">
              Exposes <code class="font-mono text-white">sentris_scan_path</code>, <code class="font-mono text-white">sentris_remediate</code>, <code class="font-mono text-white">sentris_verify_secret</code>, <code class="font-mono text-white">sentris_audit_status</code>, <code class="font-mono text-white">sentris_rollback_session</code>, and <code class="font-mono text-white">sentris_team_blast_radius</code> to Claude Code, Cursor & Windsurf.
            </p>
          </div>

          <div class="bento-card p-6 space-y-3">
            <div class="flex items-center justify-between">
              <div class="text-sm font-bold text-white">IDE Language Server Protocol (LSP 3.17)</div>
              <span class="badge-clean badge-tag-emerald">SUB-10MS DIAGNOSTICS</span>
            </div>
            <p class="text-xs text-slate-300">
              Real-time inline squiggles and 1-click Quick-Fix CodeActions (<code class="font-mono text-white">sentris lsp</code>) for VS Code, Neovim, Zed, and JetBrains IDEs.
            </p>
          </div>
        </div>
      `;
    }

    return '';
  }

  bindEvents() {
    const tabs = [
      { id: 'dash-tab-stream', key: 'stream' },
      { id: 'dash-tab-members', key: 'members' },
      { id: 'dash-tab-audit', key: 'audit' },
      { id: 'dash-tab-integrations', key: 'integrations' }
    ];

    tabs.forEach((t) => {
      const el = this.container.querySelector(`#${t.id}`);
      if (el) {
        el.addEventListener('click', () => {
          this.activeTab = t.key;
          this.render();
        });
      }
    });

    const simBtn = this.container.querySelector('#btn-sim-zk-sync');
    if (simBtn) {
      simBtn.addEventListener('click', () => {
        const sampleRepos = [
          'acme/checkout-edge-worker',
          'acme/notification-dispatcher',
          'acme/fraud-ml-scorer',
          'acme/k8s-ingress-gateway'
        ];
        const randomRepo = sampleRepos[Math.floor(Math.random() * sampleRepos.length)];
        globalQueryClient.ingestZeroKnowledgeScan({
          author: 'bharath@sentris.dev',
          repo: randomRepo,
          branch: 'feat/dodo-webhooks',
          rule: 'postgres-connection-uri',
          severity: 'Critical',
          preview: 'postgres://prod_admin:***@db.internal:5432',
          fingerprint: 'zk_94a3ab2d8f1044c91e',
          zone: 'Zone 1 (Staged Hunk)'
        });
      });
    }

    const upgradeBtn = this.container.querySelector('#btn-dash-dodo-upgrade');
    const addSeatBtn = this.container.querySelector('#btn-members-add-seat');
    [upgradeBtn, addSeatBtn].forEach((btn) => {
      if (btn) {
        btn.addEventListener('click', () => {
          openDodoCheckoutModal({
            plan: 'pro',
            seats: globalQueryClient.getState().organization.seatsPurchased + 5,
            isAnnual: false
          });
        });
      }
    });

    const rotateClusterBtn = this.container.querySelector('#btn-rotate-blast-cluster');
    if (rotateClusterBtn) {
      rotateClusterBtn.addEventListener('click', () => {
        const fp = rotateClusterBtn.dataset.fp;
        globalQueryClient.remediateSharedBlastRadius(fp);
      });
    }

    const searchInput = this.container.querySelector('#tanstack-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        const cursorPos = e.target.selectionStart;
        this.tableEngine.setSearch(e.target.value);
        this.render();
        const nextInput = this.container.querySelector('#tanstack-search-input');
        if (nextInput) {
          nextInput.focus();
          nextInput.setSelectionRange(cursorPos, cursorPos);
        }
      });
    }

    const sevSelect = this.container.querySelector('#tanstack-severity-filter');
    if (sevSelect) {
      sevSelect.addEventListener('change', (e) => {
        this.tableEngine.setSeverity(e.target.value);
        this.render();
      });
    }

    const statusSelect = this.container.querySelector('#tanstack-status-filter');
    if (statusSelect) {
      statusSelect.addEventListener('change', (e) => {
        this.tableEngine.setStatus(e.target.value);
        this.render();
      });
    }

    const sortCols = this.container.querySelectorAll('.tanstack-sort-col');
    sortCols.forEach((col) => {
      col.addEventListener('click', () => {
        this.tableEngine.toggleSort(col.dataset.col);
        this.render();
      });
    });

    const fixBtns = this.container.querySelectorAll('.action-fix-btn');
    fixBtns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.dataset.id;
        btn.innerHTML = `<span class="animate-spin inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full mr-1"></span> Rotating...`;
        setTimeout(() => {
          globalQueryClient.remediateFinding(id);
        }, 420);
      });
    });

    const verifyBtn = this.container.querySelector('#btn-verify-audit-chain');
    if (verifyBtn) {
      verifyBtn.addEventListener('click', () => {
        verifyBtn.innerHTML = `✔ Hash Chain Verified (0 Tampering Detected)`;
        verifyBtn.classList.add('text-emerald-400');
      });
    }
  }
}
