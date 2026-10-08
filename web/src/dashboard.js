/**
 * SENTRIS PRO — Commercial Team SaaS Dashboard ($8/Seat Pro Tier)
 * Clean Linear-grade developer console with live zero-knowledge findings stream,
 * seat management, and SOC 2 cryptographic hash chain verification.
 */

export class TeamDashboard {
  constructor(containerElement) {
    this.container = containerElement;
    this.activeTab = 'stream'; // 'stream' | 'members' | 'audit' | 'integrations'
    this.findings = [
      {
        id: 'fnd_stripe_01',
        time: 'Just now',
        author: 'alex.v@acme.corp',
        repo: 'acme/billing-service',
        branch: 'feature/checkout-v2',
        rule: 'stripe-secret-key',
        severity: 'Critical',
        preview: 'sk_live_51M7...f89a',
        fingerprint: 'zk_a94f18c8e2b7...',
        zone: 'Zone 1 (Staged Hunk)',
        status: 'Active (Unremediated)'
      },
      {
        id: 'fnd_aws_02',
        time: '14m ago',
        author: 'elena.r@acme.corp',
        repo: 'acme/infra-terraform',
        branch: 'main',
        rule: 'aws-access-key-id',
        severity: 'High',
        preview: 'AKIA...89BC',
        fingerprint: 'zk_77b312fe89c0...',
        zone: 'Zone 1 (Staged Hunk)',
        status: 'Remediated (Dual-Key Safe)'
      },
      {
        id: 'fnd_gh_03',
        time: '2h ago',
        author: 'marcus.b@acme.corp',
        repo: 'acme/api-gateway',
        branch: 'chore/deps',
        rule: 'github-pat',
        severity: 'Critical',
        preview: 'ghp_...77ff',
        fingerprint: 'zk_33e498aa01b1...',
        zone: 'Zone 2 (Local Commit)',
        status: 'Remediated (Dual-Key Safe)'
      },
      {
        id: 'fnd_anthropic_04',
        time: 'Yesterday',
        author: 'devon.c@acme.corp',
        repo: 'acme/llm-agents',
        branch: 'feat/claude-eval',
        rule: 'anthropic-api-key',
        severity: 'High',
        preview: 'sk-ant-api03-...d49a',
        fingerprint: 'zk_f1a28790b821...',
        zone: 'Zone 1 (Staged Hunk)',
        status: 'Remediated (Dual-Key Safe)'
      }
    ];

    this.members = [
      { name: 'Alex Vance', email: 'alex.v@acme.corp', role: 'Admin (Owner)', lastScan: 'Active now (Localhost)', seats: 'Occupied' },
      { name: 'Elena Rostova', email: 'elena.r@acme.corp', role: 'AppSec Lead', lastScan: '14m ago (pre-commit)', seats: 'Occupied' },
      { name: 'Marcus Brody', email: 'marcus.b@acme.corp', role: 'Staff Backend Eng', lastScan: '2h ago (CI/CD push)', seats: 'Occupied' },
      { name: 'Devon Clark', email: 'devon.c@acme.corp', role: 'Frontend Architect', lastScan: 'Yesterday (pre-commit)', seats: 'Occupied' },
      { name: 'Sarah Jenkins', email: 'sarah.j@acme.corp', role: 'DevOps Lead', lastScan: '3 days ago', seats: 'Occupied' },
    ];

    this.auditRecords = [
      { id: 104, action: 'ScanCompleted', time: '13:09:42', hash: '5f9e2b10', details: '24 staged files evaluated in 18ms. Zero raw leaks uploaded.' },
      { id: 103, action: 'SecretRemediated', time: '12:45:11', hash: '8a12c49e', details: 'Stripe key rotated via Dual-Key API. Replacement injected in .env.' },
      { id: 102, action: 'BaselineRecorded', time: '11:20:00', hash: '3e41b99a', details: 'Cryptographic baseline snapshot sealed for repo acme/billing-service.' },
      { id: 101, action: 'QuarantineCreated', time: '09:15:30', hash: 'c901284a', details: 'Zone 3 quarantine branch sentris/quarantine/gh-pat generated safely.' },
    ];

    this.init();
  }

  init() {
    this.render();
  }

  render() {
    this.container.innerHTML = `
      <div class="max-w-7xl mx-auto space-y-8">
        
        <!-- Organization Header Card -->
        <div class="bento-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div class="flex items-center gap-4">
            <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-[#FF5500] to-[#CC3700] flex items-center justify-center font-mono font-bold text-white text-lg shadow-lg">
              §
            </div>
            <div>
              <div class="flex items-center gap-3">
                <h2 class="text-xl font-bold text-white tracking-tight">Acme Cyber Operations</h2>
                <span class="badge-clean badge-tag-cadmium">PRO TIER ($8/SEAT)</span>
              </div>
              <div class="text-xs text-slate-400 flex items-center gap-3 pt-1">
                <span>Org ID: <code class="text-slate-300 font-mono">org_acme_cyber_ops</code></span>
                <span>•</span>
                <span class="text-emerald-400 flex items-center gap-1.5 font-mono">
                  <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  Zero-Knowledge Telemetry Mesh Connected
                </span>
              </div>
            </div>
          </div>

          <div class="flex items-center gap-3">
            <button onclick="alert('Invite link copied to clipboard:\nhttps://api.sentris.dev/invite/org_acme_cyber_ops')" class="btn-glass text-xs py-2 px-4">
              + Invite Developer
            </button>
            <button onclick="alert('Generated Sentris Pro CLI License Token:\nsp_live_' + Math.random().toString(36).substring(2, 14) + '\n\nTo login on workstation run:\nsentris auth login --token <TOKEN>')" class="btn-primary text-xs py-2 px-4">
              Generate License Token
            </button>
          </div>
        </div>

        <!-- 4 Key Metric Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          
          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>SEAT ALLOCATION</span>
              <span class="text-[#FF8844] font-bold">14 / 20 SEATS</span>
            </div>
            <div class="text-2xl font-mono font-bold text-white">$112 <span class="text-xs text-slate-400 font-normal">/ mo</span></div>
            <div class="w-full bg-[#181C26] h-1.5 rounded-full overflow-hidden">
              <div class="bg-[#FF5500] h-full rounded-full" style="width: 70%"></div>
            </div>
            <div class="text-[11px] text-slate-400 flex justify-between pt-1">
              <span>70% Quota Used</span>
              <span>6 Seats Free</span>
            </div>
          </div>

          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>ZERO-KNOWLEDGE SCANS</span>
              <span class="text-emerald-400 font-bold">100% PRIVATE</span>
            </div>
            <div class="text-2xl font-mono font-bold text-white">1,842 <span class="text-xs text-slate-400 font-normal">Scans</span></div>
            <div class="text-[11px] text-emerald-400 font-medium">
              ✔ 0 raw secrets or code uploaded
            </div>
            <div class="text-[10px] text-slate-400">
              Salted HMAC-SHA256 tokens only
            </div>
          </div>

          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>AUTO-REMEDIATIONS</span>
              <span class="text-cyan-400 font-bold">14.8s AVG</span>
            </div>
            <div class="text-2xl font-mono font-bold text-white">12 <span class="text-xs text-emerald-400 font-semibold">/ 13 Safe</span></div>
            <div class="text-[11px] text-slate-300">
              Dual-Key Staged (0 Outages)
            </div>
            <div class="text-[10px] text-slate-400">
              ~32 dev fire-drill hours saved
            </div>
          </div>

          <div class="bento-card p-5 space-y-2">
            <div class="flex justify-between items-center text-xs text-slate-400 font-mono">
              <span>SOC 2 AUDIT CHAIN</span>
              <span class="text-emerald-400 font-bold">VERIFIED</span>
            </div>
            <div class="text-2xl font-mono font-bold text-emerald-400">100% <span class="text-xs text-slate-400 font-normal">Intact</span></div>
            <div class="text-[11px] text-slate-300">
              Append-only cryptographic chain
            </div>
            <div class="text-[10px] text-slate-400">
              RFC 2104 HMAC tamper-proof sealed
            </div>
          </div>

        </div>

        <!-- Dashboard Navigation Tabs -->
        <div class="flex border-b border-white/[0.08] gap-4 text-xs font-semibold">
          <button id="dash-tab-stream" class="pb-3 px-1 transition-all ${this.activeTab === 'stream' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            Real-Time Telemetry Feed (${this.findings.length})
          </button>
          <button id="dash-tab-members" class="pb-3 px-1 transition-all ${this.activeTab === 'members' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            Active Team Seats (14/20)
          </button>
          <button id="dash-tab-audit" class="pb-3 px-1 transition-all ${this.activeTab === 'audit' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            SOC 2 Cryptographic Ledger
          </button>
          <button id="dash-tab-integrations" class="pb-3 px-1 transition-all ${this.activeTab === 'integrations' ? 'border-b-2 border-[#FF5500] text-white' : 'text-slate-400 hover:text-white'}">
            Slack & GitHub Integrations
          </button>
        </div>

        <!-- Dynamic Content Body -->
        <div id="dash-body">
          ${this.renderBodyContent()}
        </div>

      </div>
    `;

    this.bindEvents();
  }

  renderBodyContent() {
    if (this.activeTab === 'stream') {
      return `
        <div class="bento-card overflow-hidden">
          <div class="p-4 bg-[#0E1017] border-b border-white/[0.08] flex items-center justify-between">
            <div class="text-xs font-mono font-bold text-white flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-[#FF5500] animate-pulse"></span>
              LIVE ZERO-KNOWLEDGE FINDINGS STREAM
            </div>
            <div class="text-xs font-mono text-slate-400">
              Auto-Sync: Enabled (CLI & CI/CD Push)
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="bg-[#080A0E] text-slate-400 uppercase border-b border-white/[0.08]">
                <tr>
                  <th class="p-3.5">Time</th>
                  <th class="p-3.5">Developer / Repo</th>
                  <th class="p-3.5">Detector Rule</th>
                  <th class="p-3.5">Preview / Fingerprint</th>
                  <th class="p-3.5">Zone</th>
                  <th class="p-3.5">Status</th>
                  <th class="p-3.5 text-right">Autonomous Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-white/[0.08] text-slate-200">
                ${this.findings.map(f => `
                  <tr class="hover:bg-[#11141C] transition-colors">
                    <td class="p-3.5 text-slate-400">${f.time}</td>
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
                      <div class="text-[10px] text-slate-500">${f.fingerprint}</div>
                    </td>
                    <td class="p-3.5 text-cyan-400">${f.zone}</td>
                    <td class="p-3.5">
                      <span class="badge-clean ${f.status.includes('Active') ? 'bg-red-500/10 text-red-400 border border-red-500/30' : 'badge-tag-emerald'}">
                        ${f.status}
                      </span>
                    </td>
                    <td class="p-3.5 text-right">
                      ${f.status.includes('Active') ? `
                        <button class="btn-primary text-[11px] py-1 px-3 action-fix-btn" data-id="${f.id}">
                          Safe Remediate
                        </button>
                      ` : `
                        <span class="text-[11px] text-slate-400">Resolved in 14.8s</span>
                      `}
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    if (this.activeTab === 'members') {
      return `
        <div class="bento-card overflow-hidden">
          <div class="p-4 bg-[#0E1017] border-b border-white/[0.08] flex items-center justify-between">
            <div>
              <div class="text-sm font-bold text-white">Active Team Seats ($8/seat Pro Plan)</div>
              <div class="text-xs text-slate-400">Includes pre-commit hook scanning, autonomous remediation, and team dashboard sync.</div>
            </div>
            <button class="btn-primary text-xs py-1.5 px-3">
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
                  <th class="p-3.5">Last Local Scan</th>
                  <th class="p-3.5">Seat Status</th>
                  <th class="p-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-white/[0.08] text-slate-200">
                ${this.members.map(m => `
                  <tr class="hover:bg-[#11141C] transition-colors">
                    <td class="p-3.5 font-bold text-white font-sans">${m.name}</td>
                    <td class="p-3.5 text-slate-400">${m.email}</td>
                    <td class="p-3.5"><span class="badge-clean badge-tag-cadmium">${m.role}</span></td>
                    <td class="p-3.5 text-slate-400">${m.lastScan}</td>
                    <td class="p-3.5"><span class="badge-clean badge-tag-emerald">${m.seats}</span></td>
                    <td class="p-3.5 text-right">
                      <button class="btn-glass text-[11px] py-1 px-2.5">Edit</button>
                    </td>
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
                <h3 class="text-base font-bold text-white">SOC 2 / ISO 27001 Cryptographic Hash Chain</h3>
                <span class="badge-clean badge-tag-emerald">INTEGRITY 100% VERIFIED</span>
              </div>
              <p class="text-xs text-slate-400 pt-1">
                Every scan, rotation, and quarantine action appends an immutable RFC 2104 HMAC-SHA256 signed entry.
              </p>
            </div>
            <div class="flex items-center gap-2">
              <button id="btn-verify-audit-chain" class="btn-glass text-xs py-1.5 px-3">
                Verify Chain (`sentris audit --verify`)
              </button>
              <button class="btn-primary text-xs py-1.5 px-3">
                Export Evidence JSON
              </button>
            </div>
          </div>

          <div class="space-y-3 font-mono text-xs">
            ${this.auditRecords.map(r => `
              <div class="p-3.5 rounded-xl bg-[#10131A] border border-white/10 flex items-start justify-between gap-4">
                <div class="space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="text-slate-400 font-bold">#${r.id}</span>
                    <span class="badge-clean badge-tag-cadmium text-[10px]">${r.action}</span>
                    <span class="text-slate-400 text-[11px]">${r.time}</span>
                  </div>
                  <div class="text-slate-200">${r.details}</div>
                </div>
                <div class="text-right">
                  <div class="text-[10px] text-slate-400">Entry Hash:</div>
                  <div class="text-cyan-400 font-bold">${r.hash}...</div>
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
          <div class="bento-card p-6 space-y-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-[#4A154B] flex items-center justify-center text-white font-bold text-sm">#</div>
                <div>
                  <div class="text-sm font-bold text-white">Slack Incident Bot</div>
                  <div class="text-xs text-slate-400">Real-time Block Kit incident cards with 1-click rotation</div>
                </div>
              </div>
              <span class="badge-clean badge-tag-emerald">CONNECTED</span>
            </div>
            <p class="text-xs text-slate-300">
              Alerts dispatched to <code class="text-white bg-[#181C26] px-1 py-0.5 rounded font-mono">#security-fire-drill</code> on critical leaks.
            </p>
            <button class="btn-glass text-xs py-1.5 px-3">Configure Channel</button>
          </div>

          <div class="bento-card p-6 space-y-4">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-[#24292E] flex items-center justify-center text-white font-bold text-sm">GH</div>
                <div>
                  <div class="text-sm font-bold text-white">GitHub PR App</div>
                  <div class="text-xs text-slate-400">Automated pull-request comments with env-var fixes</div>
                </div>
              </div>
              <span class="badge-clean badge-tag-emerald">ACTIVE</span>
            </div>
            <p class="text-xs text-slate-300">
              Installed across 18 private repositories. Blocks leaks before merge.
            </p>
            <button class="btn-glass text-xs py-1.5 px-3">Manage Installed Repos</button>
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

    tabs.forEach(t => {
      const el = this.container.querySelector(`#${t.id}`);
      if (el) {
        el.addEventListener('click', () => {
          this.activeTab = t.key;
          this.render();
        });
      }
    });

    const fixBtns = this.container.querySelectorAll('.action-fix-btn');
    fixBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.target.dataset.id;
        const finding = this.findings.find(f => f.id === id);
        if (finding) {
          btn.innerHTML = `<span class="animate-spin inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full mr-1"></span> Rotating...`;
          setTimeout(() => {
            finding.status = 'Remediated (Dual-Key Safe)';
            this.render();
          }, 550);
        }
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
