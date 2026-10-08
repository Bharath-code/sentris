/**
 * SENTRIS PRO — Interactive Remediation Studio & IDE Workbench
 * High-fidelity developer studio showing real-time staged scans,
 * live AST code diffs, .env staging, and dual-key rotation.
 */

export class TerminalSimulator {
  constructor(containerElement, reactorInstance = null) {
    this.container = containerElement;
    this.reactor = reactorInstance;
    this.activeTab = 'code'; // 'code' | 'env' | 'audit'
    this.scanState = 'clean'; // 'clean' | 'scanning' | 'detected' | 'fixing' | 'remediated'
    this.init();
  }

  init() {
    this.render();
  }

  render() {
    this.container.innerHTML = `
      <div class="bento-card border border-white/10 shadow-2xl bg-[#090B10]/95 backdrop-blur-2xl">
        
        <!-- IDE Studio Window Bar -->
        <div class="px-4 py-3 bg-[#0D0F15] border-b border-white/[0.08] flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="flex items-center gap-1.5">
              <span class="w-3 h-3 rounded-full bg-[#FF5F56]/80 hover:bg-[#FF5F56] transition-colors cursor-pointer"></span>
              <span class="w-3 h-3 rounded-full bg-[#FFBD2E]/80 hover:bg-[#FFBD2E] transition-colors cursor-pointer"></span>
              <span class="w-3 h-3 rounded-full bg-[#27C93F]/80 hover:bg-[#27C93F] transition-colors cursor-pointer"></span>
            </div>
            
            <!-- File Tabs -->
            <div class="flex items-center gap-1 pl-4 border-l border-white/[0.08]">
              <button id="tab-file-code" class="px-3 py-1 text-xs font-mono rounded-md flex items-center gap-2 transition-all ${this.activeTab === 'code' ? 'bg-[#181C26] text-white font-semibold border border-white/10' : 'text-slate-400 hover:text-white'}">
                <span class="text-[#38BDF8]">TS</span>
                <span>checkout.ts</span>
              </button>
              <button id="tab-file-env" class="px-3 py-1 text-xs font-mono rounded-md flex items-center gap-2 transition-all ${this.activeTab === 'env' ? 'bg-[#181C26] text-white font-semibold border border-white/10' : 'text-slate-400 hover:text-white'}">
                <span class="text-[#F59E0B]">ENV</span>
                <span>.env</span>
                <span class="text-[10px] text-emerald-400 bg-emerald-500/10 px-1 rounded">gitignored</span>
              </button>
              <button id="tab-file-audit" class="px-3 py-1 text-xs font-mono rounded-md flex items-center gap-2 transition-all ${this.activeTab === 'audit' ? 'bg-[#181C26] text-white font-semibold border border-white/10' : 'text-slate-400 hover:text-white'}">
                <span class="text-[#A855F7]">SOC2</span>
                <span>audit_ledger.json</span>
              </button>
            </div>
          </div>

          <!-- Latency & Threading Badge -->
          <div class="hidden sm:flex items-center gap-3 text-xs font-mono text-slate-400">
            <span class="flex items-center gap-1.5 text-emerald-400">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              Rayon 8-Core Engine
            </span>
            <span class="text-slate-600">•</span>
            <span class="text-slate-300">Target: <code class="text-white">&lt;25ms</code></span>
          </div>
        </div>

        <!-- Studio Main Body (Code Editor + Interactive Overlay) -->
        <div class="p-5 sm:p-6 font-mono text-xs leading-relaxed min-h-[300px] relative">
          ${this.renderEditorContent()}
        </div>

        <!-- Interactive Workbench Control Footer -->
        <div class="p-4 bg-[#0B0D13] border-t border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-3">
          <div class="flex items-center gap-3 w-full sm:w-auto">
            ${this.renderControlButtons()}
          </div>

          <div class="flex items-center gap-4 text-xs font-mono text-slate-400 ml-auto">
            <span>Dual-Key Safety: <strong class="text-emerald-400">Active</strong></span>
            <span>Zero-Knowledge: <strong class="text-cyan-400">HMAC-SHA256</strong></span>
          </div>
        </div>

      </div>
    `;

    this.bindEvents();
  }

  renderEditorContent() {
    if (this.activeTab === 'code') {
      if (this.scanState === 'remediated') {
        return `
          <div class="space-y-1">
            <div class="text-slate-500">// src/billing/checkout.ts — Remediated via Sentris AST Engine</div>
            <div class="text-slate-400">import { Stripe } from "stripe";</div>
            <div class="text-slate-400">import { config } from "./config";</div>
            <br>
            <div class="text-slate-400">export async function processStripePayment(amountCents: number) {</div>
            <div class="code-diff-remove line-through opacity-70 my-1">
              -  const stripe = new Stripe("sk_live_51M7...f89a", { apiVersion: "2023-10-16" });
            </div>
            <div class="code-diff-add font-semibold my-1">
              +  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, { apiVersion: "2023-10-16" });
            </div>
            <div class="text-slate-400">   return await stripe.charges.create({ amount: amountCents, currency: "usd" });</div>
            <div class="text-slate-400">}</div>
          </div>
        `;
      }

      if (this.scanState === 'detected' || this.scanState === 'fixing') {
        return `
          <div class="space-y-1">
            <div class="text-slate-500">// src/billing/checkout.ts — Staged Commit Hunk</div>
            <div class="text-slate-400">import { Stripe } from "stripe";</div>
            <div class="text-slate-400">import { config } from "./config";</div>
            <br>
            <div class="text-slate-400">export async function processStripePayment(amountCents: number) {</div>
            <div class="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-200 my-2">
              <div class="flex items-center justify-between font-bold text-red-400 pb-1 border-b border-red-500/20">
                <span>[CRITICAL LEAK DETECTED] stripe-secret-key</span>
                <span class="text-emerald-400 font-mono text-[11px]">Provider Probe: Active Stripe Key</span>
              </div>
              <div class="pt-2 text-white font-bold">
                const stripe = new Stripe("<span class="text-amber-300 underline font-mono">sk_live_51M7...f89a</span>", { apiVersion: "2023-10-16" });
              </div>
              <div class="pt-1.5 text-[11px] text-slate-300">
                Blast Radius: Zone 1 (Staged Hunk) • Shannon Entropy: 4.82 • Uncommitted
              </div>
            </div>
            <div class="text-slate-400">   return await stripe.charges.create({ amount: amountCents, currency: "usd" });</div>
            <div class="text-slate-400">}</div>
          </div>
        `;
      }

      // Clean / Default state
      return `
        <div class="space-y-1">
          <div class="text-slate-500">// src/billing/checkout.ts — Working Tree Staged Changes</div>
          <div class="text-slate-400">import { Stripe } from "stripe";</div>
          <div class="text-slate-400">import { config } from "./config";</div>
          <br>
          <div class="text-slate-400">export async function processStripePayment(amountCents: number) {</div>
          <div class="text-slate-300">
             const stripe = new Stripe("<span class="text-amber-300">sk_live_51M7...f89a</span>", { apiVersion: "2023-10-16" });
          </div>
          <div class="text-slate-400">   return await stripe.charges.create({ amount: amountCents, currency: "usd" });</div>
          <div class="text-slate-400">}</div>
        </div>
      `;
    }

    if (this.activeTab === 'env') {
      return `
        <div class="space-y-2 text-xs">
          <div class="text-slate-500">// .env — Protected Local Environment Secret Store (.gitignore verified)</div>
          <div class="text-slate-400">PORT=3000</div>
          <div class="text-slate-400">NODE_ENV=production</div>
          <div class="text-emerald-400 font-bold bg-emerald-500/10 p-2 rounded border border-emerald-500/20">
            STRIPE_SECRET_KEY=sk_live_new_8a92f4c10e8b7d6a5c
            <div class="text-[10px] text-slate-400 font-normal pt-1">
              ✔ Staged automatically by Sentris Dual-Key Manager • Never committed to git
            </div>
          </div>
        </div>
      `;
    }

    if (this.activeTab === 'audit') {
      return `
        <div class="space-y-2 text-xs">
          <div class="text-slate-500">// .sentris/audit_ledger.json — RFC 2104 Tamper-Proof Hash Chain</div>
          <div class="p-2.5 rounded bg-[#11141C] border border-white/10 text-slate-300 space-y-1">
            <div><span class="text-slate-500">Event:</span> <strong class="text-emerald-400">SecretRemediated</strong></div>
            <div><span class="text-slate-500">Rule:</span> stripe-secret-key</div>
            <div><span class="text-slate-500">Fingerprint:</span> zk_sha256: 8f9a2b4c10e8...</div>
            <div><span class="text-slate-500">Grace Timer:</span> 24h Deprecation Active (Zero Prod Downtime)</div>
            <div><span class="text-slate-500">Entry HMAC:</span> e7b4198c0a... <span class="text-emerald-400 text-[10px]">✔ VERIFIED INTACT</span></div>
          </div>
        </div>
      `;
    }

    return '';
  }

  renderControlButtons() {
    if (this.scanState === 'clean') {
      return `
        <button id="btn-run-staged-scan" class="btn-primary text-xs py-2 px-4">
          ⚡ Run Staged Scan (18ms)
        </button>
        <span class="text-xs text-slate-400 font-mono">
          Click to simulate pre-commit check
        </span>
      `;
    }

    if (this.scanState === 'scanning') {
      return `
        <button class="btn-primary text-xs py-2 px-4 opacity-75 cursor-wait">
          <span class="animate-spin inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full mr-2"></span>
          Parallel Crawl (18.4ms)...
        </button>
      `;
    }

    if (this.scanState === 'detected') {
      return `
        <button id="btn-trigger-autofix" class="btn-primary text-xs py-2 px-4 bg-gradient-to-r from-[#FF5500] to-[#E64500]">
          🚀 Execute Autonomous Safe Fix (15s)
        </button>
        <button id="btn-reset-clean" class="btn-glass text-xs py-2 px-3">
          Dismiss
        </button>
      `;
    }

    if (this.scanState === 'fixing') {
      return `
        <button class="btn-primary text-xs py-2 px-4 opacity-80 cursor-wait">
          <span class="animate-spin inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full mr-2"></span>
          Provisioning Replacement Key via Stripe API...
        </button>
      `;
    }

    if (this.scanState === 'remediated') {
      return `
        <span class="badge-clean badge-tag-emerald py-1.5 px-3">
          ✔ Autonomous Fix Applied (14.8s)
        </span>
        <button id="btn-rollback" class="btn-glass text-xs py-2 px-3 hover:text-red-400">
          ↺ Revert Session (1-Click Rollback)
        </button>
        <button id="btn-reset-clean" class="btn-glass text-xs py-2 px-3">
          Run Another Test
        </button>
      `;
    }

    return '';
  }

  bindEvents() {
    // Tab switching
    const tabCode = this.container.querySelector('#tab-file-code');
    const tabEnv = this.container.querySelector('#tab-file-env');
    const tabAudit = this.container.querySelector('#tab-file-audit');

    if (tabCode) tabCode.addEventListener('click', () => { this.activeTab = 'code'; this.render(); });
    if (tabEnv) tabEnv.addEventListener('click', () => { this.activeTab = 'env'; this.render(); });
    if (tabAudit) tabAudit.addEventListener('click', () => { this.activeTab = 'audit'; this.render(); });

    // Actions
    const scanBtn = this.container.querySelector('#btn-run-staged-scan');
    if (scanBtn) {
      scanBtn.addEventListener('click', () => {
        this.scanState = 'scanning';
        this.render();
        if (this.reactor) this.reactor.triggerScanPulse();

        setTimeout(() => {
          this.scanState = 'detected';
          this.render();
        }, 320);
      });
    }

    const fixBtn = this.container.querySelector('#btn-trigger-autofix');
    if (fixBtn) {
      fixBtn.addEventListener('click', () => {
        this.scanState = 'fixing';
        this.render();
        if (this.reactor) this.reactor.triggerScanPulse();

        setTimeout(() => {
          this.scanState = 'remediated';
          this.render();
        }, 650);
      });
    }

    const rollbackBtn = this.container.querySelector('#btn-rollback');
    if (rollbackBtn) {
      rollbackBtn.addEventListener('click', () => {
        this.scanState = 'clean';
        this.render();
      });
    }

    const resetBtn = this.container.querySelector('#btn-reset-clean');
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        this.scanState = 'clean';
        this.render();
      });
    }
  }
}
