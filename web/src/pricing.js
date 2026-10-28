/**
 * SENTRIS PRO — Interactive $8/Seat Pro Pricing, ROI Calculator & Dodo Payments MoR Checkout
 * Minimalist, high-converting pricing architecture inspired by Linear, Raycast & Supabase.
 */

import { openDodoCheckoutModal, initSpotlightCards } from './reactbits.js';

export class PricingCalculator {
  constructor(containerElement) {
    this.container = containerElement;
    this.seats = 15;
    this.isAnnual = false;
    this.currency = 'USD'; // 'USD' | 'INR'
    this.init();
  }

  init() {
    this.render();
    this.bindEvents();
    this.calculate();
  }

  render() {
    this.container.innerHTML = `
      <div class="max-w-6xl mx-auto space-y-12">
        
        <!-- Header -->
        <div class="text-center space-y-3">
          <div class="flex flex-wrap items-center justify-center gap-2">
            <span class="badge-clean badge-tag-cadmium">TRANSPARENT UNIT ECONOMICS</span>
            <span class="badge-clean badge-tag-emerald">POWERED BY DODO PAYMENTS (GLOBAL & INDIA MoR)</span>
          </div>
          <h2 class="text-3xl sm:text-5xl font-extrabold text-white tracking-tight font-display">
            Detection is free. <span class="text-[#FF8844]">We charge for fixing things.</span>
          </h2>
          <p class="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Legacy scanners charge $19–$25/dev/mo just to flood Jira with tickets. At $8/seat, Sentris Pro pays for itself on day one by eliminating 2.5 hours of manual rotation fire-drills per developer.
          </p>

          <!-- Billing Period & Currency Switch -->
          <div class="flex flex-wrap items-center justify-center gap-3 mt-4">
            <div class="inline-flex items-center gap-2 p-1 bg-[#141722] border border-white/10 rounded-full">
              <button id="btn-billing-monthly" class="px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${!this.isAnnual ? 'bg-[#FF5500] text-white shadow-sm' : 'text-slate-400 hover:text-white'}">
                Monthly Billing ($8/seat)
              </button>
              <button id="btn-billing-annual" class="px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${this.isAnnual ? 'bg-[#FF5500] text-white shadow-sm' : 'text-slate-400 hover:text-white'} flex items-center gap-1.5">
                <span>Annual Billing ($7/seat)</span>
                <span class="bg-emerald-500/20 text-emerald-300 text-[10px] px-1.5 py-0.5 rounded-full font-mono">SAVE 12.5%</span>
              </button>
            </div>

            <div class="inline-flex items-center gap-1 p-1 bg-[#141722] border border-white/10 rounded-full text-xs font-mono">
              <button id="btn-curr-usd" class="px-3 py-1 rounded-full transition-all ${this.currency === 'USD' ? 'bg-white/15 text-white font-bold' : 'text-slate-400 hover:text-white'}">$ USD</button>
              <button id="btn-curr-inr" class="px-3 py-1 rounded-full transition-all ${this.currency === 'INR' ? 'bg-white/15 text-emerald-300 font-bold' : 'text-slate-400 hover:text-white'}">₹ INR (UPI)</button>
            </div>
          </div>
        </div>

        <!-- Interactive Calculator Bar -->
        <div class="bento-card p-6 sm:p-8">
          <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            
            <!-- Left Slider Controls -->
            <div class="lg:col-span-7 space-y-5">
              <div class="flex items-center justify-between">
                <div>
                  <div class="text-sm font-bold text-white">Engineering Team Size</div>
                  <div class="text-xs text-slate-400">Active developers pushing code & git commits</div>
                </div>
                <div class="flex items-baseline gap-1">
                  <span id="calc-seat-display" class="text-3xl font-mono font-extrabold text-[#FF8844]">${this.seats}</span>
                  <span class="text-xs font-mono text-slate-400">SEATS</span>
                </div>
              </div>

              <input id="calc-seat-slider" type="range" min="2" max="100" value="${this.seats}" aria-label="Engineering Team Size">

              <div class="flex flex-wrap items-center gap-2 pt-1 text-xs">
                <span class="text-slate-400">Quick presets:</span>
                <button class="calc-preset-btn px-2.5 py-1 rounded bg-[#141722] text-slate-300 hover:text-white border border-white/10 font-mono" data-seats="5">Seed (5)</button>
                <button class="calc-preset-btn px-2.5 py-1 rounded bg-[#141722] text-slate-300 hover:text-white border border-white/10 font-mono" data-seats="15">Series A (15)</button>
                <button class="calc-preset-btn px-2.5 py-1 rounded bg-[#141722] text-slate-300 hover:text-white border border-white/10 font-mono" data-seats="40">Series B (40)</button>
                <button class="calc-preset-btn px-2.5 py-1 rounded bg-[#141722] text-slate-300 hover:text-white border border-white/10 font-mono" data-seats="80">Scaleup (80)</button>
              </div>
            </div>

            <!-- Right Dynamic ROI Engine -->
            <div class="lg:col-span-5 bg-[#10131A] p-6 rounded-2xl border border-white/10 space-y-4">
              <div class="flex items-center justify-between pb-3 border-b border-white/[0.08]">
                <span class="text-xs font-mono text-slate-400 uppercase tracking-wider">Monthly Investment</span>
                <div class="text-right">
                  <span id="calc-cost-display" class="text-2xl font-mono font-bold text-white">$120</span>
                  <span class="text-xs text-slate-400">/ mo</span>
                </div>
              </div>

              <div class="space-y-2 text-xs text-slate-300">
                <div class="flex justify-between">
                  <span>Dev Fire-Drill Hours Saved:</span>
                  <span id="calc-hours-display" class="font-mono font-semibold text-white">37.5 hrs / mo</span>
                </div>
                <div class="flex justify-between">
                  <span>Engineering Wage Value Recovered:</span>
                  <span id="calc-value-display" class="font-mono font-semibold text-emerald-400">$4,125 / mo</span>
                </div>
                <div class="flex justify-between">
                  <span>Single Leaked Key Incident Avoided:</span>
                  <span class="font-mono font-semibold text-cyan-400">~$14,500</span>
                </div>
              </div>

              <div class="pt-3 border-t border-white/[0.08] flex items-center justify-between">
                <div>
                  <div class="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Net Monthly ROI</div>
                  <div id="calc-roi-display" class="text-xl font-mono font-extrabold text-emerald-400">3,338%</div>
                </div>
                <button id="btn-calc-dodo-checkout" class="btn-primary text-xs py-2 px-4">
                  Checkout via Dodo Payments →
                </button>
              </div>
            </div>

          </div>
        </div>

        <!-- 3-Tier Plan Comparison Cards -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          <!-- Free MIT Tier -->
          <div class="bento-card p-6 sm:p-8 flex flex-col justify-between">
            <div class="space-y-4">
              <div class="badge-clean badge-tag-muted">OPEN SOURCE (MIT)</div>
              <h3 class="text-xl font-bold text-white font-display">Free Local CLI</h3>
              <div class="text-3xl font-mono font-extrabold text-white mt-1">$0</div>
              <p class="text-xs text-slate-400">
                Full-speed local scanner, IDE LSP & AI MCP server under MIT license. Free forever.
              </p>

              <div class="space-y-2 text-xs text-slate-300 pt-2">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Sub-18ms Parallel Walker + DFA Engine</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>57+ Secret Detectors + 6-Layer FP Filter</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Built-in <code class="font-mono text-white">sentris mcp</code> & <code class="font-mono text-white">sentris lsp</code></span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Pre-commit, Pre-push & SARIF 2.1.0</span>
                </div>
                <div class="flex items-center gap-2 text-slate-500">
                  <span>✖</span>
                  <span class="line-through">Safe Dual-Key Cloud Rotation</span>
                </div>
                <div class="flex items-center gap-2 text-slate-500">
                  <span>✖</span>
                  <span class="line-through">Multi-Repo ZK Blast Radius Cloud</span>
                </div>
              </div>
            </div>

            <div class="pt-6 mt-6 border-t border-white/[0.08]">
              <button onclick="navigator.clipboard?.writeText('cargo install --path .'); this.textContent='✔ Copied: cargo install --path .'" class="btn-glass w-full justify-center text-xs font-mono">
                cargo install sentris-cli
              </button>
            </div>
          </div>

          <!-- Pro Team Tier ($8/seat) - ELEVATED CENTER -->
          <div class="bento-card p-6 sm:p-8 flex flex-col justify-between border-[#FF5500]/50 relative shadow-2xl bg-gradient-to-b from-[#141722] to-[#0B0D12]">
            <div class="absolute top-3 right-3 badge-clean badge-tag-cadmium">
              MOST POPULAR
            </div>
            
            <div class="space-y-4">
              <div class="badge-clean badge-tag-cadmium">COMMERCIAL PRO</div>
              <h3 class="text-xl font-bold text-white font-display">Sentris Pro Team</h3>
              <div class="text-3xl font-mono font-extrabold text-[#FF8844] mt-1">
                <span id="card-price-pro">$8</span><span class="text-sm font-normal text-slate-400"> / dev / mo</span>
              </div>
              <p class="text-xs text-slate-400">
                Turn leaks into autonomous 15s fixes with zero-knowledge multi-repo correlation.
              </p>

              <div class="space-y-2 text-xs text-slate-200 pt-2">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400 font-bold">✔</span>
                  <span class="font-bold text-white">Autonomous 15s Code + Vault Remediation</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Safe Dual-Key Rotation (0 Prod Downtime)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Zero-Knowledge Multi-Repo Blast Radius</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Vault, AWS, Doppler, 1Password & Infisical</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Slack Block Kit & GitHub PR Bot</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Dodo Payments MoR (Cards, Apple Pay, UPI)</span>
                </div>
              </div>
            </div>

            <div class="pt-6 mt-6 border-t border-white/[0.08]">
              <button id="btn-card-pro-dodo" class="btn-primary w-full justify-center text-xs">
                Start 14-Day Free Trial (Dodo MoR)
              </button>
            </div>
          </div>

          <!-- Enterprise Tier -->
          <div class="bento-card p-6 sm:p-8 flex flex-col justify-between">
            <div class="space-y-4">
              <div class="badge-clean badge-tag-muted">SELF-HOSTED / AIR-GAPPED</div>
              <h3 class="text-xl font-bold text-white font-display">Enterprise</h3>
              <div class="text-3xl font-mono font-extrabold text-white mt-1">
                <span id="card-price-ent">$2,000</span><span class="text-sm font-normal text-slate-400"> / year</span>
              </div>
              <p class="text-xs text-slate-400">
                Flat rate up to 50 developers ($3.33/dev/mo). Air-gapped Vanta SOC 2 compliance.
              </p>

              <div class="space-y-2 text-xs text-slate-300 pt-2">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span class="text-white font-semibold">Everything in Pro plus:</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>100% On-Prem Cloudflare / K8s Worker</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Vanta SOC 2 CC6.1 / CC6.6 Evidence Pack</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>RFC 2104 HMAC-SHA256 Tamper-Evident Chain</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Dedicated Slack Engineering Channel & SLA</span>
                </div>
              </div>
            </div>

            <div class="pt-6 mt-6 border-t border-white/[0.08]">
              <button id="btn-card-ent-dodo" class="btn-glass w-full justify-center text-xs">
                Provision Enterprise License
              </button>
            </div>
          </div>

        </div>

      </div>
    `;

    initSpotlightCards(this.container);
  }

  bindEvents() {
    const slider = this.container.querySelector('#calc-seat-slider');
    const monthlyBtn = this.container.querySelector('#btn-billing-monthly');
    const annualBtn = this.container.querySelector('#btn-billing-annual');
    const usdBtn = this.container.querySelector('#btn-curr-usd');
    const inrBtn = this.container.querySelector('#btn-curr-inr');
    const presetBtns = this.container.querySelectorAll('.calc-preset-btn');
    const calcDodoBtn = this.container.querySelector('#btn-calc-dodo-checkout');
    const proDodoBtn = this.container.querySelector('#btn-card-pro-dodo');
    const entDodoBtn = this.container.querySelector('#btn-card-ent-dodo');

    if (slider) {
      slider.addEventListener('input', (e) => {
        this.seats = parseInt(e.target.value, 10);
        this.calculate();
      });
    }

    if (monthlyBtn) {
      monthlyBtn.addEventListener('click', () => {
        this.isAnnual = false;
        this.init();
      });
    }

    if (annualBtn) {
      annualBtn.addEventListener('click', () => {
        this.isAnnual = true;
        this.init();
      });
    }

    if (usdBtn) {
      usdBtn.addEventListener('click', () => {
        this.currency = 'USD';
        this.init();
      });
    }

    if (inrBtn) {
      inrBtn.addEventListener('click', () => {
        this.currency = 'INR';
        this.init();
      });
    }

    presetBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        this.seats = parseInt(btn.dataset.seats, 10);
        if (slider) slider.value = this.seats;
        this.calculate();
      });
    });

    const triggerCheckout = (plan) => {
      openDodoCheckoutModal({
        plan,
        seats: this.seats,
        isAnnual: this.isAnnual
      });
    };

    if (calcDodoBtn) calcDodoBtn.addEventListener('click', () => triggerCheckout('pro'));
    if (proDodoBtn) proDodoBtn.addEventListener('click', () => triggerCheckout('pro'));
    if (entDodoBtn) entDodoBtn.addEventListener('click', () => triggerCheckout('enterprise'));
  }

  calculate() {
    const unitPriceUsd = this.isAnnual ? 7 : 8;
    const monthlyTotalUsd = this.seats * unitPriceUsd;
    const hoursSaved = this.seats * 2.5;
    const valueRecoveredUsd = hoursSaved * 110;
    const roi = Math.round(((valueRecoveredUsd - monthlyTotalUsd) / monthlyTotalUsd) * 100);

    const rate = this.currency === 'INR' ? 84 : 1;
    const sym = this.currency === 'INR' ? '₹' : '$';

    const seatEl = this.container.querySelector('#calc-seat-display');
    const costEl = this.container.querySelector('#calc-cost-display');
    const hoursEl = this.container.querySelector('#calc-hours-display');
    const valueEl = this.container.querySelector('#calc-value-display');
    const roiEl = this.container.querySelector('#calc-roi-display');
    const proPriceEl = this.container.querySelector('#card-price-pro');
    const entPriceEl = this.container.querySelector('#card-price-ent');

    if (seatEl) seatEl.textContent = this.seats;
    if (costEl) costEl.textContent = `${sym}${(monthlyTotalUsd * rate).toLocaleString()}`;
    if (hoursEl) hoursEl.textContent = `${hoursSaved.toFixed(1)} hrs / mo`;
    if (valueEl) valueEl.textContent = `${sym}${(valueRecoveredUsd * rate).toLocaleString()} / mo`;
    if (roiEl) roiEl.textContent = `${roi.toLocaleString()}%`;
    if (proPriceEl) proPriceEl.textContent = `${sym}${Math.round(unitPriceUsd * rate)}`;
    if (entPriceEl) entPriceEl.textContent = `${sym}${(2000 * rate).toLocaleString()}`;
  }
}
