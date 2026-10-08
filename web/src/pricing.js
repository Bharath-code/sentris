/**
 * SENTRIS PRO — Interactive $8/Seat Pro Pricing & ROI Calculator
 * Minimalist, high-taste pricing interface inspired by Linear and Supabase.
 */

export class PricingCalculator {
  constructor(containerElement) {
    this.container = containerElement;
    this.seats = 15;
    this.isAnnual = false;
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
          <div class="badge-clean badge-tag-cadmium">TRANSPARENT UNIT ECONOMICS</div>
          <h2 class="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Detection is free. <span class="text-[#FF8844]">We charge for fixing things.</span>
          </h2>
          <p class="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            Every other scanner charges $15–$25/dev/mo to dump Jira tickets. At $8/seat, Sentris Pro pays for itself on day one by eliminating 2.5 hours of manual rotation fire-drills per developer.
          </p>

          <!-- Billing Period Switch -->
          <div class="inline-flex items-center gap-2 p-1 bg-[#141722] border border-white/10 rounded-full mt-4">
            <button id="btn-billing-monthly" class="px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${!this.isAnnual ? 'bg-[#FF5500] text-white shadow-sm' : 'text-slate-400 hover:text-white'}">
              Monthly Billing ($8/seat)
            </button>
            <button id="btn-billing-annual" class="px-4 py-1.5 text-xs font-semibold rounded-full transition-all ${this.isAnnual ? 'bg-[#FF5500] text-white shadow-sm' : 'text-slate-400 hover:text-white'} flex items-center gap-1.5">
              <span>Annual Billing ($7/seat)</span>
              <span class="bg-emerald-500/20 text-emerald-300 text-[10px] px-1.5 py-0.5 rounded-full font-mono">SAVE 12.5%</span>
            </button>
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

              <input id="calc-seat-slider" type="range" min="2" max="100" value="${this.seats}">

              <div class="flex items-center gap-2 pt-1 text-xs">
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
                  <div id="calc-roi-display" class="text-xl font-mono font-extrabold text-emerald-400">3,437%</div>
                </div>
                <button onclick="document.getElementById('nav-btn-dashboard').click()" class="btn-primary text-xs py-2 px-4">
                  Start 14-Day Free Trial
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
              <div class="badge-clean badge-tag-muted">OPEN SOURCE</div>
              <h3 class="text-xl font-bold text-white">Free Local CLI</h3>
              <div class="text-3xl font-mono font-extrabold text-white mt-1">$0</div>
              <p class="text-xs text-slate-400">
                Fully functional local scanner under MIT license. Free forever.
              </p>

              <div class="space-y-2 text-xs text-slate-300 pt-2">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Sub-50ms Rayon parallel engine</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>50+ built-in secret detectors</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Pre-commit hook & SARIF export</span>
                </div>
                <div class="flex items-center gap-2 text-slate-500">
                  <span>✖</span>
                  <span class="line-through">Autonomous remediation</span>
                </div>
                <div class="flex items-center gap-2 text-slate-500">
                  <span>✖</span>
                  <span class="line-through">Safe dual-key key rotation</span>
                </div>
                <div class="flex items-center gap-2 text-slate-500">
                  <span>✖</span>
                  <span class="line-through">Centralized team SaaS dashboard</span>
                </div>
              </div>
            </div>

            <div class="pt-6 mt-6 border-t border-white/[0.08]">
              <button class="btn-glass w-full justify-center text-xs">
                brew install sentris
              </button>
            </div>
          </div>

          <!-- Pro Team Tier ($8/seat) - ELEVATED CENTER -->
          <div class="bento-card p-6 sm:p-8 flex flex-col justify-between border-[#FF5500]/50 relative shadow-2xl bg-gradient-to-b from-[#141722] to-[#0B0D12]">
            <div class="absolute -top-3 left-1/2 -translate-x-1/2 badge-clean badge-tag-cadmium">
              RECOMMENDED FOR TEAMS
            </div>
            
            <div class="space-y-4">
              <div class="badge-clean badge-tag-cadmium">PRO TIER</div>
              <h3 class="text-xl font-bold text-white">Commercial Pro</h3>
              <div class="text-3xl font-mono font-extrabold text-[#FF8844] mt-1">
                $<span id="card-price-pro">8</span><span class="text-sm font-normal text-slate-400"> / dev / mo</span>
              </div>
              <p class="text-xs text-slate-400">
                Turn alerts into autonomous 15s fixes. Unlimited repos & scans.
              </p>

              <div class="space-y-2 text-xs text-slate-200 pt-2">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400 font-bold">✔</span>
                  <span class="font-bold text-white">Autonomous Remediation (15s)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Safe Dual-Key Rotation (0 prod downtime)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>3-Tiered Git Zones (Auto-PR / .env staging)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Zero-Knowledge Team Dashboard</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Slack Block Kit & Discord incident cards</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>14-day free trial, cancel anytime</span>
                </div>
              </div>
            </div>

            <div class="pt-6 mt-6 border-t border-white/[0.08]">
              <button onclick="document.getElementById('nav-btn-dashboard').click()" class="btn-primary w-full justify-center text-xs">
                Start 14-Day Free Team Trial
              </button>
            </div>
          </div>

          <!-- Enterprise Tier -->
          <div class="bento-card p-6 sm:p-8 flex flex-col justify-between">
            <div class="space-y-4">
              <div class="badge-clean badge-tag-muted">SELF-HOSTED</div>
              <h3 class="text-xl font-bold text-white">Enterprise Tier</h3>
              <div class="text-3xl font-mono font-extrabold text-white mt-1">
                $2,000<span class="text-sm font-normal text-slate-400"> / year</span>
              </div>
              <p class="text-xs text-slate-400">
                Flat rate up to 50 developers ($3.33/dev/mo). Air-gapped compliance.
              </p>

              <div class="space-y-2 text-xs text-slate-300 pt-2">
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span class="text-white font-semibold">Everything in Pro plus:</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>100% On-Prem Docker & K8s deployment</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>SSO / SAML 2.0 (Okta, Azure AD, Google)</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>SOC 2 & ISO 27001 Cryptographic Hash Chain</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-emerald-400">✔</span>
                  <span>Dedicated Slack channel & 99.9% SLA</span>
                </div>
              </div>
            </div>

            <div class="pt-6 mt-6 border-t border-white/[0.08]">
              <button class="btn-glass w-full justify-center text-xs">
                Contact Enterprise Engineering
              </button>
            </div>
          </div>

        </div>

      </div>
    `;
  }

  bindEvents() {
    const slider = this.container.querySelector('#calc-seat-slider');
    const monthlyBtn = this.container.querySelector('#btn-billing-monthly');
    const annualBtn = this.container.querySelector('#btn-billing-annual');
    const presetBtns = this.container.querySelectorAll('.calc-preset-btn');

    if (slider) {
      slider.addEventListener('input', (e) => {
        this.seats = parseInt(e.target.value, 10);
        this.calculate();
      });
    }

    if (monthlyBtn) {
      monthlyBtn.addEventListener('click', () => {
        this.isAnnual = false;
        this.render();
        this.bindEvents();
        this.calculate();
      });
    }

    if (annualBtn) {
      annualBtn.addEventListener('click', () => {
        this.isAnnual = true;
        this.render();
        this.bindEvents();
        this.calculate();
      });
    }

    presetBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        this.seats = parseInt(btn.dataset.seats, 10);
        if (slider) slider.value = this.seats;
        this.calculate();
      });
    });
  }

  calculate() {
    const unitPrice = this.isAnnual ? 7 : 8;
    const monthlyTotal = this.seats * unitPrice;
    const hoursSaved = this.seats * 2.5;
    const valueRecovered = hoursSaved * 110;
    const roi = Math.round(((valueRecovered - monthlyTotal) / monthlyTotal) * 100);

    const seatEl = this.container.querySelector('#calc-seat-display');
    const costEl = this.container.querySelector('#calc-cost-display');
    const hoursEl = this.container.querySelector('#calc-hours-display');
    const valueEl = this.container.querySelector('#calc-value-display');
    const roiEl = this.container.querySelector('#calc-roi-display');
    const proPriceEl = this.container.querySelector('#card-price-pro');

    if (seatEl) seatEl.textContent = this.seats;
    if (costEl) costEl.textContent = `$${monthlyTotal}`;
    if (hoursEl) hoursEl.textContent = `${hoursSaved.toFixed(1)} hrs / mo`;
    if (valueEl) valueEl.textContent = `$${valueRecovered.toLocaleString()} / mo`;
    if (roiEl) roiEl.textContent = `${roi.toLocaleString()}%`;
    if (proPriceEl) proPriceEl.textContent = unitPrice;
  }
}
