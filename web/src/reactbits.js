/**
 * SENTRIS MOTION SYSTEM — REACT BITS & CRYPTOGRAPHIC INTERACTION ENGINE
 * Implements:
 *   1. DecryptedText: Cryptographic hex-scrambler (`0123456789abcdef_zk§`) on hover & entry
 *   2. SpotlightCard: Radial cursor-tracking specular glass lighting (`--mouse-x`, `--mouse-y`)
 *   3. DodoCheckoutModal: Live India/Global Merchant-of-Record checkout & CLI license provisioning
 */

import { globalQueryClient } from './tanstack-core.js';

const CIPHER_GLYPHS = '0123456789abcdef_zk§#%';

/**
 * 1. React Bits `DecryptedText` Scrambler
 * Scrambles text through cryptographic hex glyphs before locking into the target string.
 */
export function scrambleTextElement(el, durationMs = 520) {
  if (!el || el.dataset.scrambling === '1') return;
  const original = el.dataset.originalText || el.textContent.trim();
  el.dataset.originalText = original;
  el.dataset.scrambling = '1';

  const length = original.length;
  const start = performance.now();

  function tick(now) {
    const progress = Math.min(1, (now - start) / durationMs);
    const lockedCount = Math.floor(progress * length);
    let output = '';

    for (let i = 0; i < length; i++) {
      if (original[i] === ' ') {
        output += ' ';
      } else if (i < lockedCount) {
        output += original[i];
      } else {
        output += CIPHER_GLYPHS[Math.floor(Math.random() * CIPHER_GLYPHS.length)];
      }
    }

    el.textContent = output;

    if (progress < 1) {
      requestAnimationFrame(tick);
    } else {
      el.textContent = original;
      el.dataset.scrambling = '0';
    }
  }

  requestAnimationFrame(tick);
}

/**
 * Initializes `DecryptedText` on all elements with `[data-decrypt]`
 */
export function initDecryptedText(root = document) {
  const elements = root.querySelectorAll('[data-decrypt]');
  elements.forEach((el) => {
    if (el.dataset.decryptBound === '1') return;
    el.dataset.decryptBound = '1';
    el.dataset.originalText = el.textContent.trim();

    // Run once on initial mount
    scrambleTextElement(el, 620);

    // Re-scramble on hover
    el.addEventListener('mouseenter', () => {
      scrambleTextElement(el, 420);
    });
  });
}

/**
 * 2. React Bits `SpotlightCard` Radial Cursor-Tracking Specular Highlights
 */
export function initSpotlightCards(root = document) {
  const cards = root.querySelectorAll('.bento-card');
  cards.forEach((card) => {
    if (card.dataset.spotlightBound === '1') return;
    card.dataset.spotlightBound = '1';

    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    });
  });
}

/**
 * 3. Dodo Payments (Merchant of Record — India & Global SaaS) Interactive Checkout Modal
 */
export function openDodoCheckoutModal({
  plan = 'pro',
  seats = 15,
  isAnnual = false,
  onSuccess = null
} = {}) {
  const existing = document.getElementById('dodo-checkout-modal');
  if (existing) existing.remove();

  const unitUsd = plan === 'enterprise' ? 2000 : isAnnual ? 7 : 8;
  const totalUsd = plan === 'enterprise' ? 2000 : seats * unitUsd;
  const totalInr = Math.round(totalUsd * 84); // Localized INR equivalent via Dodo Payments UPI/Cards

  const modal = document.createElement('div');
  modal.id = 'dodo-checkout-modal';
  modal.className =
    'fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-md p-4';

  modal.innerHTML = `
    <div class="bento-card max-w-lg w-full p-6 sm:p-8 border border-[#FF5500]/40 bg-[#0B0D13] shadow-2xl space-y-6 relative animate-fade-in">
      <div class="flex items-start justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <div class="flex items-center gap-2">
            <span class="badge-clean badge-tag-cadmium">DODO PAYMENTS • MERCHANT OF RECORD</span>
            <span class="badge-clean badge-tag-emerald">PCI-DSS LEVEL 1</span>
          </div>
          <h3 class="text-xl font-bold text-white mt-2">
            ${plan === 'enterprise' ? 'Sentris Enterprise Self-Hosted' : `Sentris Commercial Pro (${seats} Developer Seats)`}
          </h3>
          <p class="text-xs text-slate-400 mt-0.5">
            Global tax/GST/VAT compliance handled automatically via Dodo Payments. Supports Cards, Apple Pay, and India UPI.
          </p>
        </div>
        <button id="dodo-modal-close" class="text-slate-400 hover:text-white text-sm font-mono px-2 py-1 rounded bg-white/5">✕</button>
      </div>

      <div class="space-y-4">
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-[11px] font-mono text-slate-400 uppercase mb-1">Organization Name</label>
            <input id="dodo-input-org" type="text" value="Acme Cyber Operations" class="w-full px-3 py-2 rounded-lg bg-[#121621] border border-white/10 text-xs text-white font-sans focus:outline-none focus:border-[#FF5500]" />
          </div>
          <div>
            <label class="block text-[11px] font-mono text-slate-400 uppercase mb-1">Workstation Admin Email</label>
            <input id="dodo-input-email" type="email" value="founder@acme.dev" class="w-full px-3 py-2 rounded-lg bg-[#121621] border border-white/10 text-xs text-white font-mono focus:outline-none focus:border-[#FF5500]" />
          </div>
        </div>

        <div class="p-4 rounded-xl bg-[#10131C] border border-white/10 space-y-2.5 text-xs">
          <div class="flex justify-between items-center">
            <span class="text-slate-400">Plan & Billing Cadence:</span>
            <span class="font-mono font-semibold text-white">${plan === 'enterprise' ? 'Enterprise Annual Flat' : isAnnual ? 'Pro Annual ($7/seat/mo)' : 'Pro Monthly ($8/seat/mo)'}</span>
          </div>
          <div class="flex justify-between items-center">
            <span class="text-slate-400">Active Developer Seats:</span>
            <span class="font-mono font-semibold text-[#FF8844]">${plan === 'enterprise' ? 'Up to 50 Seats' : `${seats} Seats`}</span>
          </div>
          <div class="flex justify-between items-center pt-2 border-t border-white/10">
            <span class="text-slate-300 font-semibold">Total Due After 14-Day Trial:</span>
            <div class="text-right">
              <span class="text-lg font-mono font-extrabold text-white">$${totalUsd.toLocaleString()} USD</span>
              <div class="text-[10px] font-mono text-emerald-400">≈ ₹${totalInr.toLocaleString()} INR (UPI / International Card Ready)</div>
            </div>
          </div>
        </div>

        <div id="dodo-provision-result" class="hidden p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2">
          <div class="text-xs font-bold text-emerald-300 flex items-center gap-2">
            <span>✔ Dodo Payments Subscription Active • Zero-Knowledge Token Minted</span>
          </div>
          <div class="text-[11px] text-slate-300">
            Run this command in your terminal to unlock <code class="text-white font-mono">sentris fix --safe-rotate</code> and team blast-radius sync:
          </div>
          <div class="p-2.5 rounded bg-[#07090D] border border-white/10 font-mono text-[11px] text-amber-300 select-all" id="dodo-cli-cmd"></div>
        </div>
      </div>

      <div class="flex items-center justify-between gap-3 pt-2">
        <a
          href="https://checkout.dodopayments.com/buy/pdt_sentris_pro_seat_8usd?quantity=${seats}"
          target="_blank"
          rel="noopener noreferrer"
          class="btn-glass text-xs py-2.5 px-4"
        >
          Open Hosted Dodo Checkout ↗
        </a>
        <button id="dodo-confirm-btn" class="btn-primary text-xs py-2.5 px-5 font-mono">
          Activate 14-Day Trial & Mint CLI Token →
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  const closeBtn = modal.querySelector('#dodo-modal-close');
  closeBtn.addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.remove();
  });

  const confirmBtn = modal.querySelector('#dodo-confirm-btn');
  confirmBtn.addEventListener('click', () => {
    const orgName = modal.querySelector('#dodo-input-org').value.trim() || 'Acme Cyber Operations';
    const randHex = Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const rawToken = `sp_live_${randHex}`;
    const preview = `sp_live_${randHex.slice(0, 4)}...${randHex.slice(-4)}`;

    globalQueryClient.provisionDodoSubscription({
      orgName,
      seats: plan === 'enterprise' ? 50 : seats,
      billingInterval: isAnnual ? 'annual' : 'monthly',
      plan,
      licenseToken: rawToken,
      licensePreview: preview
    });

    const resultBox = modal.querySelector('#dodo-provision-result');
    const cmdBox = modal.querySelector('#dodo-cli-cmd');
    resultBox.classList.remove('hidden');
    cmdBox.textContent = `sentris auth login --token ${rawToken}`;
    confirmBtn.textContent = '✔ Provisioned in Team Console';
    confirmBtn.classList.add('bg-emerald-600');

    if (typeof onSuccess === 'function') {
      onSuccess({ rawToken, preview, seats });
    }
  });
}
