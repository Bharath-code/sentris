/**
 * SENTRIS PRO — Master Web Application Controller (Awwwards Edition)
 * Integrates:
 *   1. TanStack Router & Query Client (`tanstack-core.js`)
 *   2. React Bits Motion (`DecryptedText`, `SpotlightCard`, `DodoCheckoutModal` in `reactbits.js`)
 *   3. Three.js 3D Zero-Knowledge Hash Vault (`three-reactor.js`)
 *   4. Interactive 15s Autonomous Remediation Terminal (`terminal-sim.js`)
 *   5. Interactive $8/Seat Pro Pricing & Dodo Payments MoR Checkout (`pricing.js`)
 *   6. Live Zero-Knowledge Team SaaS Dashboard (`dashboard.js`)
 *   7. 12-Scenario Edge-Case Stress Lab (`stress-tests.js`)
 */

import { ThreeHashReactor } from './three-reactor.js';
import { TerminalSimulator } from './terminal-sim.js';
import { PricingCalculator } from './pricing.js';
import { TeamDashboard } from './dashboard.js';
import { StressTestHarness } from './stress-tests.js';
import { MotionChoreographer } from './gsap-motion.js';
import { TanStackRouter } from './tanstack-core.js';
import {
  initDecryptedText,
  initSpotlightCards,
  openDodoCheckoutModal
} from './reactbits.js';

class SentrisApp {
  constructor() {
    this.reactor = null;
    this.terminal = null;
    this.pricing = null;
    this.dashboard = null;
    this.stressLab = null;
    this.motion = null;
    this.router = null;

    this.init();
  }

  init() {
    if (window.lucide) {
      window.lucide.createIcons();
    }

    // 1. Initialize 3D WebGL Zero-Knowledge Hash Reactor
    const canvas = document.getElementById('three-reactor-canvas');
    if (canvas) {
      this.reactor = new ThreeHashReactor(canvas);
    }

    // 2. Initialize Interactive Hero Remediation Terminal
    const termBody = document.getElementById('hero-terminal-body');
    if (termBody) {
      this.terminal = new TerminalSimulator(termBody, () => {
        if (this.reactor) {
          this.reactor.triggerScanPulse();
        }
      });
    }

    // 3. Initialize $8/Seat Pro Pricing & Dodo Payments MoR Calculator
    const pricingMount = document.getElementById('pricing-calculator-mount');
    if (pricingMount) {
      this.pricing = new PricingCalculator(pricingMount);
    }

    // 4. Initialize Commercial Team SaaS Console
    const dashMount = document.getElementById('team-dashboard-mount');
    if (dashMount) {
      this.dashboard = new TeamDashboard(dashMount);
    }

    // 5. Initialize 12-Scenario Edge-Case Stress Lab
    const stressMount = document.getElementById('stress-lab-mount');
    if (stressMount) {
      this.stressLab = new StressTestHarness(stressMount);
    }

    // 6. Initialize GSAP Mechanical Choreography + React Bits Spotlight & DecryptedText
    this.motion = new MotionChoreographer();
    initSpotlightCards(document);
    initDecryptedText(document);

    // 7. Initialize TanStack Router & Global Keyboard Shortcuts
    this.router = new TanStackRouter(
      ['home', 'dashboard', 'pricing', 'stress-lab'],
      (viewName) => this.applyView(viewName)
    );
    this.bindNavigation();
    this.applyView(this.router.currentView);
  }

  bindNavigation() {
    const navButtons = [
      { id: 'nav-btn-home', view: 'home' },
      { id: 'nav-btn-dashboard', view: 'dashboard' },
      { id: 'nav-btn-pricing', view: 'pricing' },
      { id: 'nav-btn-stress', view: 'stress-lab' }
    ];

    navButtons.forEach((b) => {
      const el = document.getElementById(b.id);
      if (el) {
        el.addEventListener('click', () => this.router.navigate(b.view));
      }
    });

    const dodoCtaBtn = document.getElementById('hero-dodo-trial-btn');
    if (dodoCtaBtn) {
      dodoCtaBtn.addEventListener('click', () => {
        openDodoCheckoutModal({ plan: 'pro', seats: 15, isAnnual: false });
      });
    }

    const triggerScanBtn = document.getElementById('hero-trigger-scan-btn');
    if (triggerScanBtn) {
      triggerScanBtn.addEventListener('click', () => {
        if (this.reactor) this.reactor.triggerScanPulse();
        if (this.terminal) this.terminal.runRemediationCycle();
      });
    }

    const pulseBtn = document.getElementById('reactor-pulse-btn');
    if (pulseBtn) {
      pulseBtn.addEventListener('click', () => {
        if (this.reactor) this.reactor.triggerScanPulse();
      });
    }

    // Global Keyboard Shortcuts (1-4 views, Cmd/Ctrl+K quick checkout)
    window.addEventListener('keydown', (e) => {
      const tag = (e.target && e.target.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        openDodoCheckoutModal({ plan: 'pro', seats: 15, isAnnual: false });
      }
    });
  }

  applyView(viewName) {
    const views = ['home', 'dashboard', 'pricing', 'stress-lab'];
    views.forEach((v) => {
      const section = document.getElementById(`view-${v}`);
      if (section) {
        if (v === viewName) {
          section.classList.remove('hidden');
        } else {
          section.classList.add('hidden');
        }
      }
    });

    const navMap = {
      home: 'nav-btn-home',
      dashboard: 'nav-btn-dashboard',
      pricing: 'nav-btn-pricing',
      'stress-lab': 'nav-btn-stress'
    };

    Object.entries(navMap).forEach(([k, btnId]) => {
      const btn = document.getElementById(btnId);
      if (btn) {
        if (k === viewName) {
          btn.classList.add('bg-white/10', 'text-white');
          btn.classList.remove('text-slate-400');
        } else {
          btn.classList.remove('bg-white/10', 'text-white');
          btn.classList.add('text-slate-400');
        }
      }
    });

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.sentrisApp = new SentrisApp();
});
