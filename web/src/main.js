/**
 * SENTRIS PRO — Main Web Platform Application Controller
 * Seamlessly integrates Product Marketing Page, Live SaaS Team Dashboard,
 * 3D Three.js Reactor, GSAP Motion, and Design System Inspector.
 */

import { ThreeHashReactor } from './three-reactor.js';
import { TerminalSimulator } from './terminal-sim.js';
import { PricingCalculator } from './pricing.js';
import { TeamDashboard } from './dashboard.js';
import { StressTestsVisualizer } from './stress-tests.js';
import { MotionChoreographer } from './gsap-motion.js';

class SentrisApp {
  constructor() {
    this.currentView = 'marketing'; // 'marketing' | 'dashboard' | 'design-system'
    this.reactor = null;
    this.terminal = null;
    this.pricing = null;
    this.dashboard = null;
    this.stressTests = null;
    this.motion = null;

    document.addEventListener('DOMContentLoaded', () => this.init());
  }

  init() {
    this.bindNavigation();
    this.initComponents();
    this.bindCopyCommands();
  }

  initComponents() {
    // 1. Three.js 3D Reactor
    const canvas = document.getElementById('reactor-canvas');
    if (canvas && window.THREE) {
      this.reactor = new ThreeHashReactor(canvas);
    }

    // 2. Terminal Simulator
    const termContainer = document.getElementById('terminal-container');
    if (termContainer) {
      this.terminal = new TerminalSimulator(termContainer, this.reactor);
    }

    // 3. Stress Tests Visualizer
    const stressContainer = document.getElementById('stress-tests-container');
    if (stressContainer) {
      this.stressTests = new StressTestsVisualizer(stressContainer);
    }

    // 4. Pricing Calculator
    const pricingContainer = document.getElementById('pricing-container');
    if (pricingContainer) {
      this.pricing = new PricingCalculator(pricingContainer);
    }

    // 5. Team SaaS Dashboard
    const dashContainer = document.getElementById('dashboard-container');
    if (dashContainer) {
      this.dashboard = new TeamDashboard(dashContainer);
    }

    // 6. GSAP Motion
    this.motion = new MotionChoreographer();
  }

  bindNavigation() {
    const navMarketing = document.getElementById('nav-btn-marketing');
    const navDashboard = document.getElementById('nav-btn-dashboard');
    const navDesign = document.getElementById('nav-btn-design');

    const marketingView = document.getElementById('view-marketing');
    const dashboardView = document.getElementById('view-dashboard');
    const designView = document.getElementById('view-design-system');

    const updateView = (view) => {
      this.currentView = view;
      if (marketingView) marketingView.classList.toggle('hidden', view !== 'marketing');
      if (dashboardView) dashboardView.classList.toggle('hidden', view !== 'dashboard');
      if (designView) designView.classList.toggle('hidden', view !== 'design-system');

      // Update button highlights
      if (navMarketing) {
        navMarketing.className = view === 'marketing'
          ? 'text-xs font-semibold px-3 py-1.5 rounded-lg bg-[var(--bg-surface-3)] text-white border border-[var(--border-subtle)]'
          : 'text-xs font-semibold px-3 py-1.5 rounded-lg text-[var(--text-secondary)] hover:text-white';
      }
      if (navDashboard) {
        navDashboard.className = view === 'dashboard'
          ? 'text-xs font-semibold px-3 py-1.5 rounded-lg bg-[#FF5500] text-white shadow-sm'
          : 'text-xs font-semibold px-3 py-1.5 rounded-lg text-[var(--text-secondary)] hover:text-white';
      }
      if (navDesign) {
        navDesign.className = view === 'design-system'
          ? 'text-xs font-semibold px-3 py-1.5 rounded-lg bg-[var(--bg-surface-3)] text-white border border-[var(--border-subtle)]'
          : 'text-xs font-semibold px-3 py-1.5 rounded-lg text-[var(--text-secondary)] hover:text-white';
      }

      window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    if (navMarketing) navMarketing.addEventListener('click', () => updateView('marketing'));
    if (navDashboard) navDashboard.addEventListener('click', () => updateView('dashboard'));
    if (navDesign) navDesign.addEventListener('click', () => updateView('design-system'));

    // CTAs across page linking to dashboard
    document.querySelectorAll('.cta-launch-dashboard').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        updateView('dashboard');
      });
    });
  }

  bindCopyCommands() {
    const copyBtns = document.querySelectorAll('.copy-cmd-btn');
    copyBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const text = btn.dataset.cmd || 'curl -fsSL https://sentris.dev/install.sh | sh';
        navigator.clipboard.writeText(text).then(() => {
          const original = btn.innerHTML;
          btn.innerHTML = '✔ Copied!';
          setTimeout(() => { btn.innerHTML = original; }, 1800);
        });
      });
    });
  }
}

new SentrisApp();
