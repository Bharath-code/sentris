/**
 * SENTRIS PRO — Mechanical GSAP Motion Choreography
 * Adheres strictly to the Anti-Slop Motion Grammar:
 * Physical spring equations, snap & settle curves, and precision number tickers.
 */

export class MotionChoreographer {
  constructor() {
    this.gsap = window.gsap || null;
    if (this.gsap) {
      this.init();
    }
  }

  init() {
    this.animateHeroElements();
    this.bindMagneticButtons();
    this.initNumberTickers();
  }

  animateHeroElements() {
    if (!this.gsap) return;

    this.gsap.from('.hero-stagger', {
      duration: 0.65,
      y: 24,
      opacity: 0,
      stagger: 0.08,
      ease: 'expo.out',
      clearProps: 'all'
    });

    this.gsap.from('.hero-card-stagger', {
      duration: 0.8,
      scale: 0.96,
      opacity: 0,
      stagger: 0.12,
      ease: 'power3.out',
      delay: 0.2,
      clearProps: 'all'
    });
  }

  bindMagneticButtons() {
    const buttons = document.querySelectorAll('.btn-primary, .btn-glass, .btn-voltage, .btn-secondary');
    buttons.forEach(btn => {
      btn.addEventListener('mousemove', (e) => {
        if (!this.gsap) return;
        const rect = btn.getBoundingClientRect();
        const x = (e.clientX - rect.left - rect.width / 2) * 0.25;
        const y = (e.clientY - rect.top - rect.height / 2) * 0.25;
        this.gsap.to(btn, {
          x,
          y,
          duration: 0.2,
          ease: 'power2.out'
        });
      });

      btn.addEventListener('mouseleave', () => {
        if (!this.gsap) return;
        this.gsap.to(btn, {
          x: 0,
          y: 0,
          duration: 0.35,
          ease: 'elastic.out(1, 0.4)'
        });
      });
    });
  }

  initNumberTickers() {
    if (!this.gsap) return;

    const tickers = document.querySelectorAll('.metric-ticker');
    tickers.forEach(el => {
      const targetVal = parseFloat(el.dataset.value) || 0;
      const prefix = el.dataset.prefix || '';
      const suffix = el.dataset.suffix || '';
      const isInteger = !el.dataset.value.includes('.');

      const obj = { val: 0 };
      this.gsap.to(obj, {
        val: targetVal,
        duration: 1.4,
        ease: 'power3.out',
        onUpdate: () => {
          el.textContent = `${prefix}${isInteger ? Math.round(obj.val) : obj.val.toFixed(1)}${suffix}`;
        }
      });
    });
  }
}
