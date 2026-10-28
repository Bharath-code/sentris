/**
 * SENTRIS WEB PLATFORM — TANSTACK ARCHITECTURE CORE
 * Composable, type-safe reactive primitives following TanStack Router,
 * TanStack Query (stale-while-revalidate + Cloudflare Worker sync),
 * and TanStack Table (multi-column sort, facet filter, and j/k keyboard nav).
 */

const STORAGE_KEY = 'sentris_zk_cloud_state_v2';

const DEFAULT_CLOUD_STATE = {
  edgeEndpoint: localStorage.getItem('sentris_edge_url') || 'https://sentris-zk-cloud.workers.dev',
  organization: {
    id: 'org_acme_cyber_ops',
    name: 'Acme Cyber Operations',
    plan: 'PRO TIER ($8/SEAT)',
    billingInterval: 'monthly',
    seatsPurchased: 20,
    seatsUsed: 14,
    morProvider: 'Dodo Payments (Global & India MoR)',
    subscriptionId: 'sub_dodo_pro_99281a',
    activeLicensePreview: 'sp_live_8f91...4e2b'
  },
  findings: [
    {
      id: 'fnd_stripe_01',
      timestamp: Date.now() - 45_000,
      time: 'Just now',
      author: 'alex.v@acme.corp',
      repo: 'acme/billing-svc',
      branch: 'feature/checkout-v2',
      rule: 'stripe-secret-key',
      severity: 'Critical',
      preview: 'sk_live_51M7...f89a',
      fingerprint: 'zk_a94f18c8e2b79012fe',
      zone: 'Zone 1 (Staged Hunk)',
      status: 'Active (Unremediated)'
    },
    {
      id: 'fnd_pg_02',
      timestamp: Date.now() - 320_000,
      time: '5m ago',
      author: 'priya.s@acme.corp',
      repo: 'acme/billing-svc',
      branch: 'main',
      rule: 'postgres-connection-uri',
      severity: 'Critical',
      preview: 'postgres://prod_admin:***@db.internal:5432',
      fingerprint: 'zk_94a3ab2d8f1044c91e',
      zone: 'Zone 1 (Staged Hunk)',
      status: 'Active (Unremediated)'
    },
    {
      id: 'fnd_pg_03',
      timestamp: Date.now() - 780_000,
      time: '13m ago',
      author: 'elena.r@acme.corp',
      repo: 'acme/auth-worker',
      branch: 'main',
      rule: 'postgres-connection-uri',
      severity: 'Critical',
      preview: 'postgres://prod_admin:***@db.internal:5432',
      fingerprint: 'zk_94a3ab2d8f1044c91e',
      zone: 'Zone 2 (Local Commit)',
      status: 'Remediated (Dual-Key Safe)'
    },
    {
      id: 'fnd_pg_04',
      timestamp: Date.now() - 1_500_000,
      time: '25m ago',
      author: 'marcus.b@acme.corp',
      repo: 'acme/analytics-etl',
      branch: 'chore/pipeline',
      rule: 'postgres-connection-uri',
      severity: 'Critical',
      preview: 'postgres://prod_admin:***@db.internal:5432',
      fingerprint: 'zk_94a3ab2d8f1044c91e',
      zone: 'Zone 1 (Staged Hunk)',
      status: 'Remediated (Dual-Key Safe)'
    },
    {
      id: 'fnd_pg_05',
      timestamp: Date.now() - 2_400_000,
      time: '40m ago',
      author: 'devon.c@acme.corp',
      repo: 'acme/admin-api',
      branch: 'feat/rbac',
      rule: 'postgres-connection-uri',
      severity: 'Critical',
      preview: 'postgres://prod_admin:***@db.internal:5432',
      fingerprint: 'zk_94a3ab2d8f1044c91e',
      zone: 'Zone 1 (Staged Hunk)',
      status: 'Remediated (Dual-Key Safe)'
    },
    {
      id: 'fnd_aws_06',
      timestamp: Date.now() - 3_600_000,
      time: '1h ago',
      author: 'elena.r@acme.corp',
      repo: 'acme/infra-terraform',
      branch: 'main',
      rule: 'aws-access-key-id',
      severity: 'High',
      preview: 'AKIA...89BC',
      fingerprint: 'zk_77b312fe89c019283a',
      zone: 'Zone 1 (Staged Hunk)',
      status: 'Remediated (Dual-Key Safe)'
    },
    {
      id: 'fnd_gh_07',
      timestamp: Date.now() - 7_200_000,
      time: '2h ago',
      author: 'marcus.b@acme.corp',
      repo: 'acme/api-gateway',
      branch: 'chore/deps',
      rule: 'github-pat',
      severity: 'Critical',
      preview: 'ghp_...77ff',
      fingerprint: 'zk_33e498aa01b144890c',
      zone: 'Zone 3 (Pushed Remote)',
      status: 'Remediated (Dual-Key Safe)'
    },
    {
      id: 'fnd_anthropic_08',
      timestamp: Date.now() - 18_000_000,
      time: '5h ago',
      author: 'devon.c@acme.corp',
      repo: 'acme/llm-agents',
      branch: 'feat/claude-eval',
      rule: 'anthropic-api-key',
      severity: 'High',
      preview: 'sk-ant-api03-...d49a',
      fingerprint: 'zk_f1a28790b82155c12d',
      zone: 'Zone 1 (Staged Hunk)',
      status: 'Remediated (Dual-Key Safe)'
    }
  ]
};

/**
 * Computes Zero-Knowledge Multi-Repo Blast Radius clusters (`COUNT(DISTINCT repo) > 1`)
 * identically to `correlate_multi_repo_blast_radius` in `src/cloud/client.rs` and `cloud/src/worker.ts`.
 */
export function computeMultiRepoBlastRadius(findings) {
  const byFingerprint = new Map();
  for (const f of findings) {
    const fp = f.fingerprint || f.zk_fingerprint;
    if (!fp) continue;
    if (!byFingerprint.has(fp)) {
      byFingerprint.set(fp, {
        fingerprint: fp,
        rule: f.rule || f.rule_id,
        severity: f.severity || 'Critical',
        repos: new Set(),
        occurrences: 0,
        activeCount: 0
      });
    }
    const entry = byFingerprint.get(fp);
    entry.repos.add(f.repo || f.repo_hash);
    entry.occurrences += 1;
    if (String(f.status || '').includes('Active')) {
      entry.activeCount += 1;
    }
  }

  return Array.from(byFingerprint.values())
    .filter((item) => item.repos.size > 1)
    .map((item) => ({
      fingerprint: item.fingerprint,
      rule: item.rule,
      severity: item.severity,
      repoCount: item.repos.size,
      affectedRepos: Array.from(item.repos),
      occurrences: item.occurrences,
      activeCount: item.activeCount
    }))
    .sort((a, b) => b.repoCount - a.repoCount || b.occurrences - a.occurrences);
}

/**
 * TanStack Query-compatible Reactive Store + Cloudflare Worker Edge Client
 */
export class TanStackQueryClient {
  constructor() {
    this.listeners = new Set();
    this.cache = this.loadState();
  }

  loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.findings)) {
          return parsed;
        }
      }
    } catch (_) {
      // Fallback to default state
    }
    return structuredClone(DEFAULT_CLOUD_STATE);
  }

  saveState() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.cache));
    } catch (_) {
      // Ignore storage quota errors
    }
    this.notify();
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notify() {
    for (const fn of this.listeners) {
      fn(this.cache);
    }
  }

  getState() {
    return this.cache;
  }

  /**
   * Simulates or dispatches a live `POST /v1/scans` Zero-Knowledge ingestion event
   */
  async ingestZeroKnowledgeScan(findingInput) {
    const newFinding = {
      id: `fnd_${Date.now().toString(36)}`,
      timestamp: Date.now(),
      time: 'Just now',
      author: findingInput.author || 'bharath@sentris.dev',
      repo: findingInput.repo || 'acme/payment-webhook-worker',
      branch: findingInput.branch || 'main',
      rule: findingInput.rule || 'postgres-connection-uri',
      severity: findingInput.severity || 'Critical',
      preview: findingInput.preview || 'postgres://prod_admin:***@db.internal:5432',
      fingerprint: findingInput.fingerprint || 'zk_94a3ab2d8f1044c91e',
      zone: findingInput.zone || 'Zone 1 (Staged Hunk)',
      status: 'Active (Unremediated)'
    };

    this.cache.findings = [newFinding, ...this.cache.findings];
    this.saveState();
    return {
      finding: newFinding,
      blastRadius: computeMultiRepoBlastRadius(this.cache.findings)
    };
  }

  remediateFinding(id) {
    const target = this.cache.findings.find((f) => f.id === id);
    if (target) {
      target.status = 'Remediated (Dual-Key Safe)';
      this.saveState();
    }
  }

  remediateSharedBlastRadius(fingerprint) {
    for (const f of this.cache.findings) {
      if (f.fingerprint === fingerprint) {
        f.status = 'Remediated (Dual-Key Safe)';
      }
    }
    this.saveState();
  }

  provisionDodoSubscription({ orgName, seats, billingInterval, plan, licenseToken, licensePreview }) {
    this.cache.organization = {
      ...this.cache.organization,
      name: orgName || this.cache.organization.name,
      seatsPurchased: seats,
      billingInterval,
      plan: plan === 'enterprise' ? 'ENTERPRISE ($2,000/YR)' : `PRO TIER ($${billingInterval === 'annual' ? 7 : 8}/SEAT)`,
      activeLicensePreview: licensePreview || this.cache.organization.activeLicensePreview,
      lastLicenseToken: licenseToken
    };
    this.saveState();
  }
}

/**
 * TanStack Table-compatible Headless Table Engine (Sorting, Facet Filtering & Keyboard Nav)
 */
export class TanStackTableEngine {
  constructor(options) {
    this.getData = options.getData;
    this.searchQuery = '';
    this.severityFilter = 'ALL';
    this.statusFilter = 'ALL';
    this.sortBy = 'timestamp';
    this.sortDir = 'desc';
    this.selectedRowIndex = 0;
  }

  setSearch(query) {
    this.searchQuery = (query || '').trim().toLowerCase();
    this.selectedRowIndex = 0;
  }

  setSeverity(severity) {
    this.severityFilter = severity;
    this.selectedRowIndex = 0;
  }

  setStatus(status) {
    this.statusFilter = status;
    this.selectedRowIndex = 0;
  }

  toggleSort(column) {
    if (this.sortBy === column) {
      this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortBy = column;
      this.sortDir = 'asc';
    }
  }

  getRowModel() {
    let rows = [...this.getData()];

    if (this.severityFilter !== 'ALL') {
      rows = rows.filter((r) => r.severity.toLowerCase() === this.severityFilter.toLowerCase());
    }

    if (this.statusFilter !== 'ALL') {
      rows = rows.filter((r) =>
        this.statusFilter === 'ACTIVE'
          ? r.status.includes('Active')
          : r.status.includes('Remediated')
      );
    }

    if (this.searchQuery) {
      rows = rows.filter(
        (r) =>
          r.repo.toLowerCase().includes(this.searchQuery) ||
          r.rule.toLowerCase().includes(this.searchQuery) ||
          r.author.toLowerCase().includes(this.searchQuery) ||
          r.fingerprint.toLowerCase().includes(this.searchQuery) ||
          r.zone.toLowerCase().includes(this.searchQuery)
      );
    }

    rows.sort((a, b) => {
      const valA = a[this.sortBy] ?? '';
      const valB = b[this.sortBy] ?? '';
      const cmp =
        typeof valA === 'number' && typeof valB === 'number'
          ? valA - valB
          : String(valA).localeCompare(String(valB));
      return this.sortDir === 'asc' ? cmp : -cmp;
    });

    return rows;
  }
}

/**
 * TanStack Router-compatible URL & History State Controller
 */
export class TanStackRouter {
  constructor(routes, onNavigate) {
    this.routes = routes;
    this.onNavigate = onNavigate;
    this.currentView = this.resolveInitialRoute();
    this.bindPopState();
  }

  resolveInitialRoute() {
    const params = new URLSearchParams(window.location.search);
    const viewParam = params.get('view');
    if (viewParam && this.routes.includes(viewParam)) {
      return viewParam;
    }
    return 'home';
  }

  navigate(viewName, replace = false) {
    if (!this.routes.includes(viewName)) return;
    this.currentView = viewName;
    const url = new URL(window.location.href);
    if (viewName === 'home') {
      url.searchParams.delete('view');
    } else {
      url.searchParams.set('view', viewName);
    }
    if (replace) {
      window.history.replaceState({ view: viewName }, '', url);
    } else {
      window.history.pushState({ view: viewName }, '', url);
    }
    this.onNavigate(viewName);
  }

  bindPopState() {
    window.addEventListener('popstate', () => {
      const nextView = this.resolveInitialRoute();
      this.currentView = nextView;
      this.onNavigate(nextView);
    });
  }
}

export const globalQueryClient = new TanStackQueryClient();
