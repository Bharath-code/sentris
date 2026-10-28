// Single source of truth for product facts shown on the site.
// Numbers come from docs/BENCHMARKS-AND-ARCHITECTURE.md; keep them in sync when the benchmark reruns.
export const site = {
  name: 'Sentris',
  // TODO: switch to `cargo install sentris` / brew once a public channel ships (crate + tap 404 today)
  install: 'cargo install --git https://github.com/Bharath-code/sentris',
  github: 'https://github.com/Bharath-code/sentris',
  // TODO: swap for a team address once the domain is bought
  contact: 'mailto:kumarbharath63@gmail.com?subject=Sentris%20self-hosted',
  priceMonthly: 8,
  priceAnnual: 7,
  enterpriseYear: 2000,
  benchmark: [
    { name: 'Sentris', ms: 18, ram: 14 },
    { name: 'Kingfisher', ms: 42, ram: 48 },
    { name: 'Gitleaks', ms: 195, ram: 65 },
    { name: 'TruffleHog', ms: 640, ram: 210 },
  ],
  backends: ['.env', 'Vault', 'AWS Secrets Manager', 'Doppler', '1Password', 'Infisical'],
} as const

export const loginCommand = (server: string, key = '<your-key>') =>
  `sentris auth login --token ${key} --server ${server}`
