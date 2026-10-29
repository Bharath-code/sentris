// Single source of truth for product facts shown on the site.
// Benchmark numbers are generated: `bench/run.sh` writes src/lib/benchmark.json. Never hand-type them.
import benchmarkData from './benchmark.json'

const sentrisRun = benchmarkData.results.find((r) => r.name === 'Sentris')
const slowestRun = benchmarkData.results[benchmarkData.results.length - 1]

export const formatMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`)

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
  benchmark: benchmarkData.results.map((r) => ({ name: r.name, ms: r.ms_median, ram: r.peak_rss_mb })),
  benchmarkMeta: {
    date: benchmarkData.date,
    files: benchmarkData.workload.files,
    mb: benchmarkData.workload.mb,
    repo: `django ${benchmarkData.workload.tag}`,
    cpu: benchmarkData.hardware.cpu,
    sentrisMs: sentrisRun?.ms_median ?? 0,
    sentrisRamMb: sentrisRun?.peak_rss_mb ?? 0,
    slowest: slowestRun.name,
    slowestRamMb: slowestRun.peak_rss_mb,
    compared: benchmarkData.results.map((r) => r.name),
  },
  backends: ['.env', 'Vault', 'AWS Secrets Manager', 'Doppler'],
} as const

export const loginCommand = (server: string, key = '<your-key>') =>
  `sentris auth login --token ${key} --server ${server}`
