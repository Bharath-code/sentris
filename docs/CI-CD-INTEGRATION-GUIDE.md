# Enterprise CI/CD Integration & Multi-Cloud Ecosystem Guide

This guide details how to integrate **Sentris** into modern enterprise CI/CD pipelines and container ecosystems. Sentris is architected in Rust for ultra-fast, memory-safe execution (>10,000 files/sec), native zero-egress offline operation, and seamless drop-in compatibility across all major DevOps platforms.

---

## 1. Quick Platform Matrix

| Platform | Recommended Format | Native Artifact / Feature | Fail-on-Secret Support |
| :--- | :--- | :--- | :---: |
| **GitLab CI/CD** | `--format gitlab` | `gl-secret-detection-report.json` (Schema v15.0.7) | ✅ |
| **GitHub Actions** | `--format github` / `sarif` | Inline PR Annotations & Code Scanning Tab | ✅ |
| **Azure DevOps** | `--format sarif` | Advanced Security & Build Artifacts | ✅ |
| **Bitbucket Pipelines**| `--format text` / `json` | Pipeline Failure Logs & Webhook Incident Cards | ✅ |
| **Docker / K8s** | Multi-Arch Alpine/Scratch | Non-root UID 10001, sub-15MB container footprint | ✅ |

---

## 2. Docker Container Deployment

Sentris provides official multi-architecture Docker container images (`linux/amd64`, `linux/arm64`) optimized for minimal surface area and high security:

* **Base:** Minimal Alpine Linux 3.20 (<15MB footprint)
* **Security:** Runs as unprivileged non-root user `sentris` (`UID:GID 10001:10001`)
* **Standard Entrypoint:** `/usr/local/bin/sentris`
* **Default CMD:** `["scan", "."]`

### Running Locally with Docker
```bash
# Scan current directory mounted as read-only volume
docker run --rm -v "$(pwd):/workspace:ro" ghcr.io/sentris-security/sentris:latest scan .

# Scan git commit history
docker run --rm -v "$(pwd):/workspace:ro" ghcr.io/sentris-security/sentris:latest scan . --git-history

# Zero-egress air-gapped container scan
docker run --rm --network none -v "$(pwd):/workspace:ro" ghcr.io/sentris-security/sentris:latest scan . --offline
```

---

## 3. GitLab CI/CD Integration

Sentris natively outputs the official GitLab Secret Detection Report JSON format conforming to **GitLab Schema v15.0.7**. Findings automatically populate the GitLab Merge Request Security Widget and Vulnerability Report in GitLab Ultimate and Premium.

### `.gitlab-ci.yml`
```yaml
stages:
  - test

sentris_secret_detection:
  stage: test
  image:
    name: ghcr.io/sentris-security/sentris:latest
    entrypoint: [""]
  variables:
    GIT_DEPTH: "50"
  script:
    - sentris scan . --format gitlab --fail-on-secret > gl-secret-detection-report.json
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
    paths:
      - gl-secret-detection-report.json
    expire_in: 1 week
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## 4. GitHub Actions Integration

Sentris integrates with GitHub Actions using two complementary methods:
1. **`--format github`**: Emits GitHub workflow commands (`::error file=...,line=...`) that render instant inline error annotations on pull request diffs.
2. **`--format sarif`**: Emits SARIF v2.1.0 uploaded to GitHub Code Scanning (Security tab).

### `.github/workflows/sentris.yml`
```yaml
name: Sentris Secret Detection

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    name: Sentris Secret Scanner
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Cache Sentris
        id: cache-sentris
        uses: actions/cache@v4
        with:
          path: ~/.sentris/bin
          key: ${{ runner.os }}-sentris-v0.1.0

      - name: Install Sentris CLI
        if: steps.cache-sentris.outputs.cache-hit != 'true'
        run: curl -fsSL https://sentris.dev/install.sh | bash

      - name: Add to PATH
        run: echo "$HOME/.sentris/bin" >> $GITHUB_PATH

      - name: Scan with PR Annotations
        run: sentris scan . --format github --fail-on-secret

      - name: Generate SARIF Security Report
        if: always()
        run: sentris scan . --format sarif > sentris.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentris.sarif
          category: sentris-secrets
```

---

## 5. Bitbucket Pipelines Integration

Bitbucket Pipelines executes Sentris inside the hardened Docker container, failing pull requests when unmasked secrets are committed.

### `bitbucket-pipelines.yml`
```yaml
image: ghcr.io/sentris-security/sentris:latest

pipelines:
  default:
    - step:
        name: Sentris Secret Scanning
        script:
          - sentris scan . --fail-on-secret
  pull-requests:
    '**':
      - step:
          name: Scan Pull Request
          script:
            # Enforce baseline suppression to avoid blocking on legacy credentials
            - sentris scan . --fail-on-secret --baseline .sentris-baseline.json
```

---

## 6. Azure DevOps Pipelines Integration

Export findings directly to SARIF v2.1.0 and publish into Azure DevOps Advanced Security and Build Artifacts.

### `azure-pipelines.yml`
```yaml
trigger:
  branches:
    include:
      - main
      - master
pr:
  branches:
    include:
      - '*'

pool:
  vmImage: 'ubuntu-latest'

steps:
  - checkout: self
    fetchDepth: 50

  - script: |
      curl -fsSL https://sentris.dev/install.sh | bash
      echo "##vso[task.prependpath]$HOME/.sentris/bin"
    displayName: 'Install Sentris CLI'

  - script: |
      sentris scan . --format sarif --fail-on-secret > sentris-scan.sarif
    displayName: 'Run Secret Scan'

  - task: PublishBuildArtifacts@1
    displayName: 'Publish SARIF Report'
    inputs:
      PathtoPublish: 'sentris-scan.sarif'
      ArtifactName: 'CodeAnalysisLogs'
    condition: always()
```

---

## 7. Gitleaks Migration Engine

Migrate legacy `.gitleaks.toml` rules and path allowlists into native `.sentris.toml` configuration in seconds without manual rewrite:

```bash
# Preview and execute migration
sentris migrate-gitleaks .gitleaks.toml --output .sentris.toml

# Overwrite existing destination file
sentris migrate-gitleaks .gitleaks.toml --output .sentris.toml --force
```

### Migration Mapping:
* `[[rules]] id` ➔ `rule_id`
* `[[rules]] description` ➔ `name` & `description`
* `[[rules]] regex` ➔ `pattern`
* `[[rules]] entropy` ➔ `min_entropy` (default: 3.0)
* `[allowlist] paths` ➔ `scanner.ignore_paths`
* Automatic severity inference based on rule identifiers (`critical`, `high`, `medium`, `low`).

---

## 8. Enterprise Baseline & Graceful Rollout

When deploying Sentris to a large existing codebase with pre-existing credentials, use the **Baseline Engine** to avoid blocking active deployments:

```bash
# 1. Snapshot all existing legacy secrets into a baseline file
sentris baseline record . --output .sentris-baseline.json

# 2. In CI/CD, scan with baseline suppression
# Only newly introduced secrets will cause a build failure
sentris scan . --baseline .sentris-baseline.json --fail-on-secret
```

---

## 9. Real-Time Webhook Incident Alerts

Dispatch incident alert cards to Slack or Discord webhooks during CI/CD execution:

```bash
sentris scan . --webhook "https://hooks.slack.com/services/T00/B00/X00"
```

In air-gapped environments or restricted egress environments, pass `--offline` to ensure zero network calls are attempted.
