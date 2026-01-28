# Setting Up Security Agent Testing

## Quick Start

This repository contains vulnerable code designed to test the Web3 Security Agent.

### 1. Connect Repository to Security Agent

#### Option A: Using GitHub Actions

Add this workflow to your repository:

**File:** `.github/workflows/security-scan.yml`

```yaml
name: Security Scan with AI Agent

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger External Security Agent
        run: |
          # Call your security agent's webhook or API
          curl -X POST https://your-security-agent-url/scan \
            -H "Content-Type: application/json" \
            -d '{
              "repo": "${{ github.repository }}",
              "pr": ${{ github.event.pull_request.number }},
              "branch": "${{ github.event.pull_request.head.ref }}"
            }'