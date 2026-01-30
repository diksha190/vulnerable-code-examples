# Vulnerable Code Examples 🚨

[![Security Scan](https://github.com/diksha190/vulnerable-code-examples/actions/workflows/security-scan.yml/badge.svg)](https://github.com/diksha190/vulnerable-code-examples/actions/workflows/security-scan.yml)

This repository contains intentionally vulnerable code samples for testing the **Web3 Security Agent**.

**⚠️ WARNING:** These are intentionally vulnerable! Never use this code in production.

## Automated Security Scanning

Every pull request is automatically scanned by our AI Security Agent:
- ✅ Detects 60+ vulnerability types
- ✅ Covers Ethereum, Solana, Web2, and DeFi
- ✅ Posts detailed findings as PR comments
- ✅ Includes severity levels and remediation advice

## Testing the Agent

To test the security agent locally:

```bash
# Clone this repo
git clone https://github.com/diksha190/vulnerable-code-examples.git
cd vulnerable-code-examples

# Clone the security agent
git clone https://github.com/security-ai-labs/security-ai-agent.git
cd security-ai-agent

# Install and run
pip install -r requirements.txt
python main.py
```

## Repository Structure

```
vulnerable-code-examples/
├── ethereum/
│   └── vulnerable_erc20.sol    # Intentionally vulnerable ERC20
├── web2/
│   └── (coming soon)
├── solana/
│   └── (coming soon)
└── defi/
    └── (coming soon)
```

## Known Vulnerabilities

### ethereum/vulnerable_erc20.sol
- 🚨 **CRITICAL**: Integer Overflow (Solidity 0.7.0)
- 🚨 **CRITICAL**: Reentrancy Attack
- 🚨 **CRITICAL**: Missing Access Control (mint, burn)
- ⚠️ **HIGH**: Unchecked Call Return
- ⚡ **MEDIUM**: Missing Zero Address Check
- ⚡ **MEDIUM**: Timestamp Dependency

## Contributing

Feel free to add more vulnerable examples to test the security agent!

1. Create a new branch
2. Add vulnerable code in appropriate directory
3. Open a PR
4. Watch the security agent find the vulnerabilities! 🔍
