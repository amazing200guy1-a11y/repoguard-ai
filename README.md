# 🛡️ RepoGuard AI — Zero-Trust Security Sentinel

[![Tests](https://img.shields.io/badge/tests-21%2F21%20pass-10B981?style=for-the-badge&logo=checkmarx)](https://github.com/amazing200guy1-a11y/repoguard-ai)
[![Atlassian Forge](https://img.shields.io/badge/Atlassian-Forge%20Hosted-0052CC?style=for-the-badge&logo=atlassian)](https://codegeist2026.devpost.com/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-7DD3FC?style=for-the-badge)](https://modelcontextprotocol.io/)
[![Zero Deps](https://img.shields.io/badge/dependencies-0%20npm-orange?style=for-the-badge)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

> **Built for Atlassian Codegeist 2026 ($120,000 Global Hackathon)**  
> *Targeting: Main Track + Best App with Atlassian MCP ($1,500) + Best Agents ($1,500)*

---

## 🏛️ What is RepoGuard AI?

**RepoGuard AI** is an enterprise-grade, fail-closed security circuit-breaker and audit system built on **Atlassian Forge**. It sits between AI coding agents (such as **Atlassian Rovo**), developers, and production repositories across **Bitbucket**, **Jira**, and **Confluence**.

### The Problem It Solves:
As software teams adopt autonomous AI agents to write and commit code, enterprises face critical vulnerabilities:
1. **Adversarial Prompt Injection:** Attackers hide prompt overrides in code comments or PR descriptions to hijack Atlassian Rovo agents.
2. **OWASP Top 10 Regressions:** AI agents inadvertently commit SQL injection, dynamic `eval()`, OS command execution, or hardcoded cloud credentials.
3. **Audit Impossibility:** Traditional git logs lack cryptographic proof of pre-flight security evaluation required for SOC2 and ISO 27001 compliance.

---

## ⚡ Core Architecture & Moats

```
[ Developer / Rovo AI Agent ]
             │
             ▼
┌──────────────────────────────────────────────┐
│  Atlassian Forge Serverless Runtime          │
│                                              │
│  1. 15-Rule OWASP + Prompt Injection Scanner │  <-- <200ms linear pass
│  2. Fail-Closed Zero-Trust Circuit Breaker   │  <-- Blocks PR merge instantly
│  3. Model Context Protocol (MCP) Server      │  <-- Rovo agent toolcall safety
│  4. SHA-256 Tamper-Evident Forensic Chain    │  <-- Cryptographic SOC2 receipt
└──────────────────────────────────────────────┘
             │
      ┌──────┴──────┐
      ▼             ▼
[ Bitbucket PR ] [ Jira Issue Glance ]
```

1. **15 OWASP & Prompt Injection Rules (`src/scanner.js`):** Evaluates SQLi, eval, secrets, path traversal, ReDoS, and AI jailbreak attacks in a single linear pass.
2. **Fail-Closed Zero-Trust Circuit Breaker (`src/circuit_breaker.js`):** Automatically halts PR merges upon detecting critical findings or prompt overrides. Generates HMAC approval tickets for human-in-the-loop authorization.
3. **Official Atlassian MCP Server (`src/mcp_server.js`):** Exposes JSON-RPC 2.0 tools (`repoguard_scan_code`, `repoguard_seal_audit_block`, `repoguard_verify_chain`) directly to Atlassian Rovo.
4. **SHA-256 Tamper-Evident Audit Chain (`src/audit_chain.js`):** Continuous cryptographic hash chain from Genesis to Tip. Mathematically catches retroactive audit manipulation.
5. **Zero Supply-Chain Risk:** 100% Node.js standard library — zero external npm dependencies.

---

## 🧪 Automated Test Suite (21/21 Passing)

```bash
node test/repoguard.test.js
```

```text
══════════════════════════════════════════════════════════
  RepoGuard AI — Enterprise Security Verification Suite   
══════════════════════════════════════════════════════════

[1. STATIC SCANNER & OWASP INVARIANTS]
  ✔ detects SQL injection via string concatenation
  ✔ detects dynamic eval() execution
  ✔ detects hardcoded AWS and API secrets
  ✔ detects XSS via innerHTML sinks
  ✔ detects OS command injection via child_process
  ✔ passes completely clean production code

[2. ADVERSARIAL ROVO PROMPT INJECTION DEFENSE]
  ✔ detects "ignore previous instructions" jailbreak pattern
  ✔ detects Confluence / Jira data exfiltration attempts

[3. ZERO-TRUST CIRCUIT BREAKER & SOC2 POLICIES]
  ✔ trips circuit breaker and blocks PR merge on critical findings (fail-closed)
  ✔ permits merge when code meets SOC2 threshold
  ✔ records tamper-evident trip history in memory

[4. SHA-256 FORENSIC AUDIT CHAIN]
  ✔ initializes audit chain with genesis block and zero entries
  ✔ appends multiple audit blocks and maintains valid cryptographic link
  ✔ detects retroactive block tampering mathematically

[5. ATLASSIAN MCP (MODEL CONTEXT PROTOCOL) SERVER]
  ✔ exposes valid MCP tool definitions conforming to JSON-RPC spec
  ✔ executes repoguard_scan_code via MCP tools/call
  ✔ seals audit block via MCP repoguard_seal_audit_block

[6. ATLASSIAN FORGE SERVERLESS HANDLERS]
  ✔ executes Forge scanHandler successfully
  ✔ executes Forge auditHandler and seals cryptographic block
  ✔ executes Forge uiResolver for Bitbucket & Jira panels
  ✔ executes Forge prTriggerHandler on simulated Bitbucket PR event

══════════════════════════════════════════════════════════
  RESULT: 21/21 TESTS PASSING (100% SUCCESS)
══════════════════════════════════════════════════════════
```

---

## 🖥️ Live Interactive Dashboard
Open `dashboard.html` in any modern web browser to interact with the live telemetry cockpit, test scenarios against the circuit breaker, and observe the SHA-256 audit chain.

---

## 👤 Developer
**Usman Bamidele**  
Federal University of Agriculture, Abeokuta (FUNAAB)  
GitHub: [@amazing200guy1-a11y](https://github.com/amazing200guy1-a11y)
