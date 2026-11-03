# RepoGuard AI — Devpost Submission Package
**Hackathon**: Atlassian Codegeist 2026 ($120,000)  
**Submission URL**: https://codegeist2026.devpost.com  

---

## 1. Quick Form Fields

- **Project Title**: `RepoGuard AI — Zero-Trust Security Sentinel & MCP for Atlassian Cloud`
- **Elevator Pitch / Tagline** (under 200 chars):
  > Autonomous zero-trust security circuit-breaker & Model Context Protocol (MCP) server for Atlassian Cloud. Intercepts OWASP vulnerabilities and AI prompt injections with tamper-evident SHA-256 audits.
- **GitHub Repository**: https://github.com/amazing200guy1-a11y/repoguard-ai
- **Live Interactive Cockpit**: https://amazing200guy1-a11y.github.io/repoguard-ai/dashboard.html
- **Installed Atlassian Cloud Site**: `https://one-atlas-kyif.atlassian.net`
- **Forge App ID**: `ari:cloud:ecosystem::app/801b9100-b9f9-4f8b-9f2d-fd6b09b4d7aa`
- **Target Tracks**:
  - Main Track: Codegeist 2026
  - Best App with Atlassian MCP ($1,500)
  - Best Agents ($1,500)
  - Best Student Project (Usman Bamidele — Federal University of Agriculture, Abeokuta - FUNAAB, 100-Level Mathematics)

---

## 2. Devpost Story / Description (Copy & Paste)

### 💡 Inspiration
As AI agents (like Atlassian Rovo) increasingly read repositories, draft PRs, and automate deployments, software development teams face an unprecedented risk: **poisoned PRs, malicious prompt injection embedded in pull request diffs, and undetected credential leaks**. Traditional CI/CD security tools run asynchronously after commits are accepted. 

We built **RepoGuard AI** to give engineering and security teams a **fail-closed, zero-trust autonomous circuit breaker** that integrates natively into Atlassian Cloud through the **Model Context Protocol (MCP)** and **Atlassian Forge**. RepoGuard ensures that no unsafe code or adversarial prompt injection can slip past PR review or Rovo agent interactions.

### 🛡️ What It Does
RepoGuard AI acts as a 24/7 security sentinel across Jira, Confluence, and Bitbucket:

1. **Automated Vulnerability & Injection Interception**:
   - Detects 15 critical OWASP vulnerabilities (SQL Injection, Remote Code Execution, Path Traversal, SSRF, Hardcoded JWT/Stripe/AWS secrets, Prototype Pollution, Deserialization, etc.).
   - Intercepts adversarial AI prompt injections (system prompt leaks, ignore-instruction exploits, unauthorized agent bypasses) before Rovo or an engineer processes them.

2. **Fail-Closed Zero-Trust Circuit Breaker**:
   - Implements configurable strict policies (`Strict Zero-Trust`, `SOC2 Compliance`, `Balanced`).
   - If a critical severity vulnerability or prompt injection is detected, RepoGuard instantly blocks the pipeline and prevents merges (`FAIL_CLOSED`).

3. **Tamper-Evident SHA-256 Audit Chain**:
   - Every scan result, file diff hash, and policy evaluation is sealed into a cryptographically linked SHA-256 block ledger (`prevHash`, `payloadHash`, `timestamp`).
   - Any tampering or modification invalidates the chain integrity immediately, providing institutional SOC2 and ISO27001 auditability.

4. **Native Atlassian MCP Server**:
   - Exposes 4 standardized JSON-RPC 2.0 tools for Atlassian Rovo and AI clients:
     - `repoguard_scan_code`
     - `repoguard_evaluate_policy`
     - `repoguard_seal_audit_block`
     - `repoguard_verify_chain`

### ⚙️ How We Built It
- **Atlassian Forge Serverless Runtime**: Deployed directly on Atlassian Cloud (`nodejs22.x` runtime) with scoped manifest declarations for Jira and Confluence.
- **Model Context Protocol (MCP)**: Custom JSON-RPC 2.0 protocol engine adhering to Model Context Protocol specification for instant AI agent tool-calling.
- **Zero-Dependency Security Core**: Written in standard, high-performance Node.js using native `node:crypto` for cryptographic SHA-256 hashing.
- **Interactive Aerospace Titanium Dashboard**: A real-time telemetry cockpit built with high-contrast titanium design, interactive PR scanner, live MCP tool explorer, and SHA-256 cryptographic audit chain verifier.

### 🧪 Test Suite & Verification (100% Pass)
RepoGuard AI includes a 21-test automated suite covering all engine modules:
- **Scanner Tests**: SQLi detection, AWS key interception, Prompt Injection rejection, clean code acceptance.
- **Circuit Breaker Tests**: Strict Zero-Trust policy enforcement, fail-closed thresholds, clean PR passing.
- **Audit Chain Tests**: Block genesis, SHA-256 cryptographic linkage, tamper detection, multi-block verification.
- **MCP Server Tests**: JSON-RPC initialize handshake, tools listing, live scan tool execution, live audit sealing.
- **Forge Handlers**: Event processing and payload resolution.

### 🏆 Accomplishments We're Proud Of
- **100% Test Pass Rate**: All 21 unit, integration, and security tests pass cleanly in under 40ms.
- **Native Atlassian Cloud Deployment**: Successfully deployed and installed directly onto Atlassian Cloud (`one-atlas-kyif.atlassian.net`) across both Jira and Confluence using Atlassian Forge CLI.
- **True Fail-Closed Guarantee**: Security is never opt-in; when doubt exists, RepoGuard rejects execution to protect customer infrastructure.

### 🔭 What's Next for RepoGuard AI
- Deep Bitbucket Pipelines CI/CD integration with automated PR status checks and bot comments.
- Custom enterprise policy builder allowing teams to author custom RegEx and AST security rules directly inside Confluence spaces.
- Real-time automated SOC2 compliance report generation directly exported to Confluence pages.

---

## 3. Video Walkthrough Script (2 Minutes)

- **0:00 - 0:25 (The Problem & Intro)**:
  > *"Hi everyone, I'm Usman Bamidele, a first-year Mathematics student at FUNAAB. In today's AI-native engineering world, agents like Atlassian Rovo are analyzing codebases and assisting developers. But what happens when an adversarial prompt injection or zero-day vulnerability is hidden inside a PR diff? Traditional scanners run late. That's why I built RepoGuard AI — an autonomous zero-trust security sentinel and Model Context Protocol server for Atlassian Cloud."*

- **0:25 - 0:55 (Live Scanner & Circuit Breaker)**:
  > *(Show live dashboard: https://amazing200guy1-a11y.github.io/repoguard-ai/dashboard.html)*  
  > *"Here is the RepoGuard AI telemetry cockpit. Let's load an adversarial pull request containing a hardcoded Stripe key, an SQL injection, and a prompt injection attack. When we trigger the zero-trust scan, the engine analyzes the diff in under 2 milliseconds, flags all 3 critical threats, and the circuit breaker trips to BLOCKED — strictly enforcing fail-closed zero-trust."*

- **0:55 - 1:25 (Atlassian MCP Server & Cloud Deployment)**:
  > *(Switch to Tab 2: MCP Protocol Explorer)*  
  > *"RepoGuard also implements the official Atlassian Model Context Protocol specification. Any AI agent or Rovo workflow can call `repoguard_scan_code` or `repoguard_evaluate_policy` via JSON-RPC 2.0 to verify code safety before generation or merge. Here you can see the MCP handshake and tool declarations running live."*

- **1:25 - 1:45 (Tamper-Evident SHA-256 Audit Chain)**:
  > *(Switch to Tab 3: SOC2 Audit Chain)*  
  > *"Every scan and decision is sealed into an immutable SHA-256 cryptographic chain. We can see block hashes, parent links, and verify the entire chain's integrity with one click. If any record is tampered with, the chain detects it instantly."*

- **1:45 - 2:00 (Outro)**:
  > *"RepoGuard AI is tested with 21 passing test suites, deployed via Forge CLI directly onto Atlassian Cloud, and ready to protect modern dev teams. Thank you!"*
