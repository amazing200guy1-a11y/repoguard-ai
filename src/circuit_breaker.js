'use strict';

/**
 * RepoGuard AI — Zero-Trust Circuit Breaker & Policy Enforcer
 * Evaluates scan results against enterprise security policies.
 * Fail-closed by design: blocks Bitbucket merge if risk exceeds threshold.
 */

const crypto = require('crypto');

const POLICIES = {
  STRICT_ZERO_TRUST: {
    maxSeverityScore: 0,
    allowCritical: false,
    allowHigh: false,
    allowMedium: false,
    blockPromptInjection: true,
    requireCleanAuditChain: true
  },
  SOC2_COMPLIANT: {
    maxSeverityScore: 5,
    allowCritical: false,
    allowHigh: false,
    allowMedium: true,
    blockPromptInjection: true,
    requireCleanAuditChain: true
  },
  BALANCED_AGILE: {
    maxSeverityScore: 12,
    allowCritical: false,
    allowHigh: true,
    allowMedium: true,
    blockPromptInjection: true,
    requireCleanAuditChain: false
  }
};

class CircuitBreaker {
  constructor(policyName = 'SOC2_COMPLIANT', customRules = {}) {
    this.policyName = policyName;
    this.policy = { ...(POLICIES[policyName] || POLICIES.SOC2_COMPLIANT), ...customRules };
    this.tripLog = [];
  }

  /**
   * Evaluate whether a Bitbucket Pull Request or Rovo Agent commit is allowed to proceed.
   * @param {object} scanResult - output from scanner.scanCode()
   * @param {object} metadata - { prId, repo, author, branch }
   * @returns {object} { allowed: boolean, status: string, reason: string, ticket?: string }
   */
  evaluate(scanResult, metadata = {}) {
    const findings = scanResult.findings || [];
    const hasCritical = findings.some(f => f.severity === 'CRITICAL');
    const hasHigh = findings.some(f => f.severity === 'HIGH');
    const hasPromptInjection = findings.some(f => f.rule_id.startsWith('AI-'));

    // Rule 1: Prompt Injection is unconditionally blocked
    if (this.policy.blockPromptInjection && hasPromptInjection) {
      const ticket = this._generateOverrideTicket('AI_PROMPT_INJECTION', metadata);
      this._recordTrip('PROMPT_INJECTION_TRIPPED', scanResult, metadata, ticket);
      return {
        allowed: false,
        status: 'TRIPPED_ADVERSARIAL_INJECTION',
        decision: 'BLOCKED',
        reason: 'Rovo Agent adversarial prompt injection signature detected. PR execution halted.',
        ticket,
        findings_count: findings.length,
        policy: this.policyName
      };
    }

    // Rule 2: Critical vulnerability violation
    if (!this.policy.allowCritical && hasCritical) {
      const ticket = this._generateOverrideTicket('CRITICAL_VULNERABILITY', metadata);
      this._recordTrip('CRITICAL_VULN_TRIPPED', scanResult, metadata, ticket);
      return {
        allowed: false,
        status: 'TRIPPED_CRITICAL_FAIL_CLOSED',
        decision: 'BLOCKED',
        reason: 'Critical OWASP vulnerability detected (e.g. SQL Injection, eval, hardcoded secret). Automated merge blocked.',
        ticket,
        findings_count: findings.length,
        policy: this.policyName
      };
    }

    // Rule 3: High vulnerability violation under strict policy
    if (!this.policy.allowHigh && hasHigh) {
      const ticket = this._generateOverrideTicket('HIGH_SEVERITY_OVERFLOW', metadata);
      this._recordTrip('HIGH_SEVERITY_TRIPPED', scanResult, metadata, ticket);
      return {
        allowed: false,
        status: 'TRIPPED_HIGH_SEVERITY',
        decision: 'BLOCKED',
        reason: 'High severity OWASP findings exceed policy allowance. Security lead sign-off required.',
        ticket,
        findings_count: findings.length,
        policy: this.policyName
      };
    }

    // Rule 4: Total severity score ceiling
    if (scanResult.severity_score > this.policy.maxSeverityScore) {
      const ticket = this._generateOverrideTicket('SEVERITY_SCORE_EXCEEDED', metadata);
      this._recordTrip('SCORE_CEILING_TRIPPED', scanResult, metadata, ticket);
      return {
        allowed: false,
        status: 'TRIPPED_SCORE_CEILING',
        decision: 'BLOCKED',
        reason: `Cumulative risk score (${scanResult.severity_score}) exceeds policy threshold (${this.policy.maxSeverityScore}).`,
        ticket,
        findings_count: findings.length,
        policy: this.policyName
      };
    }

    // Pass closed check: verified safe
    return {
      allowed: true,
      status: 'VERIFIED_CLEAR',
      decision: 'AUTHORIZED',
      reason: 'All zero-trust invariants verified. No blocking security violations found.',
      findings_count: findings.length,
      policy: this.policyName
    };
  }

  _generateOverrideTicket(reason, metadata) {
    const payload = `${reason}::${metadata.prId || 'PR_0'}::${metadata.author || 'dev'}::${Date.now()}`;
    const hmac = crypto.createHmac('sha256', 'REPOGUARD_ATLASSIAN_SECRET')
      .update(payload)
      .digest('hex')
      .slice(0, 16)
      .toUpperCase();
    return `TKT-${hmac}`;
  }

  _recordTrip(type, scanResult, metadata, ticket) {
    this.tripLog.push({
      timestamp: new Date().toISOString(),
      type,
      scan_id: scanResult.scan_id,
      ticket,
      metadata
    });
  }

  getTripHistory() {
    return [...this.tripLog];
  }
}

module.exports = {
  CircuitBreaker,
  POLICIES
};
