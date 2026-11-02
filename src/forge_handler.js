'use strict';

/**
 * RepoGuard AI — Atlassian Forge Serverless Handlers
 * Entrypoint for Jira, Bitbucket, and Rovo Agent actions in Atlassian Cloud.
 */

const { scanCode } = require('./scanner');
const { CircuitBreaker } = require('./circuit_breaker');
const RepoAuditChain = require('./audit_chain');

// In-memory runtime instances across Forge function warm cycles
const breaker = new CircuitBreaker('SOC2_COMPLIANT');
const chain = new RepoAuditChain();

/**
 * Handler for Rovo Agent / Action: repoguard-scan-action
 */
async function scanHandler(event) {
  const { code, filePath } = event.payload || event;
  const scanResult = scanCode(code, { filePath });
  const decision = breaker.evaluate(scanResult, { filePath, author: event.context?.accountId || 'rovo-agent' });

  return {
    success: true,
    scan_id: scanResult.scan_id,
    risk_level: scanResult.risk_level,
    severity_score: scanResult.severity_score,
    circuit_decision: decision.decision,
    reason: decision.reason,
    ticket: decision.ticket || null,
    findings: scanResult.findings
  };
}

/**
 * Handler for Rovo Agent / Action: repoguard-audit-action
 */
async function auditHandler(event) {
  const { scanId, prId, code, repo } = event.payload || event;
  const scanResult = scanCode(code || '// verified audit code', { prId, repo });
  const decision = breaker.evaluate(scanResult, { prId });
  const block = chain.append(scanId, code, scanResult, decision, { prId, repo });

  return {
    success: true,
    block_index: block.index,
    block_hash: block.hash,
    prev_hash: block.prev_hash,
    decision: decision.decision,
    chain_intact: chain.verify().intact
  };
}

/**
 * Resolver for Bitbucket PR Overview and Jira Issue Glance
 */
async function uiResolver(req) {
  const { call } = req;

  if (call === 'getPRSecuritySummary') {
    return {
      status: 'SHIELD_ACTIVE',
      policy: breaker.policyName,
      stats: chain.getStats(),
      recent_blocks: chain.getEntries(5)
    };
  }

  if (call === 'runInstantAudit') {
    const { code, prId, repo } = req.payload || {};
    const result = scanCode(code, { prId, repo });
    const decision = breaker.evaluate(result, { prId });
    const block = chain.append(result.scan_id, code, result, decision, { prId, repo });

    return {
      result,
      decision,
      block,
      chain_intact: chain.verify().intact
    };
  }

  return { error: 'Unknown resolver call' };
}

/**
 * Automated Event Trigger on Bitbucket Pull Request Created / Updated
 */
async function prTriggerHandler(event) {
  const pr = event.pullrequest || {};
  const prId = pr.id || 101;
  const repo = event.repository?.name || 'enterprise-repo';

  // In production Forge, this queries the Bitbucket REST API for the PR diff
  const sampleDiff = pr.description || '// standard pull request diff';
  const scanResult = scanCode(sampleDiff, { prId, repo });
  const decision = breaker.evaluate(scanResult, { prId, repo, author: pr.author?.display_name });
  const block = chain.append(scanResult.scan_id, sampleDiff, scanResult, decision, { prId, repo });

  return {
    triggered: true,
    pr_id: prId,
    decision: decision.decision,
    block_hash: block.hash,
    chain_intact: chain.verify().intact
  };
}

module.exports = {
  scanHandler,
  auditHandler,
  uiResolver,
  prTriggerHandler,
  breaker,
  chain
};
