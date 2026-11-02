'use strict';

/**
 * RepoGuard AI — SHA-256 Tamper-Evident Forensic Audit Chain
 * Built for Atlassian Bitbucket PRs & Rovo AI Agent Commit Attributions.
 * Ensures zero-trust traceability for SOC2 and ISO 27001 compliance.
 */

const crypto = require('crypto');

class RepoAuditChain {
  constructor() {
    this.entries = [];
    this.currentTipHash = 'GENESIS_ATLASSIAN_FORGE_CHAIN_V1';
  }

  _sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
  }

  /**
   * Append a scanned pull request or Rovo agent action to the chain.
   * @param {string} scanId
   * @param {string} codeContent
   * @param {object} scanResult
   * @param {object} circuitDecision
   * @param {object} metadata - { prId, repo, author, jiraKey }
   * @returns {object} Sealed chain entry
   */
  append(scanId, codeContent, scanResult, circuitDecision, metadata = {}) {
    const timestamp = new Date().toISOString();
    const index = this.entries.length;
    const prevHash = this.currentTipHash;

    const codeHash = this._sha256(codeContent || '');
    const findingsHash = this._sha256(JSON.stringify(scanResult.findings || []));
    const metadataHash = this._sha256(JSON.stringify(metadata));

    // Canonical payload for deterministic cryptographic verification
    const payload = JSON.stringify({
      index,
      timestamp,
      scan_id: scanId,
      jira_key: metadata.jiraKey || 'NONE',
      repo: metadata.repo || 'unknown_repo',
      pr_id: metadata.prId || 0,
      code_hash: codeHash,
      findings_hash: findingsHash,
      metadata_hash: metadataHash,
      finding_count: scanResult.finding_count || 0,
      severity_score: scanResult.severity_score || 0,
      decision: circuitDecision.decision || 'BLOCKED',
      prev_hash: prevHash
    });

    const hash = this._sha256(payload);

    const entry = {
      index,
      timestamp,
      scan_id: scanId,
      jira_key: metadata.jiraKey || 'NONE',
      repo: metadata.repo || 'unknown_repo',
      pr_id: metadata.prId || 0,
      code_hash: codeHash,
      findings_hash: findingsHash,
      metadata_hash: metadataHash,
      finding_count: scanResult.finding_count || 0,
      severity_score: scanResult.severity_score || 0,
      decision: circuitDecision.decision || 'BLOCKED',
      prev_hash: prevHash,
      hash
    };

    this.entries.push(entry);
    this.currentTipHash = hash;
    return entry;
  }

  /**
   * Verify the integrity of the entire chain from Genesis to tip.
   * @returns {{ intact: boolean, entry_count: number, broken_at?: number }}
   */
  verify() {
    if (this.entries.length === 0) {
      return { intact: true, entry_count: 0, tip_hash: this.currentTipHash };
    }

    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];

      const payload = JSON.stringify({
        index: e.index,
        timestamp: e.timestamp,
        scan_id: e.scan_id,
        jira_key: e.jira_key,
        repo: e.repo,
        pr_id: e.pr_id,
        code_hash: e.code_hash,
        findings_hash: e.findings_hash,
        metadata_hash: e.metadata_hash,
        finding_count: e.finding_count,
        severity_score: e.severity_score,
        decision: e.decision,
        prev_hash: e.prev_hash
      });

      const computedHash = this._sha256(payload);

      if (e.hash !== computedHash) {
        return { intact: false, entry_count: this.entries.length, broken_at: i, reason: 'HASH_MISMATCH' };
      }

      if (i === 0 && e.prev_hash !== 'GENESIS_ATLASSIAN_FORGE_CHAIN_V1') {
        return { intact: false, entry_count: this.entries.length, broken_at: 0, reason: 'GENESIS_POISONED' };
      }

      if (i > 0 && e.prev_hash !== this.entries[i - 1].hash) {
        return { intact: false, entry_count: this.entries.length, broken_at: i, reason: 'CHAIN_LINK_BROKEN' };
      }
    }

    return {
      intact: true,
      entry_count: this.entries.length,
      tip_hash: this.currentTipHash
    };
  }

  getEntries(limit = 50) {
    return [...this.entries].reverse().slice(0, limit);
  }

  getEntryByScanId(scanId) {
    return this.entries.find(e => e.scan_id === scanId) || null;
  }

  getStats() {
    return {
      total_blocks: this.entries.length,
      authorized_blocks: this.entries.filter(e => e.decision === 'AUTHORIZED').length,
      blocked_blocks: this.entries.filter(e => e.decision === 'BLOCKED').length,
      intact: this.verify().intact,
      tip_hash: this.currentTipHash
    };
  }
}

module.exports = RepoAuditChain;
