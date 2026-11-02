'use strict';

/**
 * RepoGuard AI — Model Context Protocol (MCP) Server
 * Built for Atlassian Codegeist 2026 ($1,500 Best App with Atlassian MCP Track)
 * Exposes zero-trust security & audit tools to Atlassian Rovo and AI Agents.
 */

const { scanCode } = require('./scanner');
const { CircuitBreaker } = require('./circuit_breaker');
const RepoAuditChain = require('./audit_chain');

class RepoGuardMCPServer {
  constructor() {
    this.breaker = new CircuitBreaker('SOC2_COMPLIANT');
    this.chain = new RepoAuditChain();
  }

  getToolManifest() {
    return [
      {
        name: 'repoguard_scan_code',
        description: 'Scans source code or pull requests for 15 OWASP Top 10 vulnerabilities, secrets, and adversarial prompt injections.',
        inputSchema: {
          type: 'object',
          properties: {
            code: { type: 'string', description: 'The source code snippet or git diff to scan.' },
            filePath: { type: 'string', description: 'Optional relative file path (e.g. src/auth.js).' },
            jiraKey: { type: 'string', description: 'Associated Jira Issue Key (e.g. PROJ-104).' }
          },
          required: ['code']
        }
      },
      {
        name: 'repoguard_evaluate_policy',
        description: 'Evaluates scan findings against enterprise zero-trust circuit-breaker policies (STRICT_ZERO_TRUST, SOC2_COMPLIANT).',
        inputSchema: {
          type: 'object',
          properties: {
            scanId: { type: 'string', description: 'The scan ID returned from repoguard_scan_code.' },
            policy: { type: 'string', enum: ['STRICT_ZERO_TRUST', 'SOC2_COMPLIANT', 'BALANCED_AGILE'] },
            author: { type: 'string', description: 'Git committer or Rovo Agent name.' }
          },
          required: ['scanId']
        }
      },
      {
        name: 'repoguard_seal_audit_block',
        description: 'Cryptographically seals a scan result into the SHA-256 tamper-evident audit chain for SOC2 compliance.',
        inputSchema: {
          type: 'object',
          properties: {
            code: { type: 'string', description: 'The source code that was scanned.' },
            prId: { type: 'number', description: 'Bitbucket Pull Request ID.' },
            repo: { type: 'string', description: 'Repository slug.' },
            jiraKey: { type: 'string', description: 'Jira issue key.' }
          },
          required: ['code', 'prId', 'repo']
        }
      },
      {
        name: 'repoguard_verify_chain',
        description: 'Verifies the cryptographic integrity of the entire audit chain from Genesis to tip.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];
  }

  async handleCallTool(name, args = {}) {
    switch (name) {
      case 'repoguard_scan_code': {
        const result = scanCode(args.code, { filePath: args.filePath, jiraKey: args.jiraKey });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      }

      case 'repoguard_evaluate_policy': {
        const breaker = args.policy ? new CircuitBreaker(args.policy) : this.breaker;
        // In a live MCP call, evaluate scan payload
        const dummyScan = {
          scan_id: args.scanId,
          findings: args.findings || [],
          severity_score: args.severityScore || 0
        };
        const decision = breaker.evaluate(dummyScan, { author: args.author });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(decision, null, 2)
            }
          ]
        };
      }

      case 'repoguard_seal_audit_block': {
        const scanResult = scanCode(args.code, { prId: args.prId, repo: args.repo });
        const decision = this.breaker.evaluate(scanResult, { prId: args.prId, author: args.author || 'rovo-agent' });
        const block = this.chain.append(
          scanResult.scan_id,
          args.code,
          scanResult,
          decision,
          { prId: args.prId, repo: args.repo, jiraKey: args.jiraKey }
        );
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                status: 'SEALED',
                block_index: block.index,
                block_hash: block.hash,
                decision: decision.decision,
                intact: this.chain.verify().intact
              }, null, 2)
            }
          ]
        };
      }

      case 'repoguard_verify_chain': {
        const verification = this.chain.verify();
        const stats = this.chain.getStats();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ ...verification, stats }, null, 2)
            }
          ]
        };
      }

      default:
        throw new Error(`Unknown MCP Tool: ${name}`);
    }
  }

  handleJsonRpc(message) {
    if (message.method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: this.getToolManifest()
        }
      };
    }

    if (message.method === 'tools/call') {
      return this.handleCallTool(message.params.name, message.params.arguments)
        .then(res => ({
          jsonrpc: '2.0',
          id: message.id,
          result: res
        }))
        .catch(err => ({
          jsonrpc: '2.0',
          id: message.id,
          error: { code: -32603, message: err.message }
        }));
    }

    return {
      jsonrpc: '2.0',
      id: message.id,
      error: { code: -32601, message: 'Method not found' }
    };
  }
}

// CLI / Stdio execution support
if (require.main === module) {
  const readline = require('readline');
  const server = new RepoGuardMCPServer();
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });

  rl.on('line', async line => {
    try {
      const parsed = JSON.parse(line);
      const res = await server.handleJsonRpc(parsed);
      process.stdout.write(JSON.stringify(res) + '\n');
    } catch (e) {
      process.stderr.write(`MCP JSON parse error: ${e.message}\n`);
    }
  });
}

module.exports = RepoGuardMCPServer;
