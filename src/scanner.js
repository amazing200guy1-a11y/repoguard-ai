'use strict';

/**
 * RepoGuard AI — Enterprise Security & Prompt-Injection Scanner
 * Built for Atlassian Forge & Rovo Agents (Codegeist 2026)
 * Zero external npm dependencies — Node.js stdlib only.
 */

const OWASP_RULES = [
  {
    id: 'OWASP-A01-TRAVERSAL',
    name: 'Path Traversal / Arbitrary File Read',
    severity: 'HIGH',
    category: 'Broken Access Control',
    patterns: [
      /\.\.\//g,
      /path\.join\(.*req\./i,
      /fs\.(readFile|readFileSync|createReadStream)\(.*(?:req\.|params|query|body)/i
    ],
    advisory: 'Sanitize file paths with path.resolve() and verify path stays within allowed root boundaries.'
  },
  {
    id: 'OWASP-A02-SECRET',
    name: 'Hardcoded Cryptographic Secret / API Key',
    severity: 'CRITICAL',
    category: 'Cryptographic Failures',
    patterns: [
      /(?:apiKey|api_key|password|secret|token|jwt|awsKey)\s*[:=]\s*["'`][A-Za-z0-9+/=_\-\.@!]{8,}["'`]/i,
      /sk-[A-Za-z0-9]{20,}/,
      /AKIA[0-9A-Z]{16}/,
      /ghp_[A-Za-z0-9]{36}/
    ],
    advisory: 'Secrets must never be stored in source code. Inject via Atlassian Forge environment variables or enterprise vault.'
  },
  {
    id: 'OWASP-A02-WEAK-CRYPTO',
    name: 'Broken / Obsolete Cryptographic Hash',
    severity: 'MEDIUM',
    category: 'Cryptographic Failures',
    patterns: [
      /createHash\s*\(\s*['"]md5['"]\s*\)/i,
      /createHash\s*\(\s*['"]sha1['"]\s*\)/i
    ],
    advisory: 'MD5 and SHA-1 are cryptographically vulnerable. Use SHA-256 or SHA-512.'
  },
  {
    id: 'OWASP-A03-SQLI',
    name: 'SQL String Concatenation Injection',
    severity: 'CRITICAL',
    category: 'Injection',
    patterns: [
      /["'`]\s*\+\s*(?:userId|username|name|id|input|query|param|req\.)/i,
      /WHERE\s+\w+\s*=.*?\+\s*[a-zA-Z_$]/i,
      /SELECT\s+.*?\+\s*[a-zA-Z_$]/i,
      /`SELECT\s+.*?\$\{/i,
      /db\.(?:query|execute)\s*\(\s*`[^`]*\$\{/i
    ],
    advisory: 'Use parameterized queries or prepared statements. Never interpolate untrusted variables into SQL strings.'
  },
  {
    id: 'OWASP-A03-EVAL',
    name: 'eval() Remote Dynamic Code Execution',
    severity: 'CRITICAL',
    category: 'Injection',
    patterns: [
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /setTimeout\s*\(\s*["'`]/,
      /setInterval\s*\(\s*["'`]/
    ],
    advisory: 'eval() and dynamic Function invocation execute arbitrary bytecode. Replace with structured parsers.'
  },
  {
    id: 'OWASP-A03-XSS',
    name: 'Cross-Site Scripting (XSS) via DOM Sink',
    severity: 'HIGH',
    category: 'Injection',
    patterns: [
      /\.innerHTML\s*=/,
      /\.outerHTML\s*=/,
      /document\.write\s*\(/
    ],
    advisory: 'Directly assigning to innerHTML allows script injection. Use textContent or DOMPurify.'
  },
  {
    id: 'OWASP-A03-CMD',
    name: 'OS Command Injection',
    severity: 'CRITICAL',
    category: 'Injection',
    patterns: [
      /exec\s*\(.*\+/i,
      /execSync\s*\(\s*`/i,
      /child_process.*shell\s*:\s*true/i
    ],
    advisory: 'Direct shell execution allows OS command injection. Use execFile() with discrete argument vectors.'
  },
  {
    id: 'OWASP-A03-NOSQL',
    name: 'NoSQL / MongoDB Operator Injection',
    severity: 'HIGH',
    category: 'Injection',
    patterns: [
      /\$where\s*:/i,
      /find\(\s*\{[^}]*\$[a-z]/i
    ],
    advisory: 'Sanitize query payloads to strip dollar-sign operator prefixes before database queries.'
  },
  {
    id: 'OWASP-A06-REDOS',
    name: 'Regular Expression Denial of Service (ReDoS)',
    severity: 'MEDIUM',
    category: 'Vulnerable Components',
    patterns: [
      /\(\.\+\)\+/,
      /\(\.\*\)\*/,
      /\(a\+\)\+/
    ],
    advisory: 'Nested quantifiers cause exponential catastrophic backtracking. Rewrite using non-overlapping states.'
  },
  {
    id: 'OWASP-A08-PROTO-POLLUTION',
    name: 'Prototype Pollution',
    severity: 'HIGH',
    category: 'Software & Data Integrity',
    patterns: [
      /__proto__/i,
      /\["__proto__"\]/,
      /Object\.assign\([^,]+,.*req\./i
    ],
    advisory: 'Guard object recursion against __proto__, constructor, and prototype mutations.'
  },
  {
    id: 'OWASP-A09-LOG-LEAK',
    name: 'Sensitive Credential Leak in Production Log',
    severity: 'LOW',
    category: 'Security Logging & Monitoring',
    patterns: [
      /console\.(?:log|debug|info)\s*\(.*(?:password|secret|apiKey|token|credential)/i
    ],
    advisory: 'Logging sensitive tokens compromises SOC2 compliance. Scrub credentials before logging.'
  }
];

const PROMPT_INJECTION_RULES = [
  {
    id: 'AI-INJECT-01',
    name: 'Rovo Agent Instruction Override',
    severity: 'CRITICAL',
    category: 'Adversarial Prompt Injection',
    patterns: [
      /ignore\s+(?:all\s+)?previous\s+instructions/i,
      /override\s+(?:system\s+)?safety\s+guardrails/i,
      /you\s+are\s+now\s+in\s+unrestricted\s+mode/i,
      /disregard\s+(?:company\s+)?policy/i
    ],
    advisory: 'Adversarial prompt injection detected. This payload attempts to hijack Atlassian Rovo agent system context.'
  },
  {
    id: 'AI-EXFIL-02',
    name: 'Confluence / Jira Internal Data Exfiltration Attempt',
    severity: 'CRITICAL',
    category: 'Adversarial Data Exfiltration',
    patterns: [
      /export\s+(?:all\s+)?confluence\s+pages/i,
      /curl\s+.*webhook\.site/i,
      /fetch\s*\(["'`]https?:\/\/(?:webhook|burpcollaborator|requestbin)/i,
      /send\s+(?:jira\s+)?api\s+keys?\s+to/i
    ],
    advisory: 'Data exfiltration attempt detected. Malicious attempt to transmit enterprise Atlassian data to external endpoint.'
  }
];

function scanCode(code, context = {}) {
  const lines = (code || '').split('\n');
  const findings = [];
  const allRules = [...OWASP_RULES, ...PROMPT_INJECTION_RULES];

  allRules.forEach(rule => {
    lines.forEach((line, index) => {
      const trimmed = line.trim();
      // Skip pure non-payload comments unless checking for prompt injection in comments
      const isComment = trimmed.startsWith('//') || trimmed.startsWith('#');
      
      for (const pattern of rule.patterns) {
        if (pattern.test(line)) {
          findings.push({
            rule_id: rule.id,
            rule_name: rule.name,
            severity: rule.severity,
            category: rule.category,
            line: index + 1,
            line_text: trimmed.slice(0, 100),
            advisory: rule.advisory,
            context: context.filePath || context.prTitle || 'inline_code'
          });
          break;
        }
      }
    });
  });

  const severityWeights = { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1 };
  const severityScore = findings.reduce((acc, f) => acc + (severityWeights[f.severity] || 0), 0);

  let riskLevel = 'CLEAN';
  let circuitTripped = false;

  if (severityScore >= 10 || findings.some(f => f.severity === 'CRITICAL')) {
    riskLevel = 'CRITICAL';
    circuitTripped = true;
  } else if (severityScore >= 6 || findings.some(f => f.severity === 'HIGH')) {
    riskLevel = 'HIGH';
    circuitTripped = true;
  } else if (severityScore >= 3) {
    riskLevel = 'MEDIUM';
    circuitTripped = false;
  } else if (findings.length > 0) {
    riskLevel = 'LOW';
    circuitTripped = false;
  }

  return {
    scan_id: 'RG-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase(),
    timestamp: new Date().toISOString(),
    lines_scanned: lines.length,
    rules_evaluated: allRules.length,
    finding_count: findings.length,
    severity_score: severityScore,
    risk_level: riskLevel,
    circuit_tripped: circuitTripped,
    findings
  };
}

module.exports = {
  scanCode,
  OWASP_RULES,
  PROMPT_INJECTION_RULES
};
