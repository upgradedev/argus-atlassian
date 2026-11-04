'use strict';

// Deterministic textual pipeline repairs.
// Only rules with a safe local rewrite are transformed. A repair is
// reported as applied only after the rewritten YAML is re-extracted and
// the same Elenchos rule actually passes. That closes the loop: the
// repair cannot claim success on its own say-so. Rules needing a human
// choice (which image tag, which roster, which secret to rotate) stay
// unsupported and named.

const { extractPipelineFacts } = require('./pipeline_facts.js');
const { evaluateRules } = require('./rules.js');

const TEST_LINE = /(npm (run )?test|pytest|go test|cargo test|mvn (test|verify)|gradlew? (test|check)|dotnet test|\bjest\b|\bvitest\b)/i;
const LINT_LINE = /(eslint|ruff|flake8|pylint|golangci-lint|npm run lint|\blint\b)/i;
const SCAN_LINE = /(snyk|codeql|trivy|semgrep|bandit|npm audit|gitleaks|security scan)/i;

function mapLines(text, fn) {
  return text.split('\n').map(fn).join('\n');
}

function tidy(line) {
  return line.replace(/[ \t]{2,}(?=\|\||&&|;|$)/g, ' ').trimEnd();
}

const TRANSFORMS = Object.freeze({
  r01: (text) => mapLines(text, (line) => (
    TEST_LINE.test(line) ? tidy(line.replace(/\s*\|\|\s*true\b/g, '')) : line
  )),
  r02: (text) => text
    .replace(/((?:allow_failure|continue-on-error)\s*:\s*)true/gi, '$1false'),
  r03: (text) => mapLines(text, (line) => tidy(line
    .replace(/\s+-DskipTests(?:=(?:true|false))?/gi, '')
    .replace(/\s+--skip-tests\b/gi, '')
    .replace(/(\bSKIP_TESTS\s*[:=]\s*)(?:true|1|yes)/gi, '$1false'))),
  r05: (text) => mapLines(text, (line) => tidy(
    line.replace(/\s+--passWithNoTests(?:=(?:true|false))?/gi, ''),
  )),
  r06: (text) => {
    const withRaisedThreshold = text.replace(
      /(--cov-fail-under(?:=|\s+))(\d+(?:\.\d+)?)/gi,
      (match, prefix, value) => (Number(value) < 80 ? `${prefix}80` : match),
    );
    if (withRaisedThreshold !== text) return withRaisedThreshold;
    if (!/pytest|--cov(?:=|\s)/i.test(text) || /--cov-fail-under/i.test(text)) return text;
    return mapLines(text, (line) => (
      /pytest|--cov(?:=|\s)/i.test(line) && !/--cov-fail-under/i.test(line)
        ? `${tidy(line)} --cov-fail-under=80`
        : line
    ));
  },
  r08: (text) => mapLines(text, (line) => (
    LINT_LINE.test(line) ? tidy(line.replace(/\s*\|\|\s*true\b/g, '')) : line
  )).replace(/((?:allow_failure|continue-on-error)\s*:\s*)true/gi, '$1false'),
  r10: (text) => mapLines(text, (line) => {
    if (!SCAN_LINE.test(line)) return line;
    return tidy(line
      .replace(/\s*\|\|\s*true\b/g, '')
      .replace(/(fail-on[= ])(?:none|critical)\b/gi, '$1high')
      .replace(/(severity[= ])(?:none|critical)\b/gi, '$1high'));
  }),
  r16: (text) => mapLines(text, (line) => tidy(line.replace(
    /\bnpm install(?=\s*(?:--|\|\||&&|;|$))/g,
    'npm ci',
  ))),
  r20: (text) => mapLines(text, (line) => tidy(line.replace(/\s*\|\|\s*exit\s+0\b/g, ''))),
});

function evaluate(text, enrichments) {
  return evaluateRules(extractPipelineFacts(text, enrichments));
}

function repairPipelineYaml(source, { enrichments = {} } = {}) {
  const original = String(source ?? '');
  const initialViolations = [...evaluate(original, enrichments).violations];
  let current = original;
  const candidateApplied = [];

  for (const [ruleId, transform] of Object.entries(TRANSFORMS)) {
    if (!initialViolations.includes(ruleId)) continue;
    const next = transform(current);
    if (next !== current) {
      candidateApplied.push(ruleId);
      current = next;
    }
  }

  const remainingViolations = [...evaluate(current, enrichments).violations];
  const applied = candidateApplied.filter((id) => !remainingViolations.includes(id));
  const unsupported = initialViolations.filter((id) => !applied.includes(id));

  return Object.freeze({
    yaml: current,
    changed: current !== original,
    applied: Object.freeze(applied),
    unsupported: Object.freeze(unsupported),
    initialViolations: Object.freeze(initialViolations),
    remainingViolations: Object.freeze(remainingViolations),
  });
}

module.exports = { TRANSFORMS, repairPipelineYaml };
