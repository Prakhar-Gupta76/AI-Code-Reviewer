const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const CATEGORIES = new Set(['quality', 'security', 'dependency', 'correctness', 'performance']);
const STRING_FIELDS = ['source', 'file', 'severity', 'category', 'title', 'description', 'suggestion'];

/**
 * Combine the completed static-analysis and AI-review Finding arrays.
 * Returns fresh Finding objects, with static findings first and AI findings second.
 * Both arguments are required; use [] for a branch that completed with no findings.
 * Invalid/missing branch results throw rather than being treated as a clean review.
 * Matching findings are preserved for the separate deduplication component.
 * Severity values and source attribution are preserved for downstream processing.
 */
function mergeFindings(staticFindings, aiFindings) {
    const merged = [];
    for (const [branch, findings] of [
        ['Static analysis', staticFindings],
        ['AI review', aiFindings],
    ]) {
        if (!Array.isArray(findings)) {
            throw new TypeError(`${branch} must provide an array of Findings.`);
        }
        // Index explicitly so sparse arrays cannot silently omit invalid findings.
        for (let index = 0; index < findings.length; index++) {
            const finding = findings[index];
            if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
                throw new TypeError(`${branch} finding ${index} must be a Finding object.`);
            }
            for (const field of STRING_FIELDS) {
                if (typeof finding[field] !== 'string' || !finding[field].trim()) {
                    throw new TypeError(`${branch} finding ${index} has an invalid ${field}.`);
                }
            }
            if (!Number.isSafeInteger(finding.line) || finding.line < 1) {
                throw new TypeError(`${branch} finding ${index} must have a positive integer line.`);
            }
            if (!SEVERITIES.has(finding.severity) || !CATEGORIES.has(finding.category)) {
                throw new TypeError(`${branch} finding ${index} has an unsupported severity or category.`);
            }
            merged.push({
                source: finding.source,
                file: finding.file,
                line: finding.line,
                severity: finding.severity,
                category: finding.category,
                title: finding.title,
                description: finding.description,
                suggestion: finding.suggestion,
            });
        }
    }
    return merged;
}

module.exports = mergeFindings;
