const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORIES = new Set(['quality', 'security', 'dependency', 'correctness', 'performance']);
const STRING_FIELDS = ['source', 'file', 'severity', 'category', 'title', 'description', 'suggestion'];

function compareStrings(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * Format the deduplicated Finding[] into a JSON-serializable final report:
 * {
 *   summary: { totalFindings, affectedFiles, bySeverity: { critical, high, medium, low, info } },
 *   findings: { critical: Finding[], high: Finding[], medium: Finding[], low: Finding[], info: Finding[] }
 * }
 * Preserves existing severity, wording, fingerprints, and all detecting sources.
 * Groups are sorted by file, then line, then title. Inputs are never mutated.
 * This component does not run analyzers, deduplicate again, or recalculate severity.
 * Empty findings are a report with zero counts, not a guarantee that the code is safe.
 */
function finalReview(findings) {
    if (!Array.isArray(findings)) {
        throw new TypeError('Final review expects an array of deduplicated Findings.');
    }
    const grouped = Object.fromEntries(SEVERITIES.map(severity => [severity, []]));
    const bySeverity = Object.fromEntries(SEVERITIES.map(severity => [severity, 0]));
    const affectedFiles = new Set();

    // Index explicitly so sparse arrays cannot silently drop invalid findings.
    for (let index = 0; index < findings.length; index++) {
        const finding = findings[index];
        if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
            throw new TypeError(`Finding ${index} must be a Finding object.`);
        }
        for (const field of STRING_FIELDS) {
            if (typeof finding[field] !== 'string' || !finding[field].trim()) {
                throw new TypeError(`Finding ${index} has an invalid ${field}.`);
            }
        }
        if (!Number.isSafeInteger(finding.line) || finding.line < 1) {
            throw new TypeError(`Finding ${index} must have a positive integer line.`);
        }
        if (!SEVERITIES.includes(finding.severity) || !CATEGORIES.has(finding.category)) {
            throw new TypeError(`Finding ${index} has an unsupported severity or category.`);
        }
        if (finding.sources !== undefined && (!Array.isArray(finding.sources)
            || finding.sources.length === 0
            || Array.from(finding.sources).some(source => typeof source !== 'string' || !source.trim()))) {
            throw new TypeError(`Finding ${index} has an invalid sources array.`);
        }
        if (finding.fingerprint !== undefined
            && (typeof finding.fingerprint !== 'string' || !finding.fingerprint.trim())) {
            throw new TypeError(`Finding ${index} has an invalid fingerprint.`);
        }

        const file = finding.file.replace(/\\/g, '/');
        const sources = new Set([finding.source.trim()]);
        for (const source of finding.sources || []) sources.add(source.trim());
        grouped[finding.severity].push({
            source: finding.source,
            file,
            line: finding.line,
            severity: finding.severity,
            category: finding.category,
            title: finding.title,
            description: finding.description,
            suggestion: finding.suggestion,
            ...(finding.fingerprint !== undefined ? { fingerprint: finding.fingerprint } : {}),
            sources: [...sources],
        });
        bySeverity[finding.severity]++;
        affectedFiles.add(file);
    }

    for (const severity of SEVERITIES) {
        grouped[severity].sort((left, right) =>
            compareStrings(left.file, right.file)
            || left.line - right.line
            || compareStrings(left.title, right.title));
    }
    return {
        summary: {
            totalFindings: findings.length,
            affectedFiles: affectedFiles.size,
            bySeverity,
        },
        findings: grouped,
    };
}

module.exports = finalReview;
