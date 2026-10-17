const path = require('node:path');

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const CATEGORIES = new Set(['quality', 'security', 'dependency', 'correctness', 'performance']);
const STRING_FIELDS = ['source', 'file', 'severity', 'category', 'title', 'description', 'suggestion'];

function normalizeTitle(title) {
    // Match case and separator variations without removing meaningful operators,
    // variable names, or other punctuation. This is not semantic/fuzzy matching.
    return title.normalize('NFC').trim().toLowerCase().replace(/[\s_-]+/gu, '-');
}

function normalizeFile(filename) {
    const relativePath = filename.replace(/\\/g, '/');
    if (relativePath.startsWith('/') || /[:\x00-\x1f\x7f]/.test(relativePath)
        || relativePath.split('/').includes('..') || relativePath.endsWith('/')) {
        throw new TypeError('Finding file must be a relative file path without traversal.');
    }
    const normalized = path.posix.normalize(relativePath);
    if (normalized === '.') throw new TypeError('Finding file must identify a file.');
    return normalized;
}

/**
 * Deduplicate the merged Finding[] by file, line, category, and normalized title.
 * Returns fresh objects in first-occurrence order, with these additional fields:
 *   fingerprint: "user.js:20:quality:unused-variable"
 *   sources: ["eslint", "ai-review", "ast-analysis"]
 * Keeps the first finding's wording and source; sources records all detectors.
 * Keeps the highest reported severity as a preliminary value for the Severity Engine.
 * Existing sources arrays are accepted, so running this component twice is safe.
 * Does not mutate input, infer equivalent titles, or merge different source locations.
 */
function deduplicateFindings(findings) {
    if (!Array.isArray(findings)) {
        throw new TypeError('Deduplication expects an array of Findings.');
    }
    const groups = new Map();
    // Index explicitly to reject sparse arrays instead of silently skipping holes.
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

        const file = normalizeFile(finding.file);
        const title = normalizeTitle(finding.title);
        const key = JSON.stringify([file, finding.line, finding.category, title]);
        let group = groups.get(key);
        if (!group) {
            group = {
                finding: {
                    source: finding.source.trim(),
                    file,
                    line: finding.line,
                    severity: finding.severity,
                    category: finding.category,
                    title: finding.title,
                    description: finding.description,
                    suggestion: finding.suggestion,
                    fingerprint: `${file}:${finding.line}:${finding.category}:${title}`,
                },
                sources: new Set(),
            };
            groups.set(key, group);
        } else if (SEVERITIES.indexOf(finding.severity) > SEVERITIES.indexOf(group.finding.severity)) {
            group.finding.severity = finding.severity;
        }
        group.sources.add(finding.source.trim());
        for (const source of finding.sources || []) group.sources.add(source.trim());
    }
    return [...groups.values()].map(group => ({
        ...group.finding,
        sources: [...group.sources],
    }));
}

module.exports = deduplicateFindings;
