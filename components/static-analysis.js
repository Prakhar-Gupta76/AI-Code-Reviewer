const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const CATEGORIES = new Set(['quality', 'security', 'dependency', 'correctness', 'performance']);

/**
 * Common Finding contract used by every analyzer:
 * { source, file, line, severity, category, title, description, suggestion }
 * Lines are one-based. Use line 1 for findings concerning an entire file.
 * Severity is preliminary; the Severity Engine can adjust it later.
 */
function normalizeFinding(source, finding) {
    for (const field of ['file', 'title', 'description', 'suggestion']) {
        if (typeof finding[field] !== 'string' || !finding[field].trim()) {
            throw new TypeError(`${source} returned a finding with an invalid ${field}.`);
        }
    }
    if (!Number.isSafeInteger(finding.line) || finding.line < 1) {
        throw new TypeError(`${source} returned a finding with an invalid line.`);
    }
    if (!SEVERITIES.has(finding.severity) || !CATEGORIES.has(finding.category)) {
        throw new TypeError(`${source} returned an unsupported severity or category.`);
    }
    return {
        source,
        file: finding.file.replace(/\\/g, '/'),
        line: finding.line,
        severity: finding.severity,
        category: finding.category,
        title: finding.title,
        description: finding.description,
        suggestion: finding.suggestion,
    };
}

function normalizeInput(input) {
    const context = Array.isArray(input) ? { files: input } : input;
    if (!context || !Array.isArray(context.files)) {
        throw new TypeError('Static analysis expects a file array or an object containing files.');
    }
    for (const file of context.files) {
        if (!file || typeof file.path !== 'string' || !file.path.trim()
            || typeof file.language !== 'string' || !file.language.trim()
            || typeof file.content !== 'string') {
            throw new TypeError('Each source file must contain path, language, and content strings.');
        }
    }
    return context;
}

async function eslint(files) {
    if (!Array.isArray(files)) throw new TypeError('ESLint expects an array of source files.');
    normalizeInput(files);
    const supportedFiles = files.filter(file => ['javascript', 'typescript'].includes(file.language));
    if (supportedFiles.length === 0) return [];

    const { Linter } = require('eslint');
    const linter = new Linter();
    const findings = [];
    const ruleDetails = {
        'no-unused-vars': {
            title: 'Unused variable',
            suggestion: 'Remove the unused variable or use it where required.',
        },
        '@typescript-eslint/no-unused-vars': {
            title: 'Unused variable',
            suggestion: 'Remove the unused variable or use it where required.',
        },
        'no-unreachable': {
            title: 'Unreachable code',
            suggestion: 'Remove the unreachable code or correct the control flow.',
        },
        eqeqeq: {
            title: 'Loose equality comparison',
            suggestion: 'Use === or !== to avoid implicit type conversion.',
        },
        'valid-typeof': {
            title: 'Invalid typeof comparison',
            suggestion: 'Compare typeof against a valid result such as "string".',
        },
    };

    for (const file of supportedFiles) {
        const filename = file.path.replace(/\\/g, '/');
        const isTypeScript = file.language === 'typescript';
        const tseslint = isTypeScript ? require('typescript-eslint') : null;
        // Synthetic filenames avoid filesystem-dependent config matching while
        // preserving the uploaded path in Findings. TSX requires its own extension.
        const lintFilename = isTypeScript
            ? (/\.tsx$/i.test(filename) ? 'input.tsx' : 'input.ts')
            : 'input.js';
        const configuration = {
            files: ['**/*.{js,ts,tsx}'],
            languageOptions: {
                ecmaVersion: 'latest',
                sourceType: /\.cjs$/i.test(filename) ? 'commonjs' : 'module',
                parserOptions: {
                    ecmaFeatures: { jsx: true },
                    // Syntax linting only; do not discover uploaded tsconfig files.
                    project: false,
                    projectService: false,
                },
                ...(isTypeScript ? { parser: tseslint.parser } : {}),
            },
            plugins: isTypeScript ? { '@typescript-eslint': tseslint.plugin } : {},
            rules: {
                'no-unused-vars': isTypeScript ? 'off' : 'warn',
                'no-unreachable': 'error',
                eqeqeq: 'warn',
                'valid-typeof': 'error',
                ...(isTypeScript ? { '@typescript-eslint/no-unused-vars': 'warn' } : {}),
            },
        };

        // Linter checks the supplied text without loading project configuration,
        // executing uploaded code, applying fixes, or honoring eslint-disable comments.
        const messages = linter.verify(file.content, configuration, {
            filename: lintFilename,
            allowInlineConfig: false,
        });
        for (const message of messages) {
            const details = ruleDetails[message.ruleId];
            findings.push(normalizeFinding('eslint', {
                file: filename,
                line: message.line || 1,
                severity: message.fatal ? 'high' : message.severity === 2 ? 'medium' : 'low',
                category: message.fatal ? 'correctness' : 'quality',
                title: message.fatal ? 'Syntax error' : details?.title || message.ruleId || 'ESLint issue',
                description: message.message,
                suggestion: message.fatal
                    ? 'Fix the syntax error so the file can be analyzed.'
                    : details?.suggestion || 'Review and correct this lint issue.',
            }));
        }
    }
    return findings;
}

async function semgrep(files) {
    if (!Array.isArray(files)) throw new TypeError('Semgrep expects an array of source files.');
    normalizeInput(files);
    if (files.length === 0) return [];
    if (files.length > 10000) throw new Error('Too many source files for Semgrep.');

    // Validate every path before creating files. These restrictions also prevent
    // Windows device names, alternate data streams, and case-insensitive aliases.
    const sources = new Map();
    const seenPaths = new Set();
    let totalBytes = 0;
    for (const file of files) {
        const filename = file.path.replace(/\\/g, '/');
        const parts = filename.split('/');
        if (filename.startsWith('/') || /[:\x00-\x1f\x7f]/.test(filename)
            || parts.includes('..') || filename.endsWith('/')
            || parts.some(part => /[. ]$/.test(part) && part !== '.')
            || parts.some(part => /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))
            || parts.some(part => /^\.(?:git|gitignore|semgrepignore)$/i.test(part))) {
            throw new Error('Invalid or reserved Semgrep source file path.');
        }
        const normalizedPath = path.posix.normalize(filename);
        if (normalizedPath === '.' || seenPaths.has(normalizedPath.toLowerCase())) {
            throw new Error('Invalid or duplicate Semgrep source file path.');
        }
        seenPaths.add(normalizedPath.toLowerCase());
        const bytes = Buffer.byteLength(file.content, 'utf8');
        totalBytes += bytes;
        if (bytes > 5 * 1024 * 1024 || totalBytes > 50 * 1024 * 1024) {
            throw new Error('Source contents exceed the Semgrep processing size limit.');
        }
        sources.set(normalizedPath, file.content);
    }

    const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'code-review-semgrep-'));
    let processingFailure;
    try {
        for (const [filename, content] of sources) {
            const destination = path.join(temporaryDirectory, filename);
            await fs.mkdir(path.dirname(destination), { recursive: true });
            await fs.writeFile(destination, content, { encoding: 'utf8', flag: 'wx' });
        }

        let stdout;
        let timedOut = false;
        let timeout;
        try {
            // The backend chooses Registry rules; uploaded code is never executed.
            // No shell is used, and uploaded nosem/gitignore directives cannot
            // suppress findings. Registry rules require network access when fetched.
            const scan = execFileAsync('semgrep', [
                'scan', '--config', 'p/default', '--json',
                '--metrics', 'off', '--disable-version-check', '--disable-nosem',
                '--no-git-ignore', '--max-target-bytes', String(5 * 1024 * 1024), '.',
            ], {
                cwd: temporaryDirectory,
                encoding: 'utf8',
                env: { ...process.env, PYTHONUTF8: '1' },
                timeout: process.platform === 'win32' ? 0 : 60000,
                maxBuffer: 20 * 1024 * 1024,
                windowsHide: true,
            });
            // All targets are on disk; signal EOF instead of leaving stdin open.
            scan.child?.stdin?.end();
            if (process.platform === 'win32') {
                // Killing only the Python launcher leaves its native scanner alive
                // on Windows. Stop this scan's process tree before removing files.
                timeout = setTimeout(() => {
                    timedOut = true;
                    if (scan.child?.pid) {
                        execFile('taskkill', ['/PID', String(scan.child.pid), '/T', '/F'], {
                            windowsHide: true,
                            timeout: 5000,
                        }, error => {
                            if (error) scan.child.kill();
                        });
                    }
                }, 60000);
            }
            ({ stdout } = await scan);
        } catch (error) {
            if (error.code === 'ENOENT') {
                throw new Error('Semgrep is not installed or is unavailable on PATH.');
            }
            if (timedOut || error.killed || error.code === 'ETIMEDOUT') {
                throw new Error('Semgrep exceeded its 60-second execution time limit.');
            }
            if (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
                throw new Error('Semgrep output exceeded the 20 MB limit.');
            }
            // Do not expose stderr: it may contain uploaded code or credentials.
            throw new Error('Semgrep failed to complete the scan. Check the CLI installation and Registry access.');
        } finally {
            clearTimeout(timeout);
        }

        let report;
        try {
            report = JSON.parse(stdout);
        } catch {
            throw new Error('Semgrep returned invalid JSON.');
        }
        if (!report || !Array.isArray(report.results) || !Array.isArray(report.errors)) {
            throw new Error('Semgrep returned an unexpected result format.');
        }
        if (report.errors.length) {
            throw new Error(`Semgrep reported ${report.errors.length} scan error(s); the scan is incomplete.`);
        }
        if (Array.isArray(report.paths?.scanned) && report.paths.scanned.length === 0) {
            throw new Error('Semgrep did not scan any source files with the selected rules.');
        }

        const severityMap = {
            INFO: 'low', WARNING: 'medium', ERROR: 'high',
            LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical',
        };
        return report.results.map(result => {
            if (!result || typeof result.path !== 'string' || !result.extra
                || typeof result.check_id !== 'string') {
                throw new Error('Semgrep returned a malformed finding.');
            }
            const absolutePath = path.resolve(temporaryDirectory, result.path.replace(/\\/g, '/'));
            const filename = path.relative(temporaryDirectory, absolutePath).replace(/\\/g, '/');
            if (!sources.has(filename)) {
                throw new Error('Semgrep returned a finding for an unexpected file.');
            }
            const category = result.extra.metadata?.category;
            return normalizeFinding('semgrep', {
                file: filename,
                line: result.start?.line,
                severity: severityMap[result.extra.severity] || 'medium',
                category: CATEGORIES.has(category) ? category : 'security',
                title: result.check_id,
                description: result.extra.message,
                suggestion: 'Review this match and follow the rule\'s remediation guidance.',
            });
        });
    } catch (error) {
        processingFailure = error;
        throw error;
    } finally {
        // This directory was created by mkdtemp; nothing is extracted into the project.
        try {
            await fs.rm(temporaryDirectory, {
                recursive: true, force: true, maxRetries: 5, retryDelay: 200,
            });
        } catch {
            if (processingFailure) {
                processingFailure.message += ' Temporary-file cleanup also failed.';
            } else {
                throw new Error('Semgrep finished, but temporary-file cleanup failed.');
            }
        }
    }
}

function isPlaceholder(value) {
    const literal = value.trim();
    return !literal
        || /^(?:example|sample|test|dummy|fake|placeholder)(?:[_ -].*)?$/i.test(literal)
        || /^(?:your[_ -].*|replace[_ -]?me|change[_ -]?me|redacted|xxx+|\*+|\.{3})$/i.test(literal)
        || /^<[^>]+>$/.test(literal)
        || /\$\{[^}]+\}|\{\{[^}]+\}\}/.test(literal);
}

async function secretScanner(files) {
    const findings = [];
    // Heuristic literal-assignment check, not a language parser. It can also find
    // credentials in comments/examples; placeholders are filtered below.
    const assignment = /\b["']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret|token)["']?\s*[:=]\s*(["'`])([^"'`\r\n]+)\1/gi;
    const privateKey = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/;

    for (const file of files) {
        const lines = file.content.split(/\r\n|\n|\r/);
        for (let index = 0; index < lines.length; index++) {
            const line = lines[index];
            for (const match of line.matchAll(assignment)) {
                if (isPlaceholder(match[2])) continue;
                // Never include the matched credential or source snippet in a Finding.
                findings.push({
                    file: file.path,
                    line: index + 1,
                    severity: 'high',
                    category: 'security',
                    title: 'Hard-coded secret',
                    description: 'A possible credential is assigned directly as a string literal.',
                    suggestion: 'Load the credential from an environment variable or secret manager. If it is real and has been exposed, rotate it.',
                });
            }
            if (privateKey.test(line)) {
                findings.push({
                    file: file.path,
                    line: index + 1,
                    severity: 'high',
                    category: 'security',
                    title: 'Embedded private key',
                    description: 'A private-key header appears in the source file.',
                    suggestion: 'Store private keys in a secret manager or protected external file. Rotate the key if it has been exposed.',
                });
            }
        }
    }
    return findings.map(finding => normalizeFinding('secret-scanner', finding));
}

async function astAnalysis(files) {
    if (!Array.isArray(files)) throw new TypeError('AST analysis expects an array of source files.');
    normalizeInput(files);
    const supportedFiles = files.filter(file => ['javascript', 'typescript'].includes(file.language));
    if (supportedFiles.length === 0) return [];

    const { parse } = require('@babel/parser');
    const traverse = require('@babel/traverse').default;
    const findings = [];
    for (const file of supportedFiles) {
        const filename = file.path.replace(/\\/g, '/');
        const isTypeScript = file.language === 'typescript';
        const plugins = [];
        if (isTypeScript) plugins.push('typescript');
        if (!isTypeScript || /\.tsx$/i.test(filename)) plugins.push('jsx');

        let ast;
        try {
            ast = parse(file.content, {
                sourceType: /\.cjs$/i.test(filename) ? 'commonjs' : 'unambiguous',
                sourceFilename: filename,
                plugins,
            });
        } catch (error) {
            // Parser errors are Findings; dependency or programming errors still fail.
            if (!(error instanceof SyntaxError)) throw error;
            findings.push(normalizeFinding('ast-analysis', {
                file: filename,
                line: error.loc?.line || 1,
                severity: 'high',
                category: 'correctness',
                title: 'Syntax error',
                description: error.message,
                suggestion: 'Fix the syntax error so structural checks can run.',
            }));
            continue;
        }

        // Traverse actual syntax nodes. Comments and strings resembling code
        // cannot trigger this rule, and no uploaded code is executed.
        traverse(ast, {
            IfStatement(nodePath) {
                const condition = nodePath.node.test;
                // Starter rule: direct assignments only, including parenthesized
                // assignments. Nested logical conditions and loop tests are excluded.
                if (condition.type !== 'AssignmentExpression') return;
                findings.push(normalizeFinding('ast-analysis', {
                    file: filename,
                    line: condition.loc.start.line,
                    severity: 'medium',
                    category: 'correctness',
                    title: 'Assignment inside an if condition',
                    description: 'This condition assigns a value rather than comparing values. This may unintentionally change program behavior.',
                    suggestion: 'If comparison was intended, use === or !==. Otherwise, make the assignment and condition explicit.',
                }));
            },
        });
    }
    return findings;
}

/**
 * Run deterministic analyzers and return a single Finding array.
 * Accepts files[] or { files }.
 * Runs ESLint, Semgrep, secret scanning, and a starter JavaScript/TypeScript AST rule.
 * Semgrep requires a working CLI on PATH and access to Registry rules.
 * Empty findings do not guarantee that the source is free of issues.
 * Uploaded code is treated as text and is never executed.
 */
async function staticAnalysis(input) {
    const context = normalizeInput(input);
    const analyzers = [
        ['eslint', eslint],
        ['semgrep', semgrep],
        ['secret-scanner', secretScanner],
        ['ast-analysis', astAnalysis],
    ];
    const findings = [];
    for (const [source, analyze] of analyzers) {
        const results = await analyze(context.files, context);
        if (!Array.isArray(results)) {
            throw new TypeError(`${source} must return an array of findings.`);
        }
        for (const result of results) findings.push(normalizeFinding(source, result));
    }
    return findings;
}

module.exports = staticAnalysis;
module.exports.eslint = eslint;
module.exports.semgrep = semgrep;
module.exports.secretScanner = secretScanner;
module.exports.astAnalysis = astAnalysis;
