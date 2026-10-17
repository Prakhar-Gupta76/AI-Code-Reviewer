const fs = require('node:fs');
const path = require('node:path');
const { TextDecoder } = require('node:util');

const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const MAX_SOURCE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 10000;
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git', 'dist']);
const LANGUAGES = {
    '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.java': 'java',
    '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.hpp': 'cpp', '.cc': 'cpp', '.cs': 'csharp',
    '.go': 'go', '.rs': 'rust', '.rb': 'ruby', '.php': 'php', '.swift': 'swift',
    '.kt': 'kotlin', '.kts': 'kotlin', '.scala': 'scala', '.sh': 'bash', '.bash': 'bash',
    '.ps1': 'powershell', '.sql': 'sql', '.html': 'html', '.css': 'css', '.scss': 'scss',
    '.sass': 'sass', '.vue': 'vue', '.svelte': 'svelte', '.dart': 'dart', '.r': 'r', '.lua': 'lua',
};

function processingError(message, statusCode = 400) {
    const error = new Error(message);
    error.status = statusCode;
    error.statusCode = statusCode;
    return error;
}

function normalizePath(filename) {
    if (typeof filename !== 'string' || !filename.trim() || /[\x00-\x1f\x7f]/.test(filename)) {
        throw processingError('Invalid source file path.');
    }
    const relativePath = filename.replace(/\\/g, '/');
    if (relativePath.startsWith('/') || /^[a-z]:/i.test(relativePath)
        || relativePath.split('/').includes('..')) {
        throw processingError('Source file paths must be relative and cannot contain traversal.');
    }
    const normalized = path.posix.normalize(relativePath);
    if (normalized === '.' || normalized === './') {
        throw processingError('Invalid source file path.');
    }
    return normalized;
}

function sourceLanguage(filename) {
    const directories = filename.split('/').slice(0, -1);
    if (directories.some(directory => IGNORED_DIRECTORIES.has(directory.toLowerCase()))) {
        return null;
    }
    return LANGUAGES[path.posix.extname(filename).toLowerCase()] || null;
}

async function readSource(stream, filename, language, budget) {
    const chunks = [];
    let size = 0;
    for await (const chunk of stream) {
        size += chunk.length;
        budget.bytes += chunk.length;
        if (size > MAX_SOURCE_BYTES || budget.bytes > MAX_TOTAL_BYTES) {
            throw processingError('Source contents exceed the processing size limit.', 413);
        }
        chunks.push(chunk);
    }

    const buffer = Buffer.concat(chunks, size);
    // Skip binary files and invalid UTF-8 rather than sending corrupted text to reviewers.
    if (buffer.includes(0)) return null;
    let content;
    try {
        content = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    } catch {
        return null;
    }
    return { path: filename, language, content };
}

function readZip(uploadPath) {
    // Install yauzl as a runtime dependency when wiring the backend.
    const yauzl = require('yauzl');
    return new Promise((resolve, reject) => {
        yauzl.open(uploadPath, { lazyEntries: true, validateEntrySizes: true }, (error, zip) => {
            if (error) {
                reject(processingError(`Unable to open ZIP: ${error.message}`));
                return;
            }

            const files = [];
            const seenPaths = new Set();
            const budget = { bytes: 0 };
            let entries = 0;
            let settled = false;
            let activeStream;

            function fail(error) {
                if (settled) return;
                settled = true;
                if (activeStream) activeStream.destroy();
                zip.close();
                reject(error.statusCode ? error : processingError(`Unable to read ZIP: ${error.message}`));
            }

            zip.on('error', fail);
            zip.on('end', () => {
                if (settled) return;
                settled = true;
                files.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
                resolve(files);
            });
            zip.on('entry', entry => {
                if (settled) return;
                try {
                    if (++entries > MAX_ZIP_ENTRIES) {
                        throw processingError('ZIP contains too many entries.', 413);
                    }
                    const filename = normalizePath(entry.fileName);
                    const fileType = (entry.externalFileAttributes >>> 16) & 0xf000;
                    const language = sourceLanguage(filename);
                    // Never follow symbolic links or process directories / special files.
                    if (filename.endsWith('/') || (entry.externalFileAttributes & 0x10)
                        || (fileType !== 0 && fileType !== 0x8000) || !language) {
                        zip.readEntry();
                        return;
                    }
                    if (seenPaths.has(filename)) {
                        throw processingError(`ZIP contains a duplicate source path: ${filename}`);
                    }
                    seenPaths.add(filename);
                    if (entry.generalPurposeBitFlag & 1) {
                        throw processingError('Encrypted source files are not supported.');
                    }
                    if (entry.uncompressedSize > MAX_SOURCE_BYTES
                        || entry.uncompressedSize > MAX_TOTAL_BYTES - budget.bytes) {
                        throw processingError('Source contents exceed the processing size limit.', 413);
                    }

                    zip.openReadStream(entry, (error, stream) => {
                        if (settled) {
                            if (stream) stream.destroy();
                            return;
                        }
                        if (error) {
                            fail(error);
                            return;
                        }
                        activeStream = stream;
                        readSource(stream, filename, language, budget).then(source => {
                            activeStream = null;
                            if (settled) return;
                            if (source) files.push(source);
                            zip.readEntry();
                        }).catch(fail);
                    });
                } catch (error) {
                    fail(error);
                }
            });
            zip.readEntry();
        });
    });
}

/**
 * Convert a normalized disk-backed upload into { path, language, content }[].
 * ZIP entries are decompressed in memory, preserving their archive-relative paths.
 * Content is UTF-8; ignored directories, unsupported files, and binary data are skipped.
 * No uploaded code is executed, and no extracted files are written to disk.
 */
async function processFile(upload) {
    if (!upload || typeof upload.path !== 'string' || !upload.path.trim()
        || upload.path.includes('\0') || !['zip', 'code'].includes(upload.type)) {
        throw processingError('Provide a valid upload path and type (zip or code).');
    }
    const originalName = normalizePath(upload.originalName);
    let stats;
    try {
        stats = await fs.promises.stat(upload.path);
    } catch (error) {
        if (error.code === 'ENOENT') throw processingError('The uploaded file was not found.', 404);
        throw error;
    }
    if (!stats.isFile()) throw processingError('The upload path must point to a file.');
    if (stats.size > MAX_UPLOAD_BYTES) throw processingError('The upload exceeds the 50 MB limit.', 413);

    if (upload.type === 'zip') return readZip(upload.path);

    const language = sourceLanguage(originalName);
    if (!language) return [];
    if (stats.size > MAX_SOURCE_BYTES) throw processingError('Source file exceeds the 5 MB limit.', 413);
    const source = await readSource(fs.createReadStream(upload.path), originalName, language, { bytes: 0 });
    return source ? [source] : [];
}

module.exports = processFile;
