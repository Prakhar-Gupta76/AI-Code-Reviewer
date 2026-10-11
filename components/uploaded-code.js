const path = require('node:path');

const MAX_UPLOAD_SIZE = 50 * 1024 * 1024; // 50 MB
const CODE_EXTENSIONS = new Set([
    '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx',
    '.py', '.java', '.c', '.h', '.cpp', '.hpp', '.cc', '.cs',
    '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.kts',
    '.scala', '.sh', '.bash', '.ps1', '.sql', '.html', '.css',
    '.scss', '.sass', '.vue', '.svelte', '.dart', '.r', '.lua',
]);

function uploadError(message, statusCode) {
    const error = new Error(message);
    error.status = statusCode;
    error.statusCode = statusCode;
    return error;
}

/**
 * Accept a disk-backed Multer upload from req.file and return the File
 * Processor's result. The caller handles the HTTP response and any errors.
 * file-processor.js must export a function accepting { path, originalName, type }.
 * Multer should also enforce the 10 MB limit while receiving the upload.
 */
async function uploadedCode(req) {
    const file = req && req.file;

    if (!file || typeof file !== 'object') {
        throw uploadError('Upload a ZIP archive or a code file.', 400);
    }

    if (typeof file.originalname !== 'string' || !file.originalname.trim()
        || /[\x00-\x1f\x7f]/.test(file.originalname)) {
        throw uploadError('The uploaded file must have a valid filename.', 400);
    }

    // Strip client-supplied directory names on either Windows or Unix.
    const originalName = path.posix.basename(file.originalname.replace(/\\/g, '/'));
    if (!originalName || originalName === '.' || originalName === '..') {
        throw uploadError('The uploaded file must have a valid filename.', 400);
    }

    if (typeof file.path !== 'string' || !file.path.trim() || file.path.includes('\0')) {
        throw uploadError('The upload must be saved to disk before processing.', 400);
    }

    if (!Number.isSafeInteger(file.size) || file.size <= 0) {
        throw uploadError('The uploaded file must contain data and have a valid size.', 400);
    }

    if (file.size > MAX_UPLOAD_SIZE) {
        throw uploadError('The uploaded file exceeds the 10 MB limit.', 413);
    }

    const extension = path.extname(originalName).toLowerCase();
    const type = extension === '.zip' ? 'zip' : 'code';
    if (type === 'code' && !CODE_EXTENSIONS.has(extension)) {
        throw uploadError('Unsupported file type. Upload a ZIP archive or a supported code file.', 415);
    }

    // Load only after validation; the next component can be implemented separately.
    // Extensions classify uploads; the File Processor must validate archive contents.
    const processFile = require('./file-processor');
    return processFile({ path: file.path, originalName, type });
}

module.exports = uploadedCode;
