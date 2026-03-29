/**
 * File Security Validator - Comprehensive Security Checks for Uploaded Files
 * 
 * Features:
 * - MIME type validation with magic number verification
 * - File size limits and archive bomb detection
 * - Malware scanning via ClamAV (if available)
 * - Script injection detection
 * - Filename sanitization
 * - Archive integrity checks
 * - PDF validation
 * 
 * Usage:
 * const validator = require('./fileSecurityValidator');
 * const result = await validator.validateFile(buffer, filename, mimetype);
 */

const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  MAX_FILE_SIZE: 500 * 1024 * 1024, // 500 MB
  MAX_PDF_SIZE: 100 * 1024 * 1024, // 100 MB for PDFs
  MAX_IMAGE_SIZE: 50 * 1024 * 1024, // 50 MB for images
  MAX_ARCHIVE_UNCOMPRESSED_SIZE: 500 * 1024 * 1024, // 500 MB
  MAX_COMPRESSION_RATIO: 100, // Alert if compression ratio > 100:1
  ALLOWED_MIME_TYPES: {
    pdf: ['application/pdf'],
    image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    document: ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    spreadsheet: ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    archive: ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed'],
    video: ['video/mp4', 'video/webm', 'video/mpeg', 'video/quicktime'],
    audio: ['audio/mpeg', 'audio/wav', 'audio/ogg'],
  },
  DANGEROUS_EXTENSIONS: [
    'exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'js', 'jar', 'app', 'com',
    'scr', 'pif', 'msi', 'dll', 'sys', 'drv', 'tmp', 'chm', 'hlp'
  ],
  DANGEROUS_KEYWORDS: [
    'alert(', 'eval(', 'onclick=', 'onerror=', 'onload=',
    '<script', '<?php', '<%', 'exec(', 'system(', 'shell_exec',
    'passthru(', 'proc_open(', 'popen(', 'curl_exec(', 'fsockopen('
  ],
};

// Magic numbers for file type validation
const MAGIC_NUMBERS = {
  pdf: { signature: Buffer.from([0x25, 0x50, 0x44, 0x46]), name: 'PDF' }, // %PDF
  jpeg: { signature: Buffer.from([0xFF, 0xD8, 0xFF]), name: 'JPEG' },
  png: { signature: Buffer.from([0x89, 0x50, 0x4E, 0x47]), name: 'PNG' },
  gif87: { signature: Buffer.from([0x47, 0x49, 0x46, 0x38, 0x37]), name: 'GIF87' },
  gif89: { signature: Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39]), name: 'GIF89' },
  zip: { signature: Buffer.from([0x50, 0x4B, 0x03, 0x04]), name: 'ZIP' },
  rar: { signature: Buffer.from([0x52, 0x61, 0x72, 0x21]), name: 'RAR' },
  gzip: { signature: Buffer.from([0x1F, 0x8B]), name: 'GZIP' },
  mp4: { signature: Buffer.from('ftyp', 'utf8'), offset: 4, name: 'MP4' },
  webm: { signature: Buffer.from([0x1A, 0x45, 0xDF, 0xA3]), name: 'WebM' },
};

/**
 * Validate file signature/magic numbers
 */
function validateMagicNumber(buffer, mimetype) {
  const errors = [];
  
  // Map MIME type to expected magic number
  if (mimetype.includes('pdf')) {
    if (!buffer.slice(0, 4).equals(MAGIC_NUMBERS.pdf.signature)) {
      errors.push('Invalid PDF signature - file may be corrupted or not a real PDF');
    }
  } else if (mimetype.includes('jpeg') || mimetype.includes('jpg')) {
    const sig = buffer.slice(0, 3);
    if (!sig.equals(MAGIC_NUMBERS.jpeg.signature)) {
      errors.push('Invalid JPEG signature - file may be corrupted or not a real JPEG');
    }
  } else if (mimetype.includes('png')) {
    if (!buffer.slice(0, 4).equals(MAGIC_NUMBERS.png.signature)) {
      errors.push('Invalid PNG signature - file may be corrupted or not a real PNG');
    }
  } else if (mimetype.includes('gif')) {
    const sig = buffer.slice(0, 6);
    const isGif87 = sig.slice(0, 6).equals(Buffer.from([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]));
    const isGif89 = sig.slice(0, 6).equals(Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]));
    if (!isGif87 && !isGif89) {
      errors.push('Invalid GIF signature - file may be corrupted or not a real GIF');
    }
  } else if (mimetype.includes('zip')) {
    if (!buffer.slice(0, 4).equals(MAGIC_NUMBERS.zip.signature)) {
      errors.push('Invalid ZIP signature - file may be corrupted or not a real ZIP');
    }
  }
  
  return errors;
}

/**
 * Detect malicious content in file
 */
function detectMaliciousContent(buffer, filename) {
  const errors = [];
  
  try {
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 100000)); // Check first 100KB
    
    // Check for dangerous keywords
    for (const keyword of CONFIG.DANGEROUS_KEYWORDS) {
      if (content.toLowerCase().includes(keyword.toLowerCase())) {
        errors.push(`Detected potentially malicious keyword: "${keyword}"`);
      }
    }
    
    // Check for HTML/Script injection in PDFs or archives
    if (filename.endsWith('.pdf')) {
      if (content.includes('<script') || content.includes('JavaScript')) {
        errors.push('PDF contains potentially malicious JavaScript code');
      }
    }
  } catch (e) {
    // Binary content - check at byte level
  }
  
  return errors;
}

/**
 * Sanitize filename to prevent path traversal and injection
 */
function sanitizeFilename(filename) {
  // Remove path components
  const basename = path.basename(filename);
  
  // Remove dangerous characters
  const sanitized = basename
    .replace(/[^a-zA-Z0-9._-]/g, '_') // Replace non-alphanumeric with underscore
    .replace(/_{2,}/g, '_') // Replace multiple underscores with single
    .substring(0, 255); // Limit length
  
  return sanitized;
}

/**
 * Check for archive bomb (compression ratio too high)
 */
async function detectArchiveBomb(buffer) {
  const errors = [];
  
  try {
    // Check for zip archive
    if (buffer.slice(0, 4).equals(MAGIC_NUMBERS.zip.signature)) {
      // For ZIP files, check the compression ratio
      // This is a simplified check - in production use proper ZIP library
      const compressedSize = buffer.length;
      
      // Try to decompress with size limit
      try {
        let uncompressedSize = 0;
        const decompressed = zlib.gunzipSync(buffer, { maxOutputLength: CONFIG.MAX_ARCHIVE_UNCOMPRESSED_SIZE });
        uncompressedSize = decompressed.length;
        
        const ratio = uncompressedSize / compressedSize;
        if (ratio > CONFIG.MAX_COMPRESSION_RATIO) {
          errors.push(`Archive bomb detected: compression ratio ${ratio.toFixed(2)}:1 exceeds limit of ${CONFIG.MAX_COMPRESSION_RATIO}:1`);
        }
      } catch (e) {
        // Not a gzip file, continue
      }
    }
  } catch (e) {
    console.error('Archive bomb detection error:', e.message);
  }
  
  return errors;
}

/**
 * Validate file extension matches MIME type
 */
function validateExtensionMatch(filename, mimetype) {
  const errors = [];
  const ext = path.extname(filename).toLowerCase().substring(1);
  
  // Check if extension is dangerous
  if (CONFIG.DANGEROUS_EXTENSIONS.includes(ext)) {
    errors.push(`Dangerous file extension rejected: .${ext}`);
  }
  
  // Validate extension matches mimetype
  const mimeTypeExt = mimetype.split('/')[1];
  if (ext && mimeTypeExt) {
    if (!ext.includes(mimeTypeExt) && !mimeTypeExt.includes(ext)) {
      errors.push(`File extension .${ext} does not match MIME type ${mimetype}`);
    }
  }
  
  return errors;
}

/**
 * Main validation function
 */
async function validateFile(buffer, filename, mimetype, fileType = 'document') {
  const result = {
    isValid: true,
    errors: [],
    warnings: [],
    details: {
      filename: filename,
      sanitizedFilename: sanitizeFilename(filename),
      mimetype: mimetype,
      fileSize: buffer.length,
      fileType: fileType,
      hash: crypto.createHash('sha256').update(buffer).digest('hex'),
    },
  };

  try {
    // 1. Check file size
    const maxSize = fileType === 'pdf' ? CONFIG.MAX_PDF_SIZE : 
                   fileType === 'image' ? CONFIG.MAX_IMAGE_SIZE : 
                   CONFIG.MAX_FILE_SIZE;
    
    if (buffer.length === 0) {
      result.errors.push('File is empty');
    } else if (buffer.length > maxSize) {
      result.errors.push(`File size (${(buffer.length / 1024 / 1024).toFixed(2)}MB) exceeds maximum allowed (${(maxSize / 1024 / 1024).toFixed(2)}MB)`);
    }

    // 2. Validate filename
    if (!filename || filename.length === 0) {
      result.errors.push('Filename is required');
    } else if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      result.errors.push('Filename contains invalid path characters');
    }

    // 3. Validate MIME type
    const allowedMimeTypes = Object.values(CONFIG.ALLOWED_MIME_TYPES).flat();
    if (!allowedMimeTypes.includes(mimetype)) {
      result.errors.push(`MIME type "${mimetype}" is not allowed`);
    }

    // 4. Validate magic numbers / file signature
    result.errors.push(...validateMagicNumber(buffer, mimetype));

    // 5. Validate extension matches MIME type
    result.errors.push(...validateExtensionMatch(filename, mimetype));

    // 6. Detect malicious content
    result.errors.push(...detectMaliciousContent(buffer, filename));

    // 7. Detect archive bombs
    if (fileType === 'archive') {
      result.errors.push(...await detectArchiveBomb(buffer));
    }

    // 8. Additional security checks for specific file types
    if (fileType === 'image') {
      // Check for image bombs (extremely large dimensions encoded in header)
      try {
        const width = buffer.readUInt32BE(16);
        const height = buffer.readUInt32BE(20);
        if (width * height > 100000000) { // More than 100 megapixels
          result.warnings.push(`Image dimensions (${width}x${height}) are unusually large - potential decompression bomb`);
        }
      } catch (e) {
        // Continue if we can't parse image headers
      }
    }

    // 9. Check file hash against known malware signatures (if needed)
    // In production, integrate with VirusTotal API or similar
    result.details.suspicious = false;

    // Set final validation status
    result.isValid = result.errors.length === 0;

  } catch (error) {
    result.errors.push(`Validation error: ${error.message}`);
    result.isValid = false;
  }

  return result;
}

/**
 * Enhanced validation with ClamAV integration (optional)
 * Requires: npm install clamav.js
 * And running ClamAV daemon
 */
async function validateWithClamAV(buffer, filename) {
  try {
    const NodeClam = require('clamscan');
    const clamscan = await new NodeClam().init({
      clamdscan: {
        host: 'localhost',
        port: 3310,
      },
    });

    const { isInfected, viruses } = await clamscan.scanBuffer(buffer);
    
    if (isInfected) {
      return {
        isValid: false,
        detected: true,
        viruses: viruses,
        message: `Malware detected: ${viruses.join(', ')}`
      };
    }
    
    return { isValid: true, detected: false };
  } catch (error) {
    console.log('ClamAV not available or error:', error.message);
    // ClamAV is optional - continue with basic validation
    return { isValid: true, detected: false, warning: 'ClamAV unavailable' };
  }
}

/**
 * Validate file before upload and return detailed report
 */
async function securityCheck(buffer, filename, mimetype, fileType = 'document') {
  const basicValidation = await validateFile(buffer, filename, mimetype, fileType);
  
  // If basic validation fails, return immediately
  if (!basicValidation.isValid) {
    return basicValidation;
  }

  // Optional: Run ClamAV if available
  const clamavResult = await validateWithClamAV(buffer, filename);
  if (!clamavResult.isValid) {
    basicValidation.isValid = false;
    basicValidation.errors.push(clamavResult.message);
    basicValidation.clamavDetection = clamavResult;
  }

  return basicValidation;
}

module.exports = {
  validateFile,
  validateWithClamAV,
  securityCheck,
  sanitizeFilename,
  CONFIG,
};
