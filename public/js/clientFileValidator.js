/**
 * Client-Side File Security Validator
 * Validates files before upload to provide immediate feedback to users
 * 
 * Usage:
 * const validator = new ClientFileValidator();
 * const result = await validator.validateFile(file);
 */

class ClientFileValidator {
  constructor() {
    this.CONFIG = {
      MAX_FILE_SIZE: 500 * 1024 * 1024, // 500 MB
      MAX_PDF_SIZE: 100 * 1024 * 1024, // 100 MB for PDFs
      MAX_IMAGE_SIZE: 50 * 1024 * 1024, // 50 MB for images
      ALLOWED_MIME_TYPES: {
        image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        file: ['application/pdf', 'application/zip', 'application/x-rar-compressed', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'video/mp4', 'video/webm'],
      },ss
      DANGEROUS_EXTENSIONS: [
        'exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'js', 'jar', 'app', 'com',
        'scr', 'pif', 'msi', 'dll', 'sys', 'drv', 'tmp', 'chm', 'hlp'
      ],
      ALLOWED_EXTENSIONS: {
        image: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        file: ['pdf', 'zip', 'rar', '7z', 'ppt', 'pptx', 'doc', 'docx', 'xls', 'xlsx', 'mp4', 'webm'],
      }
    };
    
    this.MAGIC_NUMBERS = {
      pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]), // %PDF
      jpeg: new Uint8Array([0xFF, 0xD8, 0xFF]),
      png: new Uint8Array([0x89, 0x50, 0x4E, 0x47]),
      gif: new Uint8Array([0x47, 0x49, 0x46, 0x38]),
      zip: new Uint8Array([0x50, 0x4B, 0x03, 0x04]),
    };
  }

  /**
   * Main validation function
   */
  async validateFile(file, fileType = 'file') {
    const result = {
      isValid: true,
      errors: [],
      warnings: [],
      details: {
        filename: file.name,
        fileSize: file.size,
        fileType: fileType,
        mimeType: file.type,
      },
    };

    try {
      // 1. Check file size
      const maxSize = fileType === 'image' ? this.CONFIG.MAX_IMAGE_SIZE : this.CONFIG.MAX_FILE_SIZE;
      if (file.size === 0) {
        result.errors.push('File is empty');
      } else if (file.size > maxSize) {
        result.errors.push(`File size (${this.formatBytes(file.size)}) exceeds maximum allowed (${this.formatBytes(maxSize)})`);
      }

      // 2. Validate filename
      if (!file.name || file.name.length === 0) {
        result.errors.push('Filename is required');
      } else if (file.name.includes('..') || file.name.includes('/') || file.name.includes('\\')) {
        result.errors.push('Filename contains invalid path characters');
      }

      // 3. Get and validate extension
      const ext = this.getExtension(file.name).toLowerCase();
      if (this.CONFIG.DANGEROUS_EXTENSIONS.includes(ext)) {
        result.errors.push(`Dangerous file extension rejected: .${ext}`);
      }

      // 4. Check allowed extensions for file type
      const allowedExts = fileType === 'image' ? this.CONFIG.ALLOWED_EXTENSIONS.image : this.CONFIG.ALLOWED_EXTENSIONS.file;
      if (ext && !allowedExts.includes(ext)) {
        result.errors.push(`File extension .${ext} is not allowed for ${fileType} uploads`);
      }

      // 5. Validate MIME type
      const allowedMimes = fileType === 'image' ? this.CONFIG.ALLOWED_MIME_TYPES.image : this.CONFIG.ALLOWED_MIME_TYPES.file;
      if (file.type && !allowedMimes.includes(file.type)) {
        result.errors.push(`MIME type "${file.type}" is not allowed`);
      }

      // 6. Check magic numbers (first few bytes)
      if (file.size > 4) {
        const header = await this.getFileHeader(file, 16);
        const magicResult = this.validateMagicNumber(header, file.type, ext);
        result.errors.push(...magicResult.errors);
        result.warnings.push(...magicResult.warnings);
      }

      // Set final validation status
      result.isValid = result.errors.length === 0;

    } catch (error) {
      result.errors.push(`Validation error: ${error.message}`);
      result.isValid = false;
    }

    return result;
  }

  /**
   * Get first N bytes of file as buffer
   */
  getFileHeader(file, bytes = 16) {
    return new Promise((resolve, reject) => {
      const blob = file.slice(0, bytes);
      const reader = new FileReader();
      reader.onload = (e) => {
        const arr = new Uint8Array(e.target.result);
        resolve(arr);
      };
      reader.onerror = () => reject(new Error('Could not read file'));
      reader.readAsArrayBuffer(blob);
    });
  }

  /**
   * Validate file magic numbers
   */
  validateMagicNumber(header, mimetype, ext) {
    const errors = [];
    const warnings = [];

    // Check based on MIME type
    if (mimetype.includes('pdf') || ext === 'pdf') {
      if (!this.arrayStartsWith(header, this.MAGIC_NUMBERS.pdf)) {
        errors.push('Invalid PDF signature - file may be corrupted or not a real PDF');
      }
    } else if (mimetype.includes('jpeg') || mimetype.includes('jpg') || ext === 'jpg' || ext === 'jpeg') {
      if (!this.arrayStartsWith(header, this.MAGIC_NUMBERS.jpeg)) {
        errors.push('Invalid JPEG signature - file may be corrupted or not a real JPEG');
      }
    } else if (mimetype.includes('png') || ext === 'png') {
      if (!this.arrayStartsWith(header, this.MAGIC_NUMBERS.png)) {
        errors.push('Invalid PNG signature - file may be corrupted or not a real PNG');
      }
    } else if (mimetype.includes('gif') || ext === 'gif') {
      if (!this.arrayStartsWith(header, this.MAGIC_NUMBERS.gif)) {
        errors.push('Invalid GIF signature - file may be corrupted or not a real GIF');
      }
    } else if (mimetype.includes('zip') || ext === 'zip') {
      if (!this.arrayStartsWith(header, this.MAGIC_NUMBERS.zip)) {
        warnings.push('ZIP signature not detected - may not be a real ZIP file');
      }
    }

    return { errors, warnings };
  }

  /**
   * Check if byte array starts with prefix array
   */
  arrayStartsWith(src, prefix) {
    if (!src || !prefix || src.length < prefix.length) return false;
    for (let i = 0; i < prefix.length; i++) {
      if (src[i] !== prefix[i]) return false;
    }
    return true;
  }

  /**
   * Get file extension
   */
  getExtension(filename) {
    const parts = filename.split('.');
    return parts.length > 1 ? parts[parts.length - 1] : '';
  }

  /**
   * Format bytes to human readable
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }
}

// Create global instance and expose it
window.fileValidator = new ClientFileValidator();
window.ClientFileValidator = ClientFileValidator;
