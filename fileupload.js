// =================================================================
//     S3 Multipart Upload Backend - Custom Naming Logic
// =================================================================

// --- Imports ---
const {
    S3Client,
    CreateMultipartUploadCommand,
    UploadPartCommand,
    CompleteMultipartUploadCommand,
    AbortMultipartUploadCommand
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { getSignedUrl: getCloudFrontSignedUrl } = require('@aws-sdk/cloudfront-signer');
const { PDFDocument } = require('pdf-lib');
const cors = require('cors');
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const File = require("./models/file");
const fileSecurityValidator = require('./services/fileSecurityValidator');
const authenticateJWT_user  = require('./routes/authentication/jwtAuth'); // Assuming path is correct
const requireAuth = require('./routes/authentication/reaquireAuth'); // Assuming path is correct
const Categories=require("./models/categories")
const router = express.Router();
const Coupon=require("./models/couponschema.js");
const User = require("./models/userData");
const { sendNotification } = require("./test.js");

// --- Configuration ---
const IMAGE_BUCKET = process.env.S3_IMAGE_BUCKET || 'vidyari3';
const MAIN_FILE_BUCKET = process.env.S3_MAIN_FILE_BUCKET || 'vidyarimain2';
const REGION = process.env.AWS_REGION || 'ap-south-1';
const URL_EXPIRATION_SECONDS = 21600;
const CF_DOMAIN_DOWNLOADS = process.env.CF_DOMAIN_DOWNLOADS || 'd2q25uqlym20sh.cloudfront.net';
const CLOUDFRONT_DOWNLOAD_KEY_PAIR_ID = process.env.CLOUDFRONT_KEY_PAIR_ID || process.env.CLOUDFRONT_KEYPAIR_ID;
const CLOUDFRONT_PRIVATE_KEY_PATH = path.join(__dirname, 'private_keys', 'cloudfront-private-key.pem');
let CLOUDFRONT_PRIVATE_KEY = null;
try {
    CLOUDFRONT_PRIVATE_KEY = fs.readFileSync(CLOUDFRONT_PRIVATE_KEY_PATH, 'utf8');
} catch (err) {
    console.warn('CloudFront private key not found at', CLOUDFRONT_PRIVATE_KEY_PATH);
}

function buildCloudFrontSignedUrl(fileKey, ttlSeconds = 3600) {
    if (!fileKey) {
        throw new Error('Missing CloudFront file key');
    }
    if (!CLOUDFRONT_DOWNLOAD_KEY_PAIR_ID || !CLOUDFRONT_PRIVATE_KEY) {
        throw new Error('CloudFront signing configuration is missing');
    }

    const cleanedDomain = String(CF_DOMAIN_DOWNLOADS).replace(/^https?:\/\//, '').replace(/\/+$/, '');
    let cleanKey = String(fileKey).trim();
    try {
        const parsed = new URL(cleanKey);
        cleanKey = parsed.pathname.replace(/^\/+/, '');
    } catch (e) {
        cleanKey = cleanKey.replace(/^\/+/, '');
    }

    const encodedKey = encodeURIComponent(cleanKey).replace(/%2F/g, '/');
    const unsignedUrl = `https://${cleanedDomain}/${encodedKey}`;

    return getCloudFrontSignedUrl({
        url: unsignedUrl,
        keyPairId: CLOUDFRONT_DOWNLOAD_KEY_PAIR_ID,
        privateKey: CLOUDFRONT_PRIVATE_KEY,
        dateLessThan: new Date(Date.now() + ttlSeconds * 1000),
    });
}

// --- S3 Client ---
const s3Client = new S3Client({
    region: REGION,
    useAccelerateEndpoint: false
});

// --- Middleware ---
router.use(cors({ origin: '*' }));
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

// =================================================================
//                         Helper Functions
// =================================================================
const getS3Params = (fileType, originalFileName, fileId) => {
    let fileExtension = path.extname(originalFileName).toLowerCase();

    if (fileType === 'image') {
        // normalise JPEG variants to .jpg so we have a single canonical key
        if (fileExtension === '.jpeg') fileExtension = '.jpg';

        const generatedFileName = `${fileId}${fileExtension}`;
        return {
            bucket: IMAGE_BUCKET,
            key: `files-previews/images/${generatedFileName}`,
            generatedFileName: generatedFileName
        };
    } 
    
    if (fileType === 'main') {
        const baseName = path.basename(originalFileName, fileExtension);
        const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
        const generatedFileName = `${baseName}-${uniqueSuffix}${fileExtension}`;
        return {
            bucket: MAIN_FILE_BUCKET,
            key: `main-files/${generatedFileName}`,
            generatedFileName: generatedFileName // Return just the filename part
        };
    }
    
    if (fileType === 'sample') {
        const generatedFileName = `sample-${fileId}-${Date.now()}${fileExtension}`;
        return {
            bucket: MAIN_FILE_BUCKET,
            key: `sample-files/${generatedFileName}`,
            generatedFileName: generatedFileName
        };
    }
    
    throw new Error('Invalid fileType specified. Must be "image", "main", or "sample".');
};


// =================================================================
//                         API Routes
// =================================================================

// --- STEP 1: Start Upload ---
router.post('/start-multipart-upload', authenticateJWT_user, async (req, res) => {
    const { fileName, contentType, fileType, fileId } = req.body;
    if (!fileName || !contentType || !fileType || !fileId) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    try {
        console.log(`\n🔒 SECURITY CHECK: Validating upload initiation`);
        console.log(`📄 File: ${fileName} | Type: ${fileType} | MIME: ${contentType}`);
        
        // --- SERVER-SIDE VALIDATION (Quick Checks) ---
        // 1. Check filename for dangerous content
        const fileExt = path.extname(fileName).toLowerCase().substring(1);
        const DANGEROUS_EXTENSIONS = ['exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'js', 'jar', 'app', 'com', 'scr', 'pif', 'msi', 'dll', 'sys', 'drv'];
        
        if (DANGEROUS_EXTENSIONS.includes(fileExt)) {
            console.error(`❌ BLOCKED: Dangerous extension .${fileExt}`);
            return res.status(400).json({ 
                error: 'Security validation failed',
                reason: `Dangerous file extension rejected: .${fileExt}`,
                status: 'BLOCKED'
            });
        }
        
        // 2. Validate MIME type matches file type
        const allowedImageMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        const allowedFileMimes = ['application/pdf', 'application/zip', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'video/mp4', 'video/webm'];
        const allowedMimes = fileType === 'image' ? allowedImageMimes : allowedFileMimes;
        
        if (!allowedMimes.includes(contentType)) {
            console.error(`❌ BLOCKED: Invalid MIME type ${contentType} for ${fileType}`);
            return res.status(400).json({
                error: 'Security validation failed',
                reason: `MIME type "${contentType}" is not allowed`,
                status: 'BLOCKED'
            });
        }
        
        console.log(`✅ Initial validation passed - proceeding with upload`);
        
        const { bucket, key, generatedFileName } = getS3Params(fileType, fileName, fileId);

        const command = new CreateMultipartUploadCommand({
            Bucket: bucket,
            Key: key,
            ContentType: contentType,
            Metadata: {
                'original-filename': fileName,
                'file-type': fileType,
                'upload-initiated': new Date().toISOString()
            }
        });
        
        const { UploadId } = await s3Client.send(command);
        
        // Return the full key for subsequent requests, AND the final filename for the DB
        res.json({ uploadId: UploadId, key: key, generatedFileName: generatedFileName });

    } catch (err) {
        console.error('❌ Error initiating multipart upload:', err);
        res.status(500).json({ error: 'Could not initiate multipart upload.' });
    }
});

// --- STEP 2: Get Presigned URL ---
router.get('/get-presigned-part-url', authenticateJWT_user, async (req, res) => {
    const { key, uploadId, partNumber, fileType } = req.query;
    if (!key || !uploadId || !partNumber || !fileType) {
        return res.status(400).json({ error: 'Missing required query parameters.' });
    }

    const bucket = fileType === 'image' ? IMAGE_BUCKET : MAIN_FILE_BUCKET;

    const command = new UploadPartCommand({
        Bucket: bucket,
        Key: key,
        UploadId: uploadId,
        PartNumber: parseInt(partNumber, 10),
    });

    try {
        const presignedUrl = await getSignedUrl(s3Client, command, { expiresIn: URL_EXPIRATION_SECONDS });
        res.json({ url: presignedUrl });
    } catch (err) {
        console.error('Error getting presigned URL for part:', err);
        res.status(500).json({ error: 'Could not get presigned URL.' });
    }
});

// --- STEP 3: Complete Upload ---
router.post('/complete-multipart-upload', authenticateJWT_user, async (req, res) => {
    const { key, uploadId, parts, fileType, fileId, generatedFileName, fileSize } = req.body;
    if (!key || !uploadId || !Array.isArray(parts) || !fileType || !fileId || !generatedFileName) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    const bucket = fileType === 'image' ? IMAGE_BUCKET : MAIN_FILE_BUCKET;
    const sortedParts = [...parts].sort((a, b) => a.PartNumber - b.PartNumber);

    console.log(`\n🔒 SECURITY CHECK: Completing multipart upload`);
    console.log(`📄 File: ${generatedFileName} | Size: ${fileSize} bytes | Type: ${fileType}`);
    
    // Final size validation
    const MAX_IMAGE_SIZE = 50 * 1024 * 1024; // 50 MB
    const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500 MB
    const MAX_SAMPLE_SIZE = 100 * 1024 * 1024; // 100 MB
    const maxSize = fileType === 'image' ? MAX_IMAGE_SIZE : fileType === 'sample' ? MAX_SAMPLE_SIZE : MAX_FILE_SIZE;
    
    if (fileSize > maxSize) {
        console.error(`❌ BLOCKED: File exceeds size limit`);
        return res.status(400).json({
            error: 'File size validation failed',
            reason: `File size (${(fileSize / 1024 / 1024).toFixed(2)}MB) exceeds maximum (${(maxSize / 1024 / 1024).toFixed(2)}MB)`,
            status: 'REJECTED'
        });
    }

    const command = new CompleteMultipartUploadCommand({
        Bucket: bucket, Key: key, UploadId: uploadId, MultipartUpload: { Parts: sortedParts },
    });

    try {
        const result = await s3Client.send(command);
        const fullS3Url = result.Location || `https://${bucket}.s3.${REGION}.amazonaws.com/${key}`;
        
        console.log(`✅ Upload completed successfully on S3`);
        
        // --- DATABASE LOGIC (Updated as per your request) ---
        const updatePayload = {
            securityValidated: true,
            validationTimestamp: new Date(),
        };
        
        if (fileType === 'image') {
            // For images, save the full S3 URL and the filename (the object ID)
            updatePayload.imageUrl = fullS3Url;
            updatePayload.imageName = generatedFileName; // e.g., "6511a...a1b.jpg"

            // ---- new: persist imageType so we don't have to probe S3 later ----
            // extension comes from the generated filename (includes leading dot)
            const ext = path.extname(generatedFileName).slice(1).toLowerCase();
            // normalise jpeg/jpg etc
            updatePayload.imageType = ext === "jpeg" ? "jpeg" : ext === "jpg" ? "jpg" : ext;
        } else if (fileType === 'main') {
            // For the main file, save ONLY the generated name to fileUrl
            updatePayload.fileUrl = generatedFileName; // e.g., "my-doc-175...-d7f3.pdf"
            updatePayload.storedFilename = key; // e.g., "main-files/my-doc-175...-d7f3.pdf"
            updatePayload.fileSize = fileSize;
        } else if (fileType === 'sample') {
            // For sample PDF, save the generated name and store path
            updatePayload.samplePdfUrl = generatedFileName;
            updatePayload.samplePdfStoredFilename = key; // e.g., "sample-files/sample-abc123-1234567890.pdf"
            updatePayload.samplePdfSize = fileSize;
        }

        const updatedFile = await File.findByIdAndUpdate(fileId, updatePayload, { new: true });
        if (!updatedFile) {
            return res.status(404).json({ error: 'File record not found in database.' });
        }
        
        console.log(`✅ Database updated with security metadata`);
        console.log(`✅ FILE UPLOAD COMPLETE - All validations passed`);
        console.log(`📊 Final: ${fileType} | Size: ${(fileSize / 1024 / 1024).toFixed(2)}MB | Validated: YES\n`);
        
        res.json({ 
            message: 'Upload completed successfully!',
            security: {
                validated: true,
                fileSize: fileSize,
                fileType: fileType
            }
        });

    } catch (err) {
        console.error('❌ Error completing multipart upload:', err);
        res.status(500).json({ error: 'Could not complete multipart upload.' });
    }
});


// --- STEP 4: Abort Upload ---
router.post('/abort-multipart-upload', authenticateJWT_user, async (req, res) => {
    const { key, uploadId, fileType } = req.body;
    if (!key || !uploadId || !fileType) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }
    const bucket = fileType === 'image' ? IMAGE_BUCKET : MAIN_FILE_BUCKET;
    const command = new AbortMultipartUploadCommand({ Bucket: bucket, Key: key, UploadId: uploadId });
    try {
        await s3Client.send(command);
        res.json({ message: 'Upload aborted successfully.' });
    } catch (err) {
        console.error('Error aborting multipart upload:', err);
        res.status(500).json({ error: 'Could not abort multipart upload.' });
    }
});


// --- Create File Record Route ---
// This route remains the same as it correctly creates the initial document.
// In your backend router file

router.post('/api/create-file-record', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        

        // 1. Extract fileSize along with other data
        const {
            title, descriptionHTML, price, category, fileSize, // <-- get fileSize
            couponCode, couponPercentage,imageType
        } = req.body;
        console.log(req.body)

        if (!title || !descriptionHTML || !price || !category || fileSize === undefined) {
            return res.status(400).json({ error: 'Missing required metadata fields.' });
        }
        
        // 2. ADD THE SERVER-SIDE CHECK
        const MAX_FILE_SIZE_BYTES = 8 * 1024 * 1024 * 1024; // 8 GB
        if (Number(fileSize) > MAX_FILE_SIZE_BYTES) {
            return res.status(400).json({ error: `File size of ${fileSize} bytes exceeds the 8 GB limit.` });
        }
        
        // 3. Map data to your schema (now including fileSize)
        const newFile = new File({
            userId: req.user._id,
            user: req.user.username,
            filename: title,
            filedescription: descriptionHTML,
            price: Number(price),
            category: category,
            fileSize: Number(fileSize), // <-- Save the file size
            couponCode: couponCode || null,
            couponPercentage: couponPercentage ? Number(couponPercentage) : null,
            imageType:imageType
        });
        const coupon=await Coupon.findOne({code:couponCode})
        if(coupon){
            res.status(400).json({error:'Coupon already exists'})
        }
   if (couponPercentage > 0 && couponCode && couponCode.trim() !== '') {
    await Coupon.create({
        userId: req.user._id,
        code: couponCode.trim(),
        discountValue: Number(couponPercentage),
        file: newFile._id,
        expiry: req.body.couponExpiry ? new Date(req.body.couponExpiry) : null
    });
}

        const filecategory=Categories.findOne({name:category})
        if(!filecategory){
           await Categories.create({
            name:category
            })
        }
        
     
        await newFile.save();

        // Send notifications to followers
        try {
            const creator = await User.findById(req.user._id).select('fullName followers');
            if (creator && creator.followers && creator.followers.length > 0) {
                const followerIds = creator.followers.map(f => f.toString());
                const notifications = followerIds.map(userId => 
                    sendNotification({
                        userId,
                        title: `New File by ${creator.fullName || 'Creator'}`,
                        body: `Check out the new file: ${newFile.filename}`,
                        target_link: `/file/${newFile.slug}/${newFile._id}`,
                        notification_type: "file_upload"
                    })
                );
                await Promise.allSettled(notifications);
                console.log(`Sent notifications to ${followerIds.length} followers for file: ${newFile.filename}`);
            }
        } catch (notifError) {
            console.error("Error sending notifications:", notifError);
            // Don't fail the request if notifications fail
        }
        
        res.status(201).json({ fileId: newFile._id });

    } catch (error) {
        console.error('Error creating file record:', error);
        res.status(500).json({ error: 'Could not create file record.' });
    }
});

// --- DELETE File Record (cleanup on upload failure) ---
router.post('/api/cleanup-failed-upload', authenticateJWT_user, async (req, res) => {
  try {
    const { fileId } = req.body;
    if (!fileId) {
      return res.status(400).json({ error: 'Missing fileId' });
    }

    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File record not found' });
    }

    // Verify ownership
    if (file.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Delete the file record from MongoDB
    await File.deleteOne({ _id: fileId });
    console.log(`Cleanup: Deleted failed upload record ${fileId}`);
    
    res.json({ success: true, message: 'Failed upload record cleaned up' });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ error: 'Could not cleanup failed upload' });
  }
});

// --- Extract PDF Pages from Local File (before upload) ---
router.post('/extract-pdf-pages', authenticateJWT_user, async (req, res) => {
  try {
    // This endpoint expects the PDF file to be sent as base64 in the request body
    const { pdfBase64 } = req.body;
    
    if (!pdfBase64) {
      return res.status(400).json({ error: 'PDF file data is required' });
    }

    // Convert base64 to buffer
    const pdfBuffer = Buffer.from(pdfBase64, 'base64');

    // Load PDF document
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    const pageCount = pdfDoc.getPageCount();

    const pages = [];
    for (let i = 0; i < pageCount && i < 20; i++) { // Limit to first 20 pages for performance
      const page = pdfDoc.getPage(i);
      const { width, height } = page.getSize();
      
      pages.push({
        pageNumber: i + 1,
        width: Math.round(width),
        height: Math.round(height)
      });
    }

    res.json({ pages, totalPages: pageCount });

  } catch (error) {
    console.error('Error extracting PDF pages:', error);
    res.status(500).json({ error: 'Failed to extract PDF pages' });
  }
});

// --- Sample Viewer Route ---
router.get('/sample-download/:fileId', authenticateJWT_user, async (req, res) => {
  try {
    const { fileId } = req.params;

    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Check if file has a sample PDF
    if (!file.samplePdfUrl && !file.samplePdfStoredFilename) {
      return res.status(404).json({ error: 'Sample PDF not available for this file' });
    }

    // Check if file is paid (price > 0)
    if (file.price <= 0) {
      return res.status(400).json({ error: 'Sample download is only available for paid files' });
    }

    const sampleKey = file.samplePdfStoredFilename || file.samplePdfUrl;
    const signedUrl = `/sample-proxy/${encodeURIComponent(fileId)}`;

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');

    return res.render('files/pdf-viewer', {
      pdfDataUrl: signedUrl,
      fileName: file.filename ? `Sample - ${file.filename}` : 'Sample Document'
    });

  } catch (error) {
    console.error('Error serving sample PDF viewer:', error);
    res.status(500).json({ error: 'Failed to load sample PDF viewer' });
  }
});

// --- Sample Proxy Route for PDF Viewer ---
router.get('/sample-proxy/:fileId', authenticateJWT_user, async (req, res) => {
  try {
    const { fileId } = req.params;
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    if (!file.samplePdfUrl && !file.samplePdfStoredFilename) {
      return res.status(404).json({ error: 'Sample PDF not available' });
    }

    if (file.price <= 0) {
      return res.status(400).json({ error: 'Sample PDF is only available for paid files' });
    }

    const sampleKey = file.samplePdfStoredFilename || file.samplePdfUrl;
    const signedUrl = buildCloudFrontSignedUrl(sampleKey, 60);
    const parsedUrl = new URL(signedUrl);
    const transport = parsedUrl.protocol === 'https:' ? https : http;

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');

    const proxyOptions = {
      method: req.method,
      headers: {
        ...req.headers,
        host: parsedUrl.host,
      },
    };

    const proxyReq = transport.request(parsedUrl, proxyOptions, cloudRes => {
      const statusCode = cloudRes.statusCode || 502;
      res.writeHead(statusCode, cloudRes.headers);
      cloudRes.pipe(res);
    });

    proxyReq.on('error', err => {
      console.error('Sample proxy request failed:', err);
      if (!res.headersSent) {
        res.status(502).send('Failed to fetch sample PDF');
      }
    });

    req.pipe(proxyReq);
  } catch (error) {
    console.error('Error proxying sample PDF:', error);
    res.status(500).json({ error: 'Failed to proxy sample PDF' });
  }
});

// --- Update File with Sample PDF Info ---
router.post('/api/update-file-sample-pdf', authenticateJWT_user, async (req, res) => {
  try {
    const { fileId, samplePdfUrl, samplePdfSize } = req.body;
    
    if (!fileId || !samplePdfUrl) {
      return res.status(400).json({ error: 'File ID and sample PDF URL are required' });
    }

    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Verify ownership
    if (file.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Update file with sample PDF info
    file.samplePdfUrl = samplePdfUrl;
    file.samplePdfStoredFilename = samplePdfUrl;
    file.samplePdfSize = samplePdfSize || 0;
    await file.save();

    res.json({ success: true, message: 'File updated with sample PDF information' });

  } catch (error) {
    console.error('Error updating file with sample PDF:', error);
    res.status(500).json({ error: 'Failed to update file' });
  }
});

// Export the router
module.exports = { fileroute: router };