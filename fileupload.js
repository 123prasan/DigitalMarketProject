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
const cors = require('cors');
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const File = require("./models/file");
const authenticateJWT_user  = require('./routes/authentication/jwtAuth'); // Assuming path is correct
const requireAuth = require('./routes/authentication/reaquireAuth'); // Assuming path is correct
const Categories=require("./models/categories")
const router = express.Router();
const Coupon=require("./models/couponschema.js");

// --- Configuration ---
const IMAGE_BUCKET = process.env.S3_IMAGE_BUCKET || 'vidyari2';
const MAIN_FILE_BUCKET = process.env.S3_MAIN_FILE_BUCKET || 'vidyarimain';
const REGION = process.env.AWS_REGION || 'ap-south-1';
const URL_EXPIRATION_SECONDS = 21600;

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
    const fileExtension = path.extname(originalFileName);

    if (fileType === 'image') {
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
    
    throw new Error('Invalid fileType specified. Must be "image" or "main".');
};


// =================================================================
//                         API Routes
// =================================================================

// --- STEP 1: Start Upload ---
router.post('/start-multipart-upload', async (req, res) => {
    const { fileName, contentType, fileType, fileId } = req.body;
    if (!fileName || !contentType || !fileType || !fileId) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    try {
        const { bucket, key, generatedFileName } = getS3Params(fileType, fileName, fileId);

        const command = new CreateMultipartUploadCommand({
            Bucket: bucket,
            Key: key,
            ContentType: contentType,
        });
        
        const { UploadId } = await s3Client.send(command);
        
        // Return the full key for subsequent requests, AND the final filename for the DB
        res.json({ uploadId: UploadId, key: key, generatedFileName: generatedFileName });

    } catch (err) {
        console.error('Error initiating multipart upload:', err);
        res.status(500).json({ error: 'Could not initiate multipart upload.' });
    }
});

// --- STEP 2: Get Presigned URL ---
router.get('/get-presigned-part-url', async (req, res) => {
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
router.post('/complete-multipart-upload', async (req, res) => {
    const { key, uploadId, parts, fileType, fileId, generatedFileName,fileSize } = req.body;
    if (!key || !uploadId || !Array.isArray(parts) || !fileType || !fileId || !generatedFileName) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    const bucket = fileType === 'image' ? IMAGE_BUCKET : MAIN_FILE_BUCKET;
    const sortedParts = [...parts].sort((a, b) => a.PartNumber - b.PartNumber);

    const command = new CompleteMultipartUploadCommand({
        Bucket: bucket, Key: key, UploadId: uploadId, MultipartUpload: { Parts: sortedParts },
    });

    try {
        const result = await s3Client.send(command);
        const fullS3Url = result.Location || `https://${bucket}.s3.${REGION}.amazonaws.com/${key}`;
        
        // --- DATABASE LOGIC (Updated as per your request) ---
        const updatePayload = {};
        if (fileType === 'image') {
            // For images, save the full S3 URL and the filename (the object ID)
            updatePayload.imageUrl = fullS3Url;
            updatePayload.imageName = generatedFileName; // e.g., "6511a...a1b.jpg"
        } else { // 'main' file
            // For the main file, save ONLY the generated name to fileUrl
            updatePayload.fileUrl = generatedFileName; // e.g., "my-doc-175...-d7f3.pdf"
            updatePayload.storedFilename = key; // e.g., "main-files/my-doc-175...-d7f3.pdf"
             updatePayload.fileSize = fileSize;
        }

        const updatedFile = await File.findByIdAndUpdate(fileId, updatePayload, { new: true });
        if (!updatedFile) {
            return res.status(404).json({ error: 'File record not found in database.' });
        }
        
        res.json({ message: 'Upload completed successfully!' });

    } catch (err) {
        console.error('Error completing multipart upload:', err);
        res.status(500).json({ error: 'Could not complete multipart upload.' });
    }
});


// --- STEP 4: Abort Upload ---
router.post('/abort-multipart-upload', async (req, res) => {
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
        
        res.status(201).json({ fileId: newFile._id });

    } catch (error) {
        console.error('Error creating file record:', error);
        res.status(500).json({ error: 'Could not create file record.' });
    }
});

// Export the router
module.exports = { fileroute: router };