/**
 * COURSE FILE UPLOAD & SERVING ARCHITECTURE
 * 
 * This system manages course uploads and serves files through CloudFront with organized S3 folders.
 * 
 * FOLDER STRUCTURE (in S3):
 * s3://vidyari3/courses/uploads/
 * ├── images/          → Course thumbnails, preview images
 * ├── videos/          → Intro videos, course videos  
 * ├── pdfs/            → PDF documents, course materials
 * └── documents/       → Word, Excel, PowerPoint files
 * 
 * CLOUDFRONT URL FORMAT:
 * https://d3epchi0htsp3c.cloudfront.net/courses/uploads/{folder}/{unique-hash}-{filename}
 *
 * USAGE ACROSS VIEWS:
 * 1. gencourse.ejs     → Uploads files (generatePresignedUrl endpoint)
 * 2. courseplayer.ejs  → Displays videos/PDFs from CloudFront URLs
 * 3. course-detail.ejs → Shows course thumbnail and metadata
 * 
 * FILE TYPE AUTO-DETECTION:
 * - Images (.jpg, .png, etc.) → /images/ folder
 * - PDFs → /pdfs/ folder
 * - Videos (.mp4, .webm, etc.) → /videos/ folder
 * - Documents (.doc, .ppt, .xls, etc.) → /documents/ folder
 * 
 * EXAMPLES:
 * - Course thumbnail: https://d3epchi0htsp3c.cloudfront.net/courses/uploads/images/abc123-thumbnail.jpg
 * - Intro video: https://d3epchi0htsp3c.cloudfront.net/courses/uploads/videos/def456-intro.mp4
 * - Course material PDF: https://d3epchi0htsp3c.cloudfront.net/courses/uploads/pdfs/ghi789-guide.pdf
 * - Lesson resource: https://d3epchi0htsp3c.cloudfront.net/courses/uploads/documents/jkl012-notes.docx
 */

const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const crypto = require("crypto");
const Course = require("../models/course");
const mongoose=require("mongoose");
const ffmpeg = require('fluent-ffmpeg');
const ffprobeStatic = require('ffprobe-static');

ffmpeg.setFfprobePath(ffprobeStatic.path);

// CloudFront Configuration
const CLOUDFRONT_DOMAIN = "d3epchi0htsp3c.cloudfront.net";

// Initialize S3 Client
const s3Client = new S3Client({
    region: process.env.AWS_S3_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

// Function to get video duration in minutes
async function getVideoDuration(url) {
    return new Promise((resolve) => {
        ffmpeg.ffprobe(url, (err, metadata) => {
            if (err || !metadata || !metadata.format || !metadata.format.duration) {
                console.log('Could not get duration for', url, err ? err.message : 'no metadata');
                resolve(30); // default 30 minutes
            } else {
                const minutes = Math.ceil(metadata.format.duration / 60);
                console.log('Duration for', url, ':', minutes, 'minutes');
                resolve(minutes);
            }
        });
    });
}

/**
 * Helper function to get the appropriate folder for a file type
 * @param {string} fileName - The file name
 * @param {string} fileType - The MIME type or file type provided
 * @param {string} fileCategory - Optional: explicit category (images, videos, pdfs, documents)
 * @returns {string} - The folder name (images, videos, pdfs, documents)
 */
function determineFileFolder(fileName, fileType, fileCategory = null) {
    if (fileCategory) {
        return fileCategory.toLowerCase();
    }
    
    const ext = fileName.split('.').pop().toLowerCase();
    const mimeType = (fileType || '').toLowerCase();
    
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(ext) || 
        mimeType.startsWith('image/')) {
        return 'images';
    } else if (['pdf'].includes(ext) || mimeType === 'application/pdf') {
        return 'pdfs';
    } else if (mimeType.startsWith('video/')) {
        return 'videos';
    } else if (['doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx'].includes(ext)) {
        return 'documents';
    }
    return 'videos'; // default
}

/**
 * @desc    Generates a pre-signed URL for uploading a file to S3
 * @route   POST /api/courses/generate-presigned-url
 * @access  Private (should be protected by auth middleware)
 * 
 * Expected Body:
 * {
 *   fileName: "course-thumbnail.jpg",
 *   fileType: "image/jpeg",
 *   fileCategory: "images" (optional - auto-detected if not provided)
 * }
 * 
 * The response includes:
 * - signedUrl: URL for uploading to S3
 * - finalUrl: CloudFront URL for accessing the file (works with course-detail.ejs, courseplayer.ejs, etc.)
 */
exports.generatePresignedUrl = async (req, res) => {
    const { fileName, fileType, fileCategory } = req.body;
    
    if (!fileName || !fileType) {
        return res.status(400).json({ message: "fileName and fileType are required" });
    }

    // Auto-detect or use provided folder
    const folder = determineFileFolder(fileName, fileType, fileCategory);

    // Generate a unique file name to prevent overwrites
    const uniqueFileName = `${crypto.randomBytes(16).toString('hex')}-${fileName}`;

    const command = new PutObjectCommand({
        Bucket: process.env.AWS_S3_BUCKET_NAME,
        Key: `courses/uploads/${folder}/${uniqueFileName}`, // Store in category-specific subfolder
        ContentType: fileType,
    });

    try {
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600}); // URL expires in 1 hour
        
        // CloudFront URL works with all views (gencourse, courseplayer, course-detail)
        const finalUrl = `https://${CLOUDFRONT_DOMAIN}/${command.input.Key}`;

        res.status(200).json({ signedUrl, finalUrl });

    } catch (error) {
        console.error("Error generating pre-signed URL:", error);
        res.status(500).json({ message: "Could not generate upload URL" });
    }
};


// In /controllers/courseController.js

// ... (keep the other code, like s3Client and generatePresignedUrl) ...

/**
 * @desc    Creates a new course in the database
 * @route   POST /api/courses/create-course
 * @access  Private (should be protected by auth middleware)
 */
exports.createCourse = async (req, res) => {
    try {
        console.log(req.body)
        const courseDataFromFrontend = req.body;

        // Check if user is authenticated
        if (!req.user) {
            return res.status(401).json({ message: "Authentication required" });
        }

        // TODO: IMPORTANT! Replace this with the actual user ID from your authentication middleware
        const mockUserId = req.user._id; // Replace with a real ObjectId from your User collection for testing
        if (!mongoose.Types.ObjectId.isValid(mockUserId)) {
            return res.status(400).json({ message: "Invalid User ID format for mocking." });
        }

        // --- MAP FRONTEND DATA TO BACKEND SCHEMA ---
        // Map resources to submodules with CloudFront URLs for direct MP4 streaming
        const mappedModules = courseDataFromFrontend.modules.map(module => ({
            unit: module.title, // Map frontend 'title' to backend 'unit'
            order: module.order,
            submodules: module.resources.map(resource => {
                // CloudFront URL from generatePresignedUrl (e.g., https://d3epchi0htsp3c.cloudfront.net/courses/uploads/...)
                const cloudFrontUrl = resource.fileUrl;
                
                return {
                    title: resource.title,
                    type: resource.type,  // 'Video' or 'Document'
                    // fileUrl stores the CloudFront URL for direct streaming
                    fileUrl: cloudFrontUrl,
                    // externalUrl kept for backward compatibility
                    externalUrl: resource.url || cloudFrontUrl,
                    order: resource.order,
                    duration: resource.duration && !isNaN(resource.duration) ? parseInt(resource.duration) : 30  // Duration in minutes, defaults to 30 if not provided
                };
            })
        }));
        // --- END MAPPING ---

        // Get real durations for video files
        for (const module of mappedModules) {
            for (const submodule of module.submodules) {
                if (submodule.type === 'Video' && submodule.fileUrl) {
                    const realDuration = await getVideoDuration(submodule.fileUrl);
                    submodule.duration = realDuration;
                }
            }
        }

        // Calculate total course duration in minutes from all submodules
        let totalDurationMinutes = 0;
        mappedModules.forEach(module => {
            module.submodules.forEach(submodule => {
                if (submodule.duration && !isNaN(submodule.duration)) {
                    totalDurationMinutes += parseInt(submodule.duration);
                }
            });
        });

        // Fallback: if no duration calculated but modules exist, use default
        if (totalDurationMinutes === 0 && mappedModules.length > 0) {
            totalDurationMinutes = mappedModules.reduce((sum, module) => {
                return sum + (module.submodules.length * 30); // 30 minutes per resource
            }, 0);
        }

        // Parse learningOutcomes and requirements (they come as comma-separated strings from frontend)
        const learningOutcomes = courseDataFromFrontend.learningOutcomes
            ? (Array.isArray(courseDataFromFrontend.learningOutcomes) 
                ? courseDataFromFrontend.learningOutcomes 
                : courseDataFromFrontend.learningOutcomes.split(',').map(item => item.trim()).filter(item => item))
            : [];

        const requirements = courseDataFromFrontend.requirements
            ? (Array.isArray(courseDataFromFrontend.requirements) 
                ? courseDataFromFrontend.requirements 
                : courseDataFromFrontend.requirements.split(',').map(item => item.trim()).filter(item => item))
            : [];

        // Create a new course instance with the CORRECTLY MAPPED data
        const newCourse = new Course({
            title: courseDataFromFrontend.title,
            description: courseDataFromFrontend.description,
            price: courseDataFromFrontend.price,
            category: courseDataFromFrontend.category,
            thumbnailUrl: courseDataFromFrontend.thumbnailUrl,
            introVideoUrl: courseDataFromFrontend.introVideoUrl,  // ✅ NOW SAVING INTRO VIDEO
            tags: courseDataFromFrontend.tags,
            modules: mappedModules, // <-- Use the new, correctly structured array
            userId: mockUserId,
            duration: totalDurationMinutes, // ✅ AUTO-CALCULATED total duration in minutes
            learningOutcomes: learningOutcomes, // ✅ SAVED learning outcomes
            requirements: requirements, // ✅ SAVED requirements
            level: courseDataFromFrontend.level || "All Levels", // ✅ SAVED difficulty level
            isFree: courseDataFromFrontend.price === 0 || courseDataFromFrontend.price === null,
            published: true,  // Courses start published for immediate visibility
            discountPrice: courseDataFromFrontend.discountPrice || null,
        });

        const savedCourse = await newCourse.save();

        res.status(201).json(savedCourse);

    } catch (error)
     {
        // Use console.error for better error logging
        console.error("Error creating course:", error);
        if (error.code === 11000) {
            return res.status(409).json({ message: "A course with this title already exists." });
        }
        // Send back the specific validation error message if it exists
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: error.message });
        }
        res.status(500).json({ message: "Failed to create course" });
    }
};

// In /controllers/courseController.js
// Add this new function to your existing file. Keep the other functions.

// /**
//  * @desc    Get a single course by its ID
//  * @route   GET /api/courses/:courseId
//  * @access  Private
//  */
// exports.getCourseById = async (req, res) => {
//     try {
//         const course = await Course.findById(req.params.courseId).lean(); // .lean() for faster read-only queries

//         if (!course) {
//             return res.status(404).json({ message: "Course not found" });
//         }
//        console.log(course)
//         res.status(200).json(course);
//     } catch (error) {
//         console.error("Error fetching course by ID:", error);
//         res.status(500).json({ message: "Server error" });
//     }
// };