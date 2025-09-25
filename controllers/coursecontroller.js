const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const crypto = require("crypto");
const Course = require("../models/course");
const mongoose=require("mongoose");
// Initialize S3 Client
const s3Client = new S3Client({
    region: process.env.AWS_S3_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

/**
 * @desc    Generates a pre-signed URL for uploading a file to S3
 * @route   POST /api/courses/generate-presigned-url
 * @access  Private (should be protected by auth middleware)
 */
exports.generatePresignedUrl = async (req, res) => {
    const { fileName, fileType } = req.body;
    if (!fileName || !fileType) {
        return res.status(400).json({ message: "fileName and fileType are required" });
    }

    // Generate a unique file name to prevent overwrites
    const uniqueFileName = `${crypto.randomBytes(16).toString('hex')}-${fileName}`;

    const command = new PutObjectCommand({
        Bucket: process.env.AWS_S3_BUCKET_NAME,
        Key: `courses/uploads/${uniqueFileName}`, // Store in a specific folder
        ContentType: fileType,
    });

    try {
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600}); // URL expires in 60 seconds
        
        const finalUrl = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_S3_REGION}.amazonaws.com/${command.input.Key}`;

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

        // TODO: IMPORTANT! Replace this with the actual user ID from your authentication middleware
        const mockUserId = req.user._id; // Replace with a real ObjectId from your User collection for testing
        if (!mongoose.Types.ObjectId.isValid(mockUserId)) {
            return res.status(400).json({ message: "Invalid User ID format for mocking." });
        }

        // --- START: FIX IS HERE ---
        // We need to map the data structure from the frontend to our Mongoose schema structure.
        const mappedModules = courseDataFromFrontend.modules.map(module => ({
            unit: module.title, // Map frontend 'title' to backend 'unit'
            order: module.order,
            submodules: module.resources.map(resource => ({ // Map 'resources' to 'submodules'
                title: resource.title,
                type: resource.type,
                externalUrl: resource.url,       // Map 'url' to 'externalUrl'
                fileUrl: resource.fileUrl,     // This is the S3 URL
                order: resource.order
            }))
        }));
        // --- END: FIX IS HERE ---

        // Create a new course instance with the CORRECTLY MAPPED data
        const newCourse = new Course({
            title: courseDataFromFrontend.title,
            description: courseDataFromFrontend.description,
            price: courseDataFromFrontend.price,
            category: courseDataFromFrontend.category,
            thumbnailUrl: courseDataFromFrontend.thumbnailUrl,
            tags: courseDataFromFrontend.tags,
            modules: mappedModules, // <-- Use the new, correctly structured array
            userId: mockUserId,
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