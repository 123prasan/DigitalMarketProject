const express = require("express");
const router = express.Router();
const {
  generatePresignedUrl,
  createCourse,
  getCourseById,
} = require("../controllers/coursecontroller");
const authenticateJWT_user = require("./authentication/jwtAuth.js");
const { enforceDeviceLimit } = require("./authentication/deviceLimit.js");
const jwt = require("jsonwebtoken");
const UserProgress = require("../models/courseProgress");
const Course = require("../models/course");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { type } = require("os");
const fs = require("fs");
const path = require("path");
const { S3Client, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { getSignedUrl: getCloudFrontSignedUrl } = require("@aws-sdk/cloudfront-signer");
const s3 = new S3Client({ region: "ap-south-1" });

// TODO: Add your authentication middleware to protect these routes
router.use(cookieParser());
// Route to get a pre-signed URL for file uploads
console.log("dsdfs");
router.post(
  "/generate-presigned-url",
  authenticateJWT_user,
  generatePresignedUrl
);
router.get("/coursecreation", authenticateJWT_user, (req,res)=>{
  res.render("courses/gencourse.ejs");
})
// Route to create the course after files are uploaded
router.post("/create-course", authenticateJWT_user, createCourse);
// In /routes/courseRoutes.js
// Add this new route to your existing file.

// const router = express.Router();
// Make sure to import getCourseById

// const authenticateJWT_user = require('./authentication/jwtAuth'); // Adjust path if needed

// ... keep your existing POST routes ...
router.post(
  "/generate-presigned-url",
  authenticateJWT_user,
  generatePresignedUrl
);
router.post("/create-course", authenticateJWT_user, createCourse);

// router.get('/:courseId', authenticateJWT_user, getCourseById);
const s3BucketName = "post-upload-pending2";
const cloudfrontDomain = process.env.CF_DOMAIN_PROFILES_COURSES ? process.env.CF_DOMAIN_PROFILES_COURSES.replace(/^https:\/\//, "") : "d3epchi0htsp3c.cloudfront.net";
const CLOUDFRONT_KEY_PAIR_ID = process.env.CLOUDFRONT_KEY_PAIR_ID;
const PRIVATE_KEY_PATH = path.join(__dirname, "..", "private_keys", "cloudfront-private-key.pem");
const PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");

router.get("/:courseId", authenticateJWT_user, enforceDeviceLimit, async (req, res) => {
  try {
    // console.log("cousr colled")
    const { courseId } = req.params;

    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).render("404", { message: "Authentication required to access courses." });
    }

    const userId = req.user._id;
    // console.log(userId)

    const [course, userProgress] = await Promise.all([
      Course.findById(courseId).lean(),
      UserProgress.findOne({ userId, courseId }).lean(),
    ]);

    if (!course) {
      return res.status(404).send("Course not found");
    }

    // Check if user has purchased/enrolled in this course
    // Allow access if course is free OR user is enrolled
    const isEnrolled = course.isFree || (course.enrolledStudents && course.enrolledStudents.some(id => id.toString() === userId.toString()));
    if (!isEnrolled) {
      return res.status(403).render("404", { message: "You must purchase this course to access it." });
    }

    // --- DYNAMIC URL TRANSFORMATION FOR CLOUDFRONT ---
    // Note: We no longer transform file URLs here for security.
    // Video URLs will be served securely via the /video API endpoint.

    const progressData = userProgress || {
      courseId: courseId,
      progress: [],
      lastAccessed: null,
    };

    // Render the EJS template with the transformed data
    res.render("courses/courseplayer", {
      course: course,
      userProgress: progressData,
    });
  } catch (error) {
    console.error("Error rendering course player:", error);
    res.status(500).send("Server error");
  }
});

// Secure video access endpoint
router.get("/:courseId/lessons/:lessonId/video", authenticateJWT_user, enforceDeviceLimit, async (req, res) => {
  try {
    const { courseId, lessonId } = req.params;

    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ error: "Authentication required." });
    }

    const userId = req.user._id;

    // Find the course
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    // Verify user is enrolled (or course is free)
    const isEnrolled = course.isFree || (course.enrolledStudents && course.enrolledStudents.some(id => id.toString() === userId.toString()));
    if (!isEnrolled) {
      return res.status(403).json({ error: "Access denied. You must purchase this course." });
    }

    // Find the lesson
    let lesson = null;
    for (const module of course.modules) {
      lesson = module.submodules.find(sub => sub._id.toString() === lessonId);
      if (lesson) break;
    }

    if (!lesson || lesson.type !== 'Video') {
      return res.status(404).json({ error: "Video lesson not found" });
    }

    // Generate signed URL for the video
    const videoUrl = lesson.fileUrl;
    if (!videoUrl) {
      return res.status(404).json({ error: "Video URL not available" });
    }

    // Extract S3 key from CloudFront URL
    let cloudfrontDomain = process.env.CF_DOMAIN_PROFILES_COURSES || "https://d3epchi0htsp3c.cloudfront.net";
    cloudfrontDomain = cloudfrontDomain.replace(/^https:\/\//, ""); // Remove https:// if present
    const urlPattern = new RegExp(`https://${cloudfrontDomain}/(.+)`);
    const match = videoUrl.match(urlPattern);

    if (!match) {
      return res.status(400).json({ error: "Invalid video URL format" });
    }

    const s3Key = match[1];

    // Generate CloudFront signed URL (valid for 1 hour)
    const cloudFrontUrl = `https://${cloudfrontDomain}/${s3Key}`;
    const signedUrl = getCloudFrontSignedUrl({
      url: cloudFrontUrl,
      keyPairId: CLOUDFRONT_KEY_PAIR_ID,
      privateKey: PRIVATE_KEY,
      dateLessThan: new Date(Date.now() + 3600 * 1000), // 1 hour from now
    });

    res.json({
      success: true,
      videoUrl: signedUrl,
      title: lesson.title,
      duration: lesson.duration
    });

  } catch (error) {
    console.error("Error generating secure video URL:", error);
    res.status(500).json({ error: "Failed to generate video URL" });
  }
});

module.exports = router;
