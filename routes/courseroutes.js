const express = require("express");
const router = express.Router();
const {
  generatePresignedUrl,
  createCourse,
  getCourseById,
} = require("../controllers/coursecontroller");
const authenticateJWT_user = require("./authentication/jwtAuth.js");
const jwt = require("jsonwebtoken");
const UserProgress = require("../models/courseProgress");
const Course = require("../models/course");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { type } = require("os");
const { S3Client, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
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
router.get("/coursecreation",(req,res)=>{
  res.render("gencourse.ejs");
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
const s3BucketName = "post-upload-pending";
const cloudfrontDomain = "d1iz17ohzrj8rc.cloudfront.net";

router.get("/:courseId", authenticateJWT_user, async (req, res) => {
  try {
    // console.log("cousr colled")
    const { courseId } = req.params;
    const userId = req.user._id;
    // console.log(userId)

    const [course, userProgress] = await Promise.all([
      Course.findById(courseId).lean(),
      UserProgress.findOne({ userId, courseId }).lean(),
    ]);

    if (!course) {
      return res.status(404).send("Course not found");
    }

    // --- DYNAMIC URL TRANSFORMATION FOR HLS MANIFEST ---
    if (cloudfrontDomain && s3BucketName) {
      const s3BaseUrl = `https://${s3BucketName}.s3`;

      // Transform thumbnail URL
      if (course.thumbnailUrl && course.thumbnailUrl.includes(s3BaseUrl)) {
        const urlPath = new URL(course.thumbnailUrl).pathname;
        course.thumbnailUrl = `https://${cloudfrontDomain}${urlPath}`;
        // console.log(course.thumbnailUrl)
      }

      // Transform submodule URLs. These URLs should now point to the HLS .m3u8 manifest file.
      course.modules.forEach(async(module) => {
        module.submodules.forEach(async(submodule) => {
          if (submodule.fileUrl) {
            const urlPath = new URL(submodule.fileUrl).pathname;
            console.log(urlPath);
            if (urlPath.includes(".pdf") || urlPath.includes(".docx")) {
                console.log("this is file")
              async function getPresignedPDF(fileKey) {
                const command = new GetObjectCommand({
                  Bucket: "vidyari2",
                  Key: fileKey,
                });
                return await getSignedUrl(s3, command, { expiresIn: 3600 }); // 1 hour
              }
              const pdfUrl = await getPresignedPDF(urlPath);
             
              submodule.fileUrl = `${pdfUrl}`;
              console.log(submodule.fileUrl)
              return;
            }
            // Assign the replaced string back to urlPath
            const newPath = urlPath
              .replace(/^\/courses\/uploads\//, "/hls-output/") // folder replacement
              .replace(/\.mp4$/i, ".m3u8"); // extension replacement
            console.log(newPath);
            // Update submodule.fileUrl to point to the CloudFront HLS master playlist
            submodule.fileUrl = `https://${cloudfrontDomain}${newPath}`;
          }
        });
      });
    }

    const progressData = userProgress || {
      courseId: courseId,
      progress: [],
      lastAccessed: null,
    };

    // Render the EJS template with the transformed data
    res.render("courseplayer", {
      course: course,
      userProgress: progressData,
    });
  } catch (error) {
    console.error("Error rendering course player:", error);
    res.status(500).send("Server error");
  }
});

module.exports = router;
