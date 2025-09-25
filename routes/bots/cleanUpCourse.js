const cron = require("node-cron");
const { DeleteObjectsCommand, S3Client } = require("@aws-sdk/client-s3");
const Course = require("../../models/Course"); // your Course model
const mongoose=require("mongoose");
mongoose.connect("mongodb+srv://prasannaprasanna35521:YyWbAq2FoOietc7B@cluster0.0ytfuyz.mongodb.net/documents?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.error("MongoDB connection error:", err));
// S3 clients
const courseS3 = new S3Client({
  region: "ap-south-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const hlsS3 = new S3Client({
  region: "ap-south-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// Extract S3 key from URL
function getS3KeyFromUrl(fileUrl) {
  if (!fileUrl) return null;
  const urlObj = new URL(fileUrl);
  console.log(urlObj.pathname)
  return urlObj.pathname.slice(1); // removes leading '/'
}

async function cleanupAbandonedCourses(gracePeriodHours = 3) {
  const cutoff = new Date(Date.now() - gracePeriodHours * 60 * 60 * 1000);
  const orphanCourses = await Course.find({
    published: false,
    
  });

  for (const course of orphanCourses) {
    const keysToDelete = [];

    // 1. Delete course files from main bucket
    course.modules.forEach(module => {
      module.submodules.forEach(submodule => {
        const key = getS3KeyFromUrl(submodule.fileUrl);
        if (key) keysToDelete.push({ Key: key });
      });
    });

    if (keysToDelete.length > 0) {
      try {
        await courseS3.send(new DeleteObjectsCommand({
          Bucket: "vidyari2",
          Delete: { Objects: keysToDelete }
        }));
        console.log(`Deleted course files for course: ${course._id}`);
      } catch (err) {
        console.error(`Failed to delete S3 files for course ${course._id}:`, err);
        continue; // skip DB deletion if S3 deletion failed
      }
    }

    // 2. Delete HLS files using their exact keys
    if (course.hlsFileKeys && course.hlsFileKeys.length > 0) {
      const hlsKeys = course.hlsFileKeys.map(f => ({ Key: f }));
      try {
        await hlsS3.send(new DeleteObjectsCommand({
          Bucket: "post-upload-pending",
          Delete: { Objects: hlsKeys }
        }));
        console.log(`Deleted HLS files for course: ${course._id}`);
      } catch (err) {
        console.error(`Failed to delete HLS files for course ${course._id}:`, err);
      }
    }

    // 3. Delete course document from MongoDB
    await Course.deleteOne({ _id: course._id });
    console.log(`Deleted course document: ${course._id}`);
  }
}


cleanupAbandonedCourses();

