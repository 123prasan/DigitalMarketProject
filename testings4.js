const { S3Client, HeadObjectCommand } = require("@aws-sdk/client-s3");
require("dotenv").config();

const s3Client = new S3Client({
  region: process.env.AWS_S3_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

const key = "files-previews/images/68482b9b587c63be6321befc.jpg";

async function checkObject() {
  try {
    const command = new HeadObjectCommand({
      Bucket: "vidyari2",
      Key: key
    });
    const data = await s3Client.send(command);
    console.log("Object exists:", data);
  } catch (err) {
    console.error("Error:", err);
  }
}

checkObject();
