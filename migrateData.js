// // // migrate.js
// // require("dotenv").config();
// // const { createClient } = require("@supabase/supabase-js");
// // const AWS = require("aws-sdk");

// // // --- Supabase Config ---
// // const supabase = createClient(
// //   process.env.SUPABASE_URL,
// //   process.env.SUPABASE_SERVICE_ROLE_KEY // use service role for full bucket access
// // );

// // // --- AWS S3 Config ---
// // const s3 = new AWS.S3({
// //   accessKeyId: process.env.AWS_ACCESS_KEY_ID,
// //   secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
// //   region: process.env.AWS_S3_REGION,
// // });

// // const SUPABASE_BUCKET = "files"; // your Supabase bucket
// // const S3_BUCKET = "vidyari-main"; // your S3 bucket
// // const S3_FOLDER = "main-files"; // target folder in S3

// // async function migrateFiles() {
// //   // 1. List files in Supabase bucket
// //   const { data: files, error } = await supabase.storage
// //     .from(SUPABASE_BUCKET)
// //     .list("", { limit: 1000 });

// //   if (error) {
// //     console.error("Error listing Supabase files:", error.message);
// //     return;
// //   }

// //   for (const file of files) {
// //     console.log(`Migrating: ${file.name}`);

// //     // 2. Download file from Supabase
// //     const { data, error: downloadError } = await supabase.storage
// //       .from(SUPABASE_BUCKET)
// //       .download(file.name);

// //     if (downloadError) {
// //       console.error(`Failed to download ${file.name}:`, downloadError.message);
// //       continue;
// //     }

// //     // Convert to Buffer for S3 upload
// //     const buffer = Buffer.from(await data.arrayBuffer());

// //     // 3. Upload to S3 inside "main-files/" folder
// //     try {
// //       await s3
// //         .upload({
// //           Bucket: S3_BUCKET,
// //           Key: `${S3_FOLDER}/${file.name}`, // folder + filename
// //           Body: buffer,
// //           ACL: "private", // or "public-read" if needed
// //         })
// //         .promise();

// //       console.log(`Uploaded ${file.name} to S3/${S3_FOLDER}`);
// //     } catch (err) {
// //       console.error(`Failed to upload ${file.name} to S3:`, err.message);
// //     }
// //   }
// // }

// // migrateFiles();
// // migrate.js
// require("dotenv").config();
// const { createClient } = require("@supabase/supabase-js");
// const AWS = require("aws-sdk");

// // --- Supabase Config ---
// const supabase = createClient(
//   process.env.SUPABASE_URL,
//   process.env.SUPABASE_SERVICE_ROLE_KEY // use service role for full bucket access
// );

// // --- AWS S3 Config ---
// const s3 = new AWS.S3({
//   accessKeyId: process.env.AWS_ACCESS_KEY_ID,
//   secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
//   region: process.env.AWS_S3_REGION,
// });

// const SUPABASE_BUCKET = "files"; // your Supabase bucket name
// const SUPABASE_FOLDER = "previews"; // only migrate from this folder
// const S3_BUCKET = "vidyari2"; // your target S3 bucket
// const S3_FOLDER = "files-previews/images"; // target folder in S3

// async function migrateFiles() {
//   // 1. List files inside Supabase "previews" folder
//   const { data: files, error } = await supabase.storage
//     .from(SUPABASE_BUCKET)
//     .list(SUPABASE_FOLDER, { limit: 1000 });

//   if (error) {
//     console.error("Error listing Supabase files:", error.message);
//     return;
//   }

//   for (const file of files) {
//     console.log(`Migrating: ${file.name}`);

//     // Full Supabase path (since files are inside previews/)
//     const supabasePath = `${SUPABASE_FOLDER}/${file.name}`;

//     // 2. Download file from Supabase
//     const { data, error: downloadError } = await supabase.storage
//       .from(SUPABASE_BUCKET)
//       .download(supabasePath);

//     if (downloadError) {
//       console.error(`Failed to download ${supabasePath}:`, downloadError.message);
//       continue;
//     }

//     // Convert to Buffer for S3 upload
//     const buffer = Buffer.from(await data.arrayBuffer());

//     // 3. Upload to S3 inside "files-previews/" folder
//     try {
//       await s3
//         .upload({
//           Bucket: S3_BUCKET,
//           Key: `${S3_FOLDER}/${file.name}`, // files-previews/<filename>
//           Body: buffer,
//           ACL: "private", // or "public-read" if you want public access
//         })
//         .promise();

//       console.log(`Uploaded ${file.name} to s3://${S3_BUCKET}/${S3_FOLDER}/`);
//     } catch (err) {
//       console.error(`Failed to upload ${file.name} to S3:`, err.message);
//     }
//   }
// }

// migrateFiles();
