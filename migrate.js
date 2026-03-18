require('dotenv').config();
const dns = require('dns');
const { S3Client } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const { createClient } = require('@supabase/supabase-js');
const { GoogleGenerativeAI } = require("@google/generative-ai"); // New Import
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const pdf = require('pdf-poppler');

dns.setServers(['1.1.1.1', '8.8.8.8']);
const File = require('./models/file'); 

// --- Configuration ---
const USER_ID = '68de9bfaf800ec98aea8b6f3'; 
const USERNAME = 'vidyari'; 
const SB_BUCKET = 'vidyarimain'; 
const SB_FOLDER = 'main-files'; 
const TEMP_DIR = path.join(__dirname, 'temp_processing');

// AI Setup (Make sure GEMINI_API_KEY is in your .env)
const genAI = new GoogleGenerativeAI("AIzaSyArJHYJ5Jg2o2J_NP3aNaiJtHq_eIHxxQ8");
const aiModel = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const s3Client = new S3Client({ region: process.env.AWS_REGION || 'ap-south-1' });

const IMAGE_BUCKET = 'vidyari3';
const MAIN_FILE_BUCKET = 'vidyarimain2';

const delay = (ms) => new Promise(res => setTimeout(res, ms));

// --- Intelligent Helper ---
async function generateAIMetadata(filename) {
    try {
        const prompt = `Act as an academic librarian for a student marketplace. 
        Analyze this filename: "${filename}".
        1. Create a professional, SEO-friendly description (exactly 2 sentences).
        2. Pick the best category (e.g., Medical, Engineering, Nursing, Commerce, Law, Arts).
        Return ONLY a JSON object: {"description": "...", "category": "..."}`;

        const result = await aiModel.generateContent(prompt);
        const response = await result.response;
        return JSON.parse(response.text().replace(/```json|```/g, ""));
    } catch (err) {
        console.log("🤖 AI skipped/failed for this file, using defaults.");
        return { 
            description: `Study resources and reference materials for ${filename}. Useful for exam preparation and revision.`, 
            category: "Academic" 
        };
    }
}

const cleanFileName = (rawName) => {
    const ext = path.extname(rawName);
    let nameWithoutExt = path.basename(rawName, ext);
    nameWithoutExt = nameWithoutExt.replace(/-\d{10,13}-[a-f0-9]{8}$/i, '').replace(/^\d{10,13}_/, '');
    return nameWithoutExt.trim();
};

async function migrateWithThumbnail() {
    try {
        await mongoose.connect(process.env.MONGODB_URI, { family: 4 });
        console.log("🚀 Connected to MongoDB");

        const { data: supabaseFiles, error } = await supabase.storage
            .from(SB_BUCKET)
            .list(SB_FOLDER, { limit: 200 });

        if (error) throw error;

        for (const sbFile of supabaseFiles) {
            if (sbFile.name === '.emptyFolderPlaceholder' || !sbFile.metadata) continue;

            const fullPath = `${SB_FOLDER}/${sbFile.name}`;
            const cleanName = cleanFileName(sbFile.name);
            const tempFilePath = path.join(TEMP_DIR, sbFile.name);

            // Check if already processed
            const exists = await File.findOne({ filename: cleanName, userId: USER_ID });
            if (exists && exists.status === 'completed') {
                console.log(`⏭️ Skipping "${cleanName}" - Already exists.`);
                continue;
            }

            // 1. Download
            const { data: blob, error: dlError } = await supabase.storage.from(SB_BUCKET).download(fullPath);
            if (dlError) continue;
            fs.writeFileSync(tempFilePath, Buffer.from(await blob.arrayBuffer()));

            // 🤖 AI INTELLIGENCE STEP
            console.log(`🧠 AI Analyzing: ${cleanName}`);
            const aiData = await generateAIMetadata(cleanName);

            // 2. Mongo Record
            let mongoFile = exists || await File.create({ 
                userId: USER_ID, 
                user: USERNAME, 
                filename: cleanName, 
                filedescription: aiData.description, // AI Generated
                category: aiData.category,           // AI Generated
                fileSize: sbFile.metadata.size, 
                status: "processing" 
            });

            const idStr = mongoFile._id.toString();
            let thumbnailUploaded = false;
            
            // 3. GENERATE THUMBNAIL
            if (path.extname(sbFile.name).toLowerCase() === '.pdf') {
                try {
                    console.log(`⚙️  Converting: ${cleanName}`);
                    await pdf.convert(tempFilePath, { format: 'jpeg', out_dir: TEMP_DIR, out_prefix: idStr, page: 1 });

                    let foundFile = null;
                    let attempts = 0;
                    while (!foundFile && attempts < 20) {
                        const filesInTemp = fs.readdirSync(TEMP_DIR);
                        foundFile = filesInTemp.find(f => f.startsWith(idStr) && f.endsWith('.jpg'));
                        if (!foundFile) { await delay(500); attempts++; }
                    }

                    if (foundFile) {
                        const fullThumbPath = path.join(TEMP_DIR, foundFile);
                        const thumbUpload = new Upload({
                            client: s3Client,
                            params: {
                                Bucket: IMAGE_BUCKET,
                                Key: `files-previews/images/${idStr}.jpg`,
                                Body: fs.createReadStream(fullThumbPath),
                                ContentType: 'image/jpeg',
                                
                            }
                        });
                        await thumbUpload.done();
                        thumbnailUploaded = true;
                        fs.unlinkSync(fullThumbPath);
                        console.log("✅ Thumbnail Uploaded");
                    }
                } catch (pError) {
                    console.error("⚠️ Poppler failure:", pError.message);
                }
            }

            // 4. UPLOAD MAIN FILE
            const s3Key = `main-files/${cleanName.replace(/[^a-z0-9]/gi, '_')}-${Date.now()}${path.extname(sbFile.name)}`;
            const mainUpload = new Upload({
                client: s3Client,
                params: {
                    Bucket: MAIN_FILE_BUCKET, Key: s3Key, Body: fs.createReadStream(tempFilePath), ContentType: 'application/pdf'
                }
            });
            await mainUpload.done();

            // 5. UPDATE MONGODB
            await File.findByIdAndUpdate(mongoFile._id, {
                status: "completed",
                fileUrl: path.basename(s3Key),
                storedFilename: s3Key,
                imageUrl: thumbnailUploaded ? `https://${IMAGE_BUCKET}.s3.amazonaws.com/files-previews/images/${idStr}.jpg` : undefined,
                imageName: thumbnailUploaded ? `${idStr}.jpg` : undefined,
                imageType: thumbnailUploaded ? 'jpg' : undefined,
                // Reinforce AI metadata in case it was a re-upload
                filedescription: aiData.description,
                category: aiData.category
            });

            console.log(`💾 Synced: ${cleanName} [Cat: ${aiData.category}]`);
            if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
        }
    } catch (err) {
        console.error("🔥 Error:", err);
    } finally {
        mongoose.connection.close();
    }
}

migrateWithThumbnail();