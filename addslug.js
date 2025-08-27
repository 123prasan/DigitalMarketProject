// Filename: add-slugs.js

// Load environment variables from your .env file
require('dotenv').config(); 

const mongoose = require('mongoose');

// --- Self-Contained Schema and Model Definition ---

function slugify(text) {
  return text.toString().toLowerCase().trim()
    .replace(/\s+/g, '-').replace(/[^\w\-]+/g, '').replace(/\-\-+/g, '-')
    .replace(/^-+/, '').replace(/-+$/, '');
}

const fileSchema = new mongoose.Schema({
    filedescription: String, user: String, filename: String, fileUrl: String,
    storedFilename: String, price: Number, uploadedAt: { type: Date, default: Date.now },
    category: { type: String, required: true }, fileSize: Number, downloadCount: { type: Number, default: 0 },
    fileType: String, slug: { type: String, unique: true }
});

// IMPORTANT: The name 'doccollection' must match your collection name
const File = mongoose.model('doccollection', fileSchema);

// --- End of Schema Definition ---


// Use the connection string from your .env file
const MONGO_URI = process.env.MONGODB_URI;

async function addSlugsToExistingFiles() {
    if (!MONGO_URI) {
        console.error('ERROR: MONGODB_URI is not defined. Please check your .env file.');
        return;
    }
    try {
        console.log('Connecting to database...');
        await mongoose.connect(MONGO_URI);
        console.log('Database connected.');

        // Find all documents that do NOT have a slug field yet
        const filesToUpdate = await File.find({ slug: { $exists: false } });

        if (filesToUpdate.length === 0) {
            console.log('All files already have slugs. No updates needed.');
            await mongoose.connection.close();
            return;
        }

        console.log(`Found ${filesToUpdate.length} files to update...`);
        let updatedCount = 0;

        for (const file of filesToUpdate) {
            const randomSuffix = (Math.random() + 1).toString(36).substring(7);
            file.slug = `${slugify(file.filename)}-${randomSuffix}`;
            
            await file.save();
            updatedCount++;
            console.log(`Updated: ${file.filename}`);
        }

        console.log(`\nMigration complete. Successfully updated ${updatedCount} files.`);
        await mongoose.connection.close();
        console.log('Database connection closed.');

    } catch (error) {
        console.error('An error occurred during migration:', error);
        await mongoose.connection.close();
        process.exit(1);
    }
}

// Run the migration function
addSlugsToExistingFiles();