/**
 * Migration Script: Add previewUrl to existing files
 * Generates placeholder preview images for files that don't have previewUrl
 */

const mongoose = require('mongoose');
const File = require('./models/file');

// Connection string
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/vidyari';

async function migratePreviewUrls() {
  try {
    console.log('🚀 Starting migration: Add previewUrl to files...');
    
    // Connect to MongoDB
    await mongoose.connect(MONGO_URI);
    console.log('✅ Connected to MongoDB');

    // Get all files
    const files = await File.find({ previewUrl: { $exists: false } });
    console.log(`📊 Found ${files.length} files without previewUrl`);

    if (files.length === 0) {
      console.log('ℹ️  All files already have previewUrl. No migration needed.');
      await mongoose.disconnect();
      return;
    }

    let updated = 0;
    let errors = 0;

    for (const file of files) {
      try {
        // Generate preview URL based on category or file type
        const category = file.category || 'General';
        const fileType = file.fileType || 'pdf';
        
        // Use placeholder image service
        const previewUrl = `https://placehold.co/600x400/e8f0fe/0b57d0?text=${encodeURIComponent(category.substring(0, 15))}&font=Outfit`;
        
        // Update the file with previewUrl
        await File.updateOne(
          { _id: file._id },
          { 
            previewUrl: previewUrl,
            rating: file.rating || 0 // Also ensure rating field exists
          }
        );
        
        updated++;
        
        // Log every 10 updates
        if (updated % 10 === 0) {
          console.log(`⏳ Migrated ${updated} files...`);
        }
      } catch (error) {
        errors++;
        console.error(`❌ Error migrating file ${file._id}:`, error.message);
      }
    }

    console.log(`\n✅ Migration complete!`);
    console.log(`📈 Updated: ${updated} files`);
    console.log(`❌ Errors: ${errors} files`);

    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    console.error(error);
    process.exit(1);
  }
}

// Run migration
migratePreviewUrls();
