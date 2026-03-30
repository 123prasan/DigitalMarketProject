/**
 * BULK UPDATE SEO META DESCRIPTIONS FOR ALL FILES
 * 
 * This script updates all existing files with optimized meta descriptions
 * Generate better Google SERP snippets to improve CTR on high-impression pages
 * 
 * Usage: node bulk-update-seo-descriptions.js [--preview] [--dry-run] [--apply]
 * 
 * Options:
 *   --preview   : Show first 5 files and their new descriptions
 *   --dry-run   : Calculate changes without saving (default)
 *   --apply     : Actually update database
 *   --no-connect: Run without MongoDB (simulation mode)
 */

require('dotenv').config();
const mongoose = require('mongoose');
require('dns').setServers(['1.1.1.1','8.8.8.8']);
// Color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  blue: '\x1b[34m',
};

function log(color, message) {
  console.log(`${color}${message}${colors.reset}`);
}

/**
 * Generate optimized meta description for a file
 * (Same logic as server.js generateOptimizedSEOForFile)
 */
function generateOptimizedDescription(file) {
  const filename = file.filename || '';
  const category = file.category || 'Study Material';
  const price = file.price || 0;

  // Detect content type from filename
  const isNotes = filename.toLowerCase().includes('note');
  const isPaper = filename.toLowerCase().includes('paper') || 
                 filename.toLowerCase().includes('question');
  const isSolution = filename.toLowerCase().includes('solution') || 
                    filename.toLowerCase().includes('answer');
  const isHandwritten = filename.toLowerCase().includes('handwritten') || 
                       filename.toLowerCase().includes('hand written');

  // Generate compelling meta description (150-160 chars)
  let description = '';

  if (isHandwritten) {
    description = `${filename} | Clear Handwritten Notes PDF | Download ${price === 0 ? 'Free' : `₹${price}`} | ${category}`;
  } else if (isNotes) {
    description = `${filename} | ${price === 0 ? 'Free' : 'Premium'} Study Notes | Complete Notes PDF | ${category} | Download Now`;
  } else if (isPaper) {
    description = `${filename} | Question Papers & Solutions | ${category} | PDF Download | Practice Papers`;
  } else if (isSolution) {
    description = `${filename} | Step-by-Step Solutions | Answer Keys | ${category} | PDF Download`;
  } else {
    // Generic educational resource
    description = `${filename} | ${price === 0 ? 'Free' : 'Premium'} Educational Resource | ${category} | Download ${price === 0 ? 'Now' : `for ₹${price}`}`;
  }

  // Truncate to 160 characters if needed
  if (description.length > 160) {
    description = description.substring(0, 157) + '...';
  }

  return description;
}

/**
 * Main script execution
 */
async function main() {
  try {
    const args = process.argv.slice(2);
    const isPreview = args.includes('--preview');
    const isDryRun = args.includes('--dry-run') || !args.includes('--apply');
    const isApply = args.includes('--apply');
    const noConnect = args.includes('--no-connect');

    log(colors.cyan, '\n╔════════════════════════════════════════════════════════════════╗');
    log(colors.cyan, '║  BULK SEO DESCRIPTION UPDATE FOR VIDYARI FILES                  ║');
    log(colors.cyan, '╚════════════════════════════════════════════════════════════════╝\n');

    let files;

    if (noConnect) {
      // Simulation mode - use sample data
      log(colors.yellow, '🔄 Running in SIMULATION mode (no MongoDB connection)\n');
      log(colors.dim, '   This shows what the script WOULD do if you ran it with your server.\n');
      
      files = [
        { _id: '1', filename: 'BCS302 VTU Notes', category: 'Engineering', price: 0, filedescription: 'Some notes' },
        { _id: '2', filename: 'DDCO Module 5 Handwritten Notes', category: 'Engineering', price: 199, filedescription: null },
        { _id: '3', filename: 'RGUHS Convocation Merit List 2026', category: 'Medical', price: 0, filedescription: 'Rank list' },
        { _id: '4', filename: 'Question Paper Solutions', category: 'General', price: 50, filedescription: '' },
        { _id: '5', filename: 'Complete Nursing Syllabus PDF', category: 'Medical', price: 100, filedescription: 'Syllabus doc' },
      ];
    } else {
      // Connect to MongoDB
      log(colors.yellow, '📡 Connecting to MongoDB...');
      const File = require('./models/file');
      
      try {
        await mongoose.connect(process.env.MONGODB_URI);
        log(colors.green, '✅ Connected successfully\n');
        
        log(colors.yellow, '📂 Fetching all files from database...');
        files = await File.find().lean();
        log(colors.green, `✅ Found ${files.length} files\n`);
      } catch (connectionError) {
        log(colors.red, `❌ MongoDB Connection Error: ${connectionError.message}`);
        log(colors.yellow, '\n💡 TIP: Start your server first, then run this script in another terminal.\n');
        log(colors.cyan, '   npm start\n');
        log(colors.yellow, '   Then in another terminal:\n');
        log(colors.cyan, '   node bulk-update-seo-descriptions.js --preview\n');
        log(colors.yellow, '   Or run in simulation mode:');
        log(colors.cyan, '   node bulk-update-seo-descriptions.js --no-connect --preview\n');
        process.exit(1);
      }
    }

    // Generate updates
    log(colors.yellow, '🔄 Generating optimized descriptions...\n');

    const updates = [];
    let improvedCount = 0;

    files.forEach((file, index) => {
      const newDescription = generateOptimizedDescription(file);
      const hasChanged = file.filedescription !== newDescription;

      if (hasChanged) {
        improvedCount++;
        updates.push({
          id: file._id,
          filename: file.filename,
          oldDesc: file.filedescription || '(empty)',
          newDesc: newDescription,
        });
      }
    });

    log(colors.green, `✅ Generated descriptions for ${improvedCount} files that will be improved\n`);

    // Preview mode: show first 5 changes
    if (isPreview && updates.length > 0) {
      log(colors.bright, '📋 PREVIEW: First 5 files to be updated\n');
      
      updates.slice(0, 5).forEach((update, i) => {
        log(colors.blue, `${i + 1}. ${update.filename}`);
        log(colors.dim, `   Old: "${update.oldDesc}"`);
        log(colors.green, `   New: "${update.newDesc}"`);
        console.log('');
      });

      if (updates.length > 5) {
        log(colors.dim, `   ... and ${updates.length - 5} more files\n`);
      }
    }

    // Summary
    log(colors.bright, '─────────────────────────────────────────────────────────────────\n');
    log(colors.bright, 'SUMMARY');
    log(colors.bright, '─────────────────────────────────────────────────────────────────\n');
    
    console.log(`Total files in database:    ${files.length}`);
    console.log(`Files to be improved:       ${improvedCount}`);
    console.log(`Files already optimized:    ${files.length - improvedCount}`);
    console.log(`Mode:                       ${isDryRun ? '🔍 DRY RUN (no changes)' : '✏️  APPLY (will save)'}`);
    if (noConnect) console.log(`Database:                   ${colors.yellow}SIMULATION (not real)${colors.reset}`);
    console.log('');

    // Apply updates if requested
    if (isApply && updates.length > 0 && !noConnect) {
      log(colors.yellow, '🚀 Applying updates to database...\n');

      const File = require('./models/file');
      let successCount = 0;
      let errorCount = 0;

      for (const update of updates) {
        try {
          await File.updateOne(
            { _id: update.id },
            { $set: { filedescription: update.newDesc } }
          );
          successCount++;

          // Show progress every 10 updates
          if (successCount % 10 === 0) {
            log(colors.green, `✅ Updated ${successCount}/${improvedCount}...`);
          }
        } catch (error) {
          errorCount++;
          log(colors.red, `❌ Error updating ${update.filename}: ${error.message}`);
        }
      }

      log(colors.green, `\n✅ Successfully updated ${successCount} files`);
      if (errorCount > 0) {
        log(colors.red, `⚠️  Failed to update ${errorCount} files`);
      }

      log(colors.green, '\n🎉 Database update complete!\n');
    } else if (isDryRun) {
      log(colors.yellow, '📊 DRY RUN MODE - No changes made to database\n');
      log(colors.bright, 'To apply these changes, run:');
      log(colors.cyan, '   node bulk-update-seo-descriptions.js --apply\n');
    }

    // Disconnect if connected
    if (!noConnect && mongoose.connection.readyState === 1) {
      await mongoose.disconnect();
      log(colors.green, '✅ Disconnected from MongoDB\n');
    }

  } catch (error) {
    log(colors.red, `\n❌ ERROR: ${error.message}\n`);
    console.error(error);
    process.exit(1);
  }
}

// Show usage info
console.log(`
${colors.bright}USAGE:${colors.reset}
  node bulk-update-seo-descriptions.js [options]

${colors.bright}OPTIONS:${colors.reset}
  --preview    Show preview of changes (first 5 files)
  --dry-run    Calculate changes without saving (default behavior)
  --apply      Actually update the database

${colors.bright}EXAMPLES:${colors.reset}
  # Preview what will change (safe, no updates)
  node bulk-update-seo-descriptions.js --preview

  # Dry run to see counts (default)
  node bulk-update-seo-descriptions.js

  # Apply changes to database
  node bulk-update-seo-descriptions.js --apply

  # Preview + Apply
  node bulk-update-seo-descriptions.js --preview --apply

${colors.bright}WHAT THIS SCRIPT DOES:${colors.reset}
  • Analyzes all files in your database
  • Generates optimized meta descriptions for Google SERP
  • Improves CTR by making snippets more compelling
  • Safe - runs in dry-run mode by default
  • Uses same logic as your file detail page SEO

${colors.bright}EXPECTED RESULTS:${colors.reset}
  📈 Better CTR on high-impression keywords
  🎯 More accurate search snippets
  ⬆️  Potential ranking improvements in 2-3 weeks

`);

// Run the script
if (require.main === module) {
  main();
}

module.exports = { generateOptimizedDescription };
