#!/usr/bin/env node

/**
 * BATCH INDEX ALL FILES - Google Indexing API
 * 
 * This script submits ALL 121 file URLs to Google's Indexing API
 * for immediate crawling and indexing.
 * 
 * Usage:
 *   node batch-index-all-files.js --preview     (shows files to be indexed)
 *   node batch-index-all-files.js --apply       (actually submits to Google)
 *   node batch-index-all-files.js --status      (checks indexing status)
 */

const mongoose = require('mongoose');
require('dns').setServers(['1.1.1.1','8.8.8.8']);
const fs = require('fs');
const path = require('path');
const https = require('https');
const { JWT } = require('google-auth-library');
require('dotenv').config();

// ===== CONFIGURATION =====
const MONGODB_URI = process.env.MONGODB_URI ;
const DOMAIN = 'https://www.vidyari.com';
const SERVICE_ACCOUNT_PATH = path.join(__dirname, 'serviceAccountKey.json');
const BATCH_SIZE = 100; // Google allows batches of 100
const DELAY_BETWEEN_BATCHES = 2000; // 2 seconds between batches



const File = require('./models/file'); // Adjust path as needed

// ===== COLORS FOR OUTPUT =====
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(color, prefix, message) {
  console.log(`${colors[color]}${colors.bright}[${prefix}]${colors.reset} ${message}`);
}

// ===== LOAD SERVICE ACCOUNT =====
async function loadServiceAccount() {
  try {
    if (!fs.existsSync(SERVICE_ACCOUNT_PATH)) {
      log('red', 'ERROR', `Service account file not found: ${SERVICE_ACCOUNT_PATH}`);
      process.exit(1);
    }
    
    const serviceAccount = JSON.parse(
      fs.readFileSync(SERVICE_ACCOUNT_PATH, 'utf8')
    );
    log('green', 'LOADED', 'Service account credentials loaded');
    return serviceAccount;
  } catch (error) {
    log('red', 'ERROR', `Failed to load service account: ${error.message}`);
    process.exit(1);
  }
}

// ===== AUTHENTICATE WITH GOOGLE =====
async function authenticateGoogle(serviceAccount) {
  try {
    const client = new JWT({
      email: serviceAccount.client_email,
      key: serviceAccount.private_key,
      scopes: ['https://www.googleapis.com/auth/indexing']
    });
    
    const res = await client.authorize();
    log('green', 'AUTH', 'Google Indexing API authenticated');
    return client;
  } catch (error) {
    log('red', 'ERROR', `Google authentication failed: ${error.message}`);
    process.exit(1);
  }
}

// ===== GENERATE FILE URL =====
function generateFileURL(file) {
  // Format: https://www.vidyari.com/file/Oops-with-java-module-5-EDU-YODHA-lz4ap/698caaebdfc55d3ef9a159be
  const slug = file.slug || file.filename
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .toLowerCase()
    .substring(0, 50);
  
  const fileId = file._id.toString();
  return `${DOMAIN}/file/${slug}/${fileId}`;
}

// ===== CONNECT TO MONGODB =====
async function connectMongoDB() {
  try {
    await mongoose.connect(MONGODB_URI);
    log('green', 'DB', 'Connected to MongoDB');
  } catch (error) {
    log('red', 'ERROR', `MongoDB connection failed: ${error.message}`);
    process.exit(1);
  }
}

// ===== FETCH ALL FILES =====
async function fetchAllFiles() {
  try {
    const files = await File.find().lean();
    log('cyan', 'FILES', `Found ${files.length} files in database`);
    return files;
  } catch (error) {
    log('red', 'ERROR', `Failed to fetch files: ${error.message}`);
    process.exit(1);
  }
}

// ===== PREVIEW MODE =====
async function previewMode(files) {
  log('yellow', 'PREVIEW', `Showing first 10 files that will be indexed:`);
  console.log('');
  
  files.slice(0, 10).forEach((file, index) => {
    const url = generateFileURL(file);
    console.log(`  ${colors.cyan}${index + 1}.${colors.reset} ${file.filename}`);
    console.log(`     ${colors.blue}${url}${colors.reset}`);
  });
  
  console.log('');
  log('yellow', 'STATS', `Total files to be indexed: ${files.length}`);
  log('yellow', 'INFO', `Run with --apply to submit all URLs to Google Indexing API`);
}

// ===== IMPROVED BATCH SUBMISSION WITH RETRY =====
async function submitURLsToGoogle(authClient, fileURLs) {
  log('magenta', 'SUBMIT', `Submitting ${fileURLs.length} URLs to Google Indexing API...`);
  console.log('');
  
  let successful = 0;
  let failed = 0;
  let skipped = 0;
  
  // Get access token
  let accessToken;
  try {
    const token = await authClient.getAccessToken();
    accessToken = token.token;
  } catch (error) {
    log('red', 'ERROR', `Failed to get access token: ${error.message}`);
    return { successful: 0, failed: fileURLs.length, skipped: 0 };
  }
  
  for (let i = 0; i < fileURLs.length; i++) {
    const url = fileURLs[i];
    
    try {
      // Show progress every 10 URLs
      if ((i + 1) % 10 === 0 || i === 0) {
        process.stdout.write(`\r${colors.cyan}Submitted: ${i + 1}/${fileURLs.length}${colors.reset}`);
      }
      
      await submitURLToGoogle(accessToken, url);
      successful++;
      
      // Add small delay to avoid rate limiting
      if ((i + 1) % 10 === 0) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    } catch (error) {
      if (error.message && error.message.includes('quotaExceeded')) {
        log('yellow', 'QUOTA', `Daily quota reached at URL ${i + 1}. Continue tomorrow.`);
        log('yellow', 'STATS', `Submitted ${successful} URLs before quota limit`);
        break;
      } else if (error.message && error.message.includes('duplicate')) {
        skipped++;
      } else {
        failed++;
        if (i < 5 || (i + 1) % 20 === 0) {
          log('yellow', 'WARN', `Error with URL ${i + 1}: ${error.message.substring(0, 60)}`);
        }
      }
    }
  }
  
  console.log(''); // New line after progress
  console.log('');
  log('green', 'COMPLETE', `Indexing request batch complete`);
  log('green', 'SUCCESS', `${successful} URLs submitted to Google`);
  if (skipped > 0) log('yellow', 'SKIPPED', `${skipped} URLs already known to Google`);
  if (failed > 0) log('yellow', 'FAILED', `${failed} URLs failed (may retry)`);
  
  return { successful, failed, skipped };
}

// ===== SUBMIT SINGLE URL TO GOOGLE =====
function submitURLToGoogle(accessToken, url) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      url: url,
      type: 'URL_UPDATED'
    });
    
    const options = {
      hostname: 'indexing.googleapis.com',
      path: '/v3/urlNotifications:publish',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Authorization': `Bearer ${accessToken}`
      }
    };
    
    const req = https.request(options, (res) => {
      let data = '';
      
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true });
        } else if (res.statusCode === 429) {
          // Rate limit
          reject(new Error('quotaExceeded: Daily limit reached'));
        } else if (res.statusCode === 400) {
          const error = JSON.parse(data);
          if (error.error && error.error.message && error.error.message.includes('duplicate')) {
            reject(new Error('duplicate: URL already submitted'));
          } else {
            reject(new Error(`Bad request: ${error.error.message}`));
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    });
    
    req.on('error', error => {
      reject(error);
    });
    
    req.write(payload);
    req.end();
  });
}

// ===== STATUS MODE =====
async function statusMode(files) {
  log('yellow', 'STATUS', 'Checking indexing status in Google Search Console...');
  console.log('');
  log('blue', 'INFO', 'Status checking requires manual GSC review:');
  console.log(`  1. Visit: https://search.google.com/search-console`);
  console.log(`  2. Select property: ${DOMAIN}`);
  console.log(`  3. Go to Coverage report → Valid section`);
  console.log(`  4. Some files may show as "Submitted, not indexed" (wait 24-48 hours)`);
  console.log('');
  log('yellow', 'STATS', `Total files in system: ${files.length}`);
  log('yellow', 'INFO', 'Most files should be indexed within 24-48 hours after submission');
}

// ===== MAIN EXECUTION =====
async function main() {
  const args = process.argv.slice(2);
  const mode = args[0] || '--preview';
  
  console.log('');
  log('cyan', 'START', '═══════════════════════════════════════════════════════');
  log('cyan', 'TOOL', 'BATCH INDEX ALL FILES - Google Indexing API');
  log('cyan', 'DOMAIN', DOMAIN);
  console.log('');
  
  // Load service account
  const serviceAccount = await loadServiceAccount();
  
  // Connect to MongoDB
  await connectMongoDB();
  
  // Fetch all files
  const files = await fetchAllFiles();
  
  if (files.length === 0) {
    log('red', 'ERROR', 'No files found to index');
    process.exit(1);
  }
  
  // Generate URLs
  const fileURLs = files.map(generateFileURL);
  
  if (mode === '--preview') {
    // Preview mode
    await previewMode(files);
  } 
  else if (mode === '--status') {
    // Status check mode
    await statusMode(files);
  }
  else if (mode === '--apply') {
    // Apply mode - actually submit to Google
    log('yellow', 'WARNING', 'Submitting to Google Indexing API (Google may rate-limit after 100 URLs/day)');
    console.log('');
    
    const authClient = await authenticateGoogle(serviceAccount);
    
    // Submit all URLs
    const result = await submitURLsToGoogle(authClient, fileURLs);
    
    console.log('');
    log('green', 'NEXT', `Next steps:`);
    console.log(`  1. Wait 24-48 hours for Google to crawl and index URLs`);
    console.log(`  2. Check Google Search Console Coverage report: https://search.google.com/search-console`);
    console.log(`  3. Monitor your rankings in GSC Performance report`);
    console.log(`  4. If not all indexed, run this script again tomorrow (${Math.ceil(fileURLs.length / 100)} batches needed)`);
    
  } else {
    log('red', 'ERROR', `Unknown mode: ${mode}`);
    console.log('');
    log('blue', 'USAGE', 'Available modes:');
    console.log(`  node batch-index-all-files.js --preview   (show URLs to be indexed)`);
    console.log(`  node batch-index-all-files.js --apply     (submit to Google)`);
    console.log(`  node batch-index-all-files.js --status    (check status in GSC)`);
    process.exit(1);
  }
  
  // Cleanup
  await mongoose.disconnect();
  log('cyan', 'DONE', '═══════════════════════════════════════════════════════');
  console.log('');
}

// Run main
main().catch(error => {
  log('red', 'FATAL', error.message);
  process.exit(1);
});
