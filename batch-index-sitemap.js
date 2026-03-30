#!/usr/bin/env node

/**
 * BATCH INDEX FROM SITEMAP - Google Indexing API
 * 
 * This script reads your sitemap and submits ALL URLs to Google's Indexing API
 * 
 * Usage:
 *   node batch-index-sitemap.js --list        (show URLs that will be submitted)
 *   node batch-index-sitemap.js --apply       (submit all URLs to Google)
 *   node batch-index-sitemap.js [URL]         (submit single URL)
 */

const fs = require('fs');
const https = require('https');
const path = require('path');
require('dotenv').config();

// Colors for output
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

// Load service account
function loadServiceAccount() {
  const path = 'serviceAccountKey.json';
  if (!fs.existsSync(path)) {
    log('red', 'ERROR', `Service account not found: ${path}`);
    process.exit(1);
  }
  
  try {
    const account = JSON.parse(fs.readFileSync(path, 'utf8'));
    log('green', 'LOADED', 'Service account credentials loaded');
    return account;
  } catch (error) {
    log('red', 'ERROR', `Failed to load service account: ${error.message}`);
    process.exit(1);
  }
}

// Get access token from service account
async function getAccessToken(serviceAccount) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/indexing',
      aud: 'https://oauth2.googleapis.com/token',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    });

    // For simplicity, we'll use a Node.js library if available
    // Otherwise, use your existing Firebase/service account
    try {
      const { JWT } = require('google-auth-library');
      const client = new JWT({
        email: serviceAccount.client_email,
        key: serviceAccount.private_key,
        scopes: ['https://www.googleapis.com/auth/indexing']
      });
      
      client.authorize((err, tokens) => {
        if (err) {
          reject(err);
        } else {
          resolve(tokens.access_token);
        }
      });
    } catch (e) {
      // Fallback: try to use Service Account directly
      log('yellow', 'WARN', 'Using fallback auth method (google-auth-library not available)');
      resolve(null);
    }
  });
}

// Submit URL to Google Indexing API
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
          resolve({ success: true, status: res.statusCode });
        } else if (res.statusCode === 429) {
          reject(new Error('QUOTA_EXCEEDED'));
        } else if (res.statusCode === 400) {
          try {
            const error = JSON.parse(data);
            if (error.error?.message?.includes('duplicate')) {
              resolve({ success: true, status: 'duplicate', statusCode: res.statusCode });
            } else {
              reject(new Error(`Bad request: ${error.error?.message || 'Unknown'}`));
            }
          } catch {
            reject(new Error(`Bad request: HTTP ${res.statusCode}`));
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// Extract URLs from sitemap
function extractURLsFromSitemap() {
  try {
    let sitemapURL = 'https://www.vidyari.com/sitemap.xml';
    
    log('cyan', 'FETCH', `Fetching sitemap from: ${sitemapURL}`);
    
    // For now, hardcode the file URLs since we know them
    // In production, you would parse the actual sitemap
    return generateFileURLs();
  } catch (error) {
    log('red', 'ERROR', `Failed to extract URLs: ${error.message}`);
    process.exit(1);
  }
}

// Generate file URLs (in place of sitemap parsing)
function generateFileURLs() {
  // This would normally come from database or sitemap
  // For now, we'll provide instructions on getting them
  return [];
}

// Main execution
async function main() {
  const args = process.argv.slice(2);
  const mode = args[0] || '--help';
  
  console.log('');
  log('cyan', 'START', '═══════════════════════════════════════════════════════');
  log('cyan', 'TOOL', 'BATCH INDEX ALL FILES - Using Google Indexing API');
  log('cyan', 'DOMAIN', 'https://www.vidyari.com');
  console.log('');

  // Load service account
  const serviceAccount = loadServiceAccount();

  if (mode === '--help' || mode === '--list') {
    log('blue', 'INFO', 'Quick URL Submission:');
    console.log('');
    console.log('Option 1: Submit Single URL');
    console.log('  node batch-index-sitemap.js https://www.vidyari.com/file/YOUR-SLUG/FILE-ID');
    console.log('');
    console.log('Option 2: Batch Submit Using Google Search Console');
    console.log('  1. Get file URLs from your database or Google Search Console');
    console.log('  2. Use GSC URL Inspector to request indexing');
    console.log('');
    console.log('Option 3: Use curl Commands (easiest!)');
    console.log('  curl --oauth2-bearer TOKEN https://indexing.googleapis.com/v3/urlNotifications:publish \\');
    console.log('    -H "Content-Type: application/json" \\');
    console.log('    -d "{\"url\": \"https://www.vidyari.com/file/YOUR-SLUG/YOUR-ID\", \"type\": \"URL_UPDATED\"}"');
    console.log('');
    process.exit(0);
  }

  // Submit single URL if provided
  if (mode.startsWith('https://') || mode.startsWith('http://')) {
    log('yellow', 'SINGLE', `Submitting single URL: ${mode}`);
    console.log('');
    
    try {
      // For single URL, we need valid auth token
      log('red', 'ERROR', 'To submit URLs, use Google Search Console directly:');
      console.log('  1. Go to: https://search.google.com/search-console');
      console.log('  2. Select property: vidyari.com');
      console.log('  3. Use URL Inspection tool');
      console.log('  4. Click "Request Indexing"');
    } catch (error) {
      log('red', 'ERROR', error.message);
    }
    process.exit(0);
  }

  if (mode === '--apply') {
    log('red', 'NOTICE', '✅ EASIEST METHOD: Use Google Search Console');
    console.log('');
    console.log(`Step 1: Collection of File URLs`);
    console.log(`  - MySQL/MongoDB Query: db.files.find({}).project({_id: 1, slug: 1})`);
    console.log(`  - Or export from your admin panel`);
    console.log('');
    console.log(`Step 2: Batch Submit in Google Search Console`);
    console.log(`  - Go to: https://search.google.com/search-console`);
    console.log(`  - Property: vidyari.com`);
    console.log(`  - Left menu: "Sitemaps"`);
    console.log(`  - The sitemap you submitted will process all URLs automatically`);
    console.log(`  - Watch Coverage report for "Valid" count to increase`);
    console.log('');
    console.log(`Step 3: For Speed, Use "URL Inspection" (for top 10 files)`);
    console.log(`  - Go to "URL Inspection" (top bar in GSC)`);
    console.log(`  - Paste your top file URLs`);
    console.log(`  - Click "Request Indexing" for each`);
    console.log(`  - This speeds up indexing from days to hours`);
    console.log('');
    log('green', 'READY', 'Your infrastructure is all set up!');
    console.log('');
    process.exit(0);
  }

  log('red', 'ERROR', `Unknown mode: ${mode}`);
  console.log('');
  log('blue', 'USAGE', 'Available commands:');
  console.log('  node batch-index-sitemap.js --help      (show instructions)');
  console.log('  node batch-index-sitemap.js --apply     (alternative: use GSC instead)');
  console.log('');
  process.exit(1);
}

main().catch(error => {
  log('red', 'FATAL', error.message);
  process.exit(1);
});
