/**
 * MongoDB Connection Diagnostic & Fix Script
 * Run this to test and troubleshoot MongoDB connection issues
 */

require('dotenv').config();
const mongoose = require('mongoose');

console.log('🔍 MongoDB Connection Diagnostic Tool\n');
console.log('═'.repeat(50));

// Check if MONGODB_URI is set
if (!process.env.MONGODB_URI) {
  console.error('❌ ERROR: MONGODB_URI not found in .env file');
  process.exit(1);
}

console.log('📝 Connection Details:');
console.log('━'.repeat(50));

// Parse URI (without showing password)
const uri = process.env.MONGODB_URI;
const uriHidden = uri.replace(/:[^:]+@/, ':****@');
console.log(`URI: ${uriHidden}\n`);

// Test connection
async function testConnection() {
  try {
    // some networks (VPNs, WARP etc.) block SRV lookups at the system level;
    // override DNS servers to a known-public resolver before the attempt.
    const dns = require('dns');
    dns.setServers(['1.1.1.1', '8.8.8.8']);

    console.log('⏳ Testing MongoDB connection...\n');
    
    await mongoose.connect(process.env.MONGODB_URI, {
      // Mongoose 7+ enables the new parser and unified topology by default;
      // passing them explicitly will throw an error in newer drivers.
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    console.log('✅ SUCCESS: MongoDB connection established!');
    console.log('\n📊 Connection Info:');
    console.log('━'.repeat(50));
    console.log(`Database: ${mongoose.connection.name}`);
    console.log(`Host: ${mongoose.connection.host}`);
    console.log(`State: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    
    await mongoose.disconnect();
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Connection Failed\n');
    console.error('Error Details:');
    console.error('━'.repeat(50));
    console.error(`Code: ${error.code}`);
    console.error(`Message: ${error.message}\n`);
    
    console.log('🔧 Potential Fixes:\n');
    
    if (error.code === 'ECONNREFUSED' || error.message.includes('querySrv')) {
      console.log('1. ⚪ MongoDB Atlas Cluster Status:');
      console.log('   - Log in to MongoDB Atlas: https://cloud.mongodb.com');
      console.log('   - Check if cluster is running (not paused)');
      console.log('   - Click "Resume" if it\'s paused\n');
      
      console.log('2. 🔐 IP Whitelist:');
      console.log('   - Go to Network Access in MongoDB Atlas');
      console.log('   - Add your IP or use 0.0.0.0/0 (allows all - for testing only)');
      console.log('   - Allow at least 5-10 min for changes to propagate\n');
      
      console.log('3. 🔑 Verify Credentials:');
      console.log('   - Check username and password in MONGODB_URI');
      console.log('   - Ensure special characters are URL encoded\n');
      
      console.log('4. 🌐 Network Connectivity:');
      console.log('   - Check your internet connection');
      console.log('   - Try pinging: ping cluster0.0ytfuyz.mongodb.net\n');
    } else if (error.code === 'ENOTFOUND') {
      console.log('DNS resolution failed. Check:');
      console.log('   - Internet connection');
      console.log('   - MongoDB cluster name in connection string\n');
    } else if (error.message.includes('authentication')) {
      console.log('Authentication failed. Check:');
      console.log('   - Username and password');
      console.log('   - Special character encoding in MONGODB_URI\n');
    }
    
    process.exit(1);
  }
}

testConnection();
