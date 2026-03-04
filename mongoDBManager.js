/**
 * Smart MongoDB Connection Manager
 * Automatically detects and handles MongoDB connection issues
 * Add this at the top of your server.js before mongoose.connect()
 */

require('dotenv').config();
const mongoose = require('mongoose');

// MongoDB Connection Manager
class MongoDBManager {
  constructor() {
    this.localUri = 'mongodb://localhost:27017/documents';
    this.atlasUri = process.env.MONGODB_URI;
    this.currentUri = this.atlasUri;
    this.retryAttempts = 3;
    this.retryDelay = 2000;
  }

  /**
   * Get the current connection URI
   */
  getUri() {
    return this.currentUri;
  }

  /**
   * Test if local MongoDB is available
   */
  async isLocalAvailable() {
    try {
      const testConnection = await mongoose.connect(this.localUri, {
        serverSelectionTimeoutMS: 3000,
      });
      await mongoose.disconnect();
      console.log('✅ Local MongoDB is available');
      return true;
    } catch (error) {
      console.log('⚠️ Local MongoDB not available');
      return false;
    }
  }

  /**
   * Test if Atlas is available
   */
  async isAtlasAvailable() {
    try {
      const testConnection = await mongoose.connect(this.atlasUri, {
        serverSelectionTimeoutMS: 5000,
      });
      await mongoose.disconnect();
      console.log('✅ MongoDB Atlas is available');
      return true;
    } catch (error) {
      console.log('⚠️ MongoDB Atlas not available:', error.message.split('\n')[0]);
      return false;
    }
  }

  /**
   * Smart connect with fallback
   */
  async smartConnect(useLocalFallback = true) {
    console.log('\n🔌 MongoDB Connection Manager Started\n');
    console.log('═'.repeat(60));

    try {
      console.log('🔄 Attempting Atlas connection...');
      await this.connectWithRetry(this.atlasUri);
      this.currentUri = this.atlasUri;
      console.log('✅ Connected to MongoDB Atlas\n');
      return true;

    } catch (atlasError) {
      console.error('❌ Atlas connection failed\n');

      if (useLocalFallback) {
        console.log('⏳ Attempting local MongoDB fallback...');
        try {
          await this.connectWithRetry(this.localUri);
          this.currentUri = this.localUri;
          console.log('\n⚠️  Using LOCAL MongoDB (development mode)');
          console.log('📌 Please fix MongoDB Atlas connection for production\n');
          return true;

        } catch (localError) {
          console.error('❌ Local MongoDB also failed\n');
          this.printTroubleshooting(atlasError);
          return false;
        }
      } else {
        this.printTroubleshooting(atlasError);
        return false;
      }
    }
  }

  /**
   * Connect with retry logic
   */
  async connectWithRetry(uri, attempt = 1) {
    try {
      await mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 10000,
        socketTimeoutMS: 45000,
        retryWrites: true,
      });
      return true;

    } catch (error) {
      if (attempt < this.retryAttempts) {
        console.log(`  ⏳ Retry attempt ${attempt + 1}/${this.retryAttempts}...`);
        await this.delay(this.retryDelay);
        return this.connectWithRetry(uri, attempt + 1);
      }
      throw error;
    }
  }

  /**
   * Delay helper
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Print troubleshooting guide
   */
  printTroubleshooting(error) {
    console.log('\n🔧 Troubleshooting Guide\n');
    console.log('═'.repeat(60));

    const errorCode = error.code || error.message;

    console.log('\n📋 Most Common Issues:\n');

    console.log('1️⃣  MongoDB Atlas Cluster Paused:');
    console.log('   ✓ Go to https://cloud.mongodb.com');
    console.log('   ✓ Find cluster0 and click "Resume"');
    console.log('   ✓ Wait 2-3 minutes for startup\n');

    console.log('2️⃣  IP Whitelist Not Configured:');
    console.log('   ✓ Go to Network Access in MongoDB Atlas');
    console.log('   ✓ Click "+Add IP Address"');
    console.log('   ✓ Add 0.0.0.0/0 (temporary) or your IP address');
    console.log('   ✓ Wait 5-10 minutes for propagation\n');

    console.log('3️⃣  Invalid Credentials:');
    console.log('   ✓ Go to Database Access in MongoDB Atlas');
    console.log('   ✓ Reset password for database user');
    console.log('   ✓ Update MONGODB_URI in .env file\n');

    console.log('4️⃣  Use Local MongoDB (Development):');
    console.log('   ✓ Download MongoDB Community: https://www.mongodb.com/try/download/community');
    console.log('   ✓ Install and run: net start MongoDB (Windows)');
    console.log('   ✓ Update .env: MONGODB_URI=mongodb://localhost:27017/documents\n');

    console.log('Error Details:', errorCode, '\n');
  }
}

// Usage in server.js:
// 
// const dbManager = new MongoDBManager();
// await dbManager.smartConnect(true); // true = use local fallback
//
// OR keep it simple and just use:
//
// mongoose.connect(process.env.MONGODB_URI, {...})

module.exports = MongoDBManager;
