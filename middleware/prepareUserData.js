/**
 * Middleware: Prepare User Data for Views
 * 
 * This middleware automatically prepares all user-related data that needs to be sent to views.
 * It runs after JWT authentication and manages caching, data fetching, and CloudFront URL conversion.
 * 
 * Attaches to res.locals.userData with:
 * - isLoggedin: boolean
 * - profileUrl: string (avatar image URL)
 * - username: string | null
 * - useremail: string | null
 * - uId: string | null (user ID as string)
 * 
 * Usage in routes:
 * res.render('page', { ...res.locals.userData });
 * 
 * OR:
 * res.render('page', {
 *   ...res.locals.userData,
 *   customData: value
 * });
 */

const User = require('../models/userData');
const NodeCache = require('node-cache');

// Create cache instance (shared across all requests)
const userDataCache = new NodeCache({ 
  stdTTL: 15 * 60,      // 15 minutes default TTL
  checkperiod: 2 * 60   // Check for expired keys every 2 minutes
});

// CloudFront domain for avatar URLs
const CLOUDFRONT_AVATAR_URL = process.env.CF_DOMAIN_PROFILES_COURSES 
  ? (process.env.CF_DOMAIN_PROFILES_COURSES + "/avatars") 
  : "https://d3epchi0htsp3c.cloudfront.net/avatars";

/**
 * Convert S3 URL to CloudFront URL
 * @param {string} s3Url - The S3 URL
 * @returns {string} The CloudFront URL
 */
function convertToCloudFrontUrl(s3Url) {
  if (!s3Url || typeof s3Url !== 'string') return s3Url;
  
  if (s3Url.includes('s3.')) {
    try {
      const fileName = s3Url.split('/').pop();
      return `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
    } catch (err) {
      console.warn('⚠️ Failed to convert S3 URL to CloudFront:', err.message);
      return s3Url;
    }
  }
  
  return s3Url;
}

/**
 * Main middleware function
 */
const prepareUserData = async (req, res, next) => {
  try {
    // Default user data structure
    const userData = {
      isLoggedin: false,
      profileUrl: '/images/avatar.jpg',
      username: null,
      useremail: null,
      uId: null
    };

    // If user is authenticated
    if (req.user && req.user._id) {
      try {
        const userId = req.user._id.toString ? req.user._id.toString() : String(req.user._id);
        const cacheKey = `user_data_${userId}`;
        
        // Try to get from cache first
        let userFromCache = userDataCache.get(cacheKey);
        let user = userFromCache;
        
        // If not in cache, fetch from database
        if (!user) {
          user = await User.findById(req.user._id)
            .select('_id profilePicUrl username email')
            .lean()
            .exec();
          
          // Store in cache if found
          if (user) {
            userDataCache.set(cacheKey, user);
          }
        }
        
        // If user found, populate userData
        if (user) {
          userData.isLoggedin = true;
          
          // Convert S3 URLs to CloudFront
          const profileUrl = user.profilePicUrl ? convertToCloudFrontUrl(user.profilePicUrl) : null;
          userData.profileUrl = profileUrl || '/images/avatar.jpg';
          
          userData.username = user.username || null;
          userData.useremail = user.email || null;
          userData.uId = user._id.toString();
        } else {
          // User not found in DB, clear authentication
          console.warn(`⚠️ User ${userId} not found in database, clearing auth`);
          req.user = null;
        }
      } catch (dbError) {
        console.error('❌ Error fetching user data from database:', dbError.message);
        // On database error, don't clear auth immediately, just keep defaults
        // This prevents accidental logouts due to temporary DB issues
        userData.isLoggedin = false;
      }
    }
    
    // Attach userData to res.locals for access in all views
    res.locals.userData = userData;
    
    // Also attach as res.locals.auth for compatibility with existing code
    res.locals.auth = userData;
    
    // Call next middleware
    next();
  } catch (err) {
    console.error('❌ Error in prepareUserData middleware:', err);
    // On any error, set safe defaults
    res.locals.userData = {
      isLoggedin: false,
      profileUrl: '/images/avatar.jpg',
      username: null,
      useremail: null,
      uId: null
    };
    res.locals.auth = res.locals.userData;
    next();
  }
};

/**
 * Clear cache for a specific user (call this after user updates)
 * @param {string} userId - The user ID to clear from cache
 */
function clearUserCache(userId) {
  const cacheKey = `user_data_${userId}`;
  userDataCache.del(cacheKey);
}

/**
 * Clear all user data from cache
 */
function clearAllUserCache() {
  userDataCache.flushAll();
}

module.exports = {
  prepareUserData,
  clearUserCache,
  clearAllUserCache,
  userDataCache
};
