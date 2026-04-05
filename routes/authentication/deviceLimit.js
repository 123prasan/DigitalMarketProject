const UserSession = require('../../models/UserSession');

/**
 * Middleware to enforce device limit of 1 active session per user
 * This should be used after JWT authentication middleware
 */
const enforceDeviceLimit = async (req, res, next) => {
  try {
    // Skip if user is not authenticated
    if (!req.user) {
      return next();
    }

    const userId = req.user._id;
    const sessionToken = req.cookies?.token || req.cookies?.jwt || req.header('Authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return next();
    }

    // Get client information for device fingerprinting
    const ipAddress = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || '';
    const deviceInfo = generateDeviceFingerprint(req);

    // Check if session exists, create if not
    let userSession = await UserSession.findOne({ sessionToken, userId });

    if (!userSession) {
      // Create new session
      userSession = new UserSession({
        userId,
        sessionToken,
        deviceInfo,
        ipAddress,
        userAgent,
        isActive: true,
        lastActivity: new Date()
      });
      await userSession.save();
    } else {
      // Update existing session activity
      userSession.lastActivity = new Date();
      await userSession.save();
    }

    // Enforce device limit (keep only 1 active session)
    const deactivatedCount = await UserSession.enforceDeviceLimit(userId, sessionToken);

    if (deactivatedCount > 0) {
      console.log(`Device limit enforced for user ${userId}: deactivated ${deactivatedCount} old sessions`);
    }

    // Check if current session is still active
    if (!userSession.isActive) {
      return res.status(401).json({
        error: 'Session expired due to device limit',
        message: 'You have been logged out because you logged in from another device.'
      });
    }

    next();
  } catch (error) {
    console.error('Device limit middleware error:', error);
    // Don't block the request on middleware errors, just log and continue
    next();
  }
};

/**
 * Generate a simple device fingerprint from request headers
 */
function generateDeviceFingerprint(req) {
  const userAgent = req.get('User-Agent') || '';
  const acceptLanguage = req.get('Accept-Language') || '';
  const acceptEncoding = req.get('Accept-Encoding') || '';

  // Create a simple hash-like fingerprint
  const fingerprint = `${userAgent}|${acceptLanguage}|${acceptEncoding}`;
  return Buffer.from(fingerprint).toString('base64').substring(0, 50);
}

/**
 * Middleware to clean up expired sessions periodically
 * This can be called on application startup or via a cron job
 */
const cleanupExpiredSessions = async () => {
  try {
    const result = await UserSession.cleanupExpiredSessions();
    console.log(`Cleaned up ${result.modifiedCount} expired sessions`);
  } catch (error) {
    console.error('Error cleaning up expired sessions:', error);
  }
};

module.exports = {
  enforceDeviceLimit,
  cleanupExpiredSessions
};