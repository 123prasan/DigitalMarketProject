const mongoose = require('mongoose');

const userSessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  sessionToken: {
    type: String,
    required: true,
    unique: true
  },
  deviceInfo: {
    type: String,
    default: ''
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    default: ''
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastActivity: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for efficient queries
userSessionSchema.index({ userId: 1, isActive: 1 });
userSessionSchema.index({ sessionToken: 1 });
userSessionSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 }); // Auto-expire sessions after 30 days

// Method to update last activity
userSessionSchema.methods.updateActivity = function() {
  this.lastActivity = new Date();
  return this.save();
};

// Static method to get active sessions for a user
userSessionSchema.statics.getActiveSessions = function(userId) {
  return this.find({ userId, isActive: true }).sort({ lastActivity: -1 });
};

// Static method to deactivate old sessions (keep only the most recent one)
userSessionSchema.statics.enforceDeviceLimit = async function(userId, currentSessionToken) {
  const activeSessions = await this.getActiveSessions(userId);

  if (activeSessions.length <= 1) {
    return; // No limit exceeded
  }

  // Keep only the current session, deactivate others
  const sessionsToDeactivate = activeSessions.filter(session =>
    session.sessionToken !== currentSessionToken
  );

  for (const session of sessionsToDeactivate) {
    session.isActive = false;
    await session.save();
  }

  return sessionsToDeactivate.length;
};

// Static method to clean up expired sessions
userSessionSchema.statics.cleanupExpiredSessions = function() {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  return this.updateMany(
    { lastActivity: { $lt: thirtyDaysAgo } },
    { isActive: false }
  );
};

module.exports = mongoose.model('UserSession', userSessionSchema);