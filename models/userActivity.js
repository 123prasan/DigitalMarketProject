const mongoose = require('mongoose');

// User Activity Tracking Schema
const userActivitySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'userData',
      required: true,
      index: true,
    },
    sessionId: {
      // Unique session identifier for grouping activities
      type: String,
      required: true,
      index: true,
    },
    activityType: {
      type: String,
      enum: [
        'page_view',
        'click',
        'search',
        'time_spent',
        'lesson_start',
        'lesson_complete',
        'file_preview',
        'file_download',
        'review_submit',
        'comment_post',
        'purchase_view',
        'cart_add',
        'filter_apply',
        'sort_apply',
        'category_affinity',
        'wishlist_add',
      ],
      required: true,
      index: true,
    },
    pageType: {
      type: String,
      enum: ['course', 'file', 'search', 'dashboard', 'profile', 'home', 'category', 'other'],
      index: true,
    },
    courseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Course',
      index: true,
    },
    fileId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'file',
      index: true,
    },
    lessonId: {
      type: String,
      // lesson IDs are embedded in course modules
    },
    elementClicked: {
      // For click events - what element was clicked
      type: String,
      // e.g., "like-btn", "download-btn", "review-btn", "lesson-item"
    },
    searchQuery: {
      type: String,
      // For search activities
    },
    searchResults: {
      type: Number,
      // Number of search results returned
    },
    timeSpentSeconds: {
      type: Number,
      // Duration spent on a page/lesson in seconds
      default: 0,
    },
    scrollDepth: {
      type: Number,
      // Percentage of page scrolled (0-100)
      min: 0,
      max: 100,
    },
    referrer: {
      type: String,
      // What page/filter led to this activity
    },
    userAgent: {
      type: String,
      // Browser info for device tracking
    },
    ipAddress: {
      type: String,
      // Anonymized or hashed IP
    },
    metadata: {
      // Flexible field for additional context
      type: mongoose.Schema.Types.Mixed,
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
      expire: 7776000, // Auto-delete after 90 days
    },
  },
  { timestamps: true }
);

// Index for common queries
userActivitySchema.index({ userId: 1, activityType: 1, createdAt: -1 });
userActivitySchema.index({ userId: 1, courseId: 1, createdAt: -1 });
userActivitySchema.index({ userId: 1, fileId: 1, createdAt: -1 });
userActivitySchema.index({ sessionId: 1, createdAt: -1 });

// Aggregation helper to get user activity summary
userActivitySchema.statics.getUserActivitySummary = async function (userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return await this.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate },
      },
    },
    {
      $group: {
        _id: '$activityType',
        count: { $sum: 1 },
        avgTimeSpent: { $avg: '$timeSpentSeconds' },
      },
    },
    {
      $sort: { count: -1 },
    },
  ]);
};

// Get user's top interests (courses/files viewed/interacted with most)
userActivitySchema.statics.getUserInterests = async function (userId, limit = 10) {
  return await this.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        $or: [{ courseId: { $exists: true, $ne: null } }, { fileId: { $exists: true, $ne: null } }],
      },
    },
    {
      $group: {
        _id: {
          courseId: '$courseId',
          fileId: '$fileId',
        },
        interactionCount: { $sum: 1 },
        timeSpent: { $sum: '$timeSpentSeconds' },
        lastInteraction: { $max: '$createdAt' },
        activityTypes: { $push: '$activityType' },
      },
    },
    {
      $sort: { interactionCount: -1, timeSpent: -1 },
    },
    {
      $limit: limit,
    },
  ]);
};

// Get trending courses/files based on collective user activities
userActivitySchema.statics.getTrendingContent = async function (days = 7, limit = 10) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return await this.aggregate([
    {
      $match: {
        createdAt: { $gte: startDate },
        $or: [{ courseId: { $exists: true, $ne: null } }, { fileId: { $exists: true, $ne: null } }],
      },
    },
    {
      $group: {
        _id: {
          courseId: '$courseId',
          fileId: '$fileId',
        },
        totalInteractions: { $sum: 1 },
        uniqueUsers: { $addToSet: '$userId' },
        avgTimeSpent: { $avg: '$timeSpentSeconds' },
      },
    },
    {
      $addFields: {
        uniqueUserCount: { $size: '$uniqueUsers' },
      },
    },
    {
      $sort: { uniqueUserCount: -1, totalInteractions: -1 },
    },
    {
      $limit: limit,
    },
  ]);
};

module.exports = mongoose.model('userActivity', userActivitySchema);
