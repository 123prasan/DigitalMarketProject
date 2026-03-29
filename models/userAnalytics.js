const mongoose = require('mongoose');

// User Analytics Schema - aggregates device, browsing, and behavior data
const userAnalyticsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },

  // Device Information
  deviceInfo: {
    deviceType: String, // mobile, tablet, desktop
    browser: String, // Chrome, Firefox, Safari, etc.
    os: String, // Windows, MacOS, Linux, Android, iOS
    screenResolution: String, // 1920x1080
    timezone: String,
    language: String,
    connectionSpeed: String, // 4g, 3g, slow-2g, unknown
    lastUpdated: { type: Date, default: Date.now },
  },

  // Category Affinity - user preference for content categories
  categoryAffinity: {
    type: Map,
    of: {
      visits: Number, // How many times visited
      totalTimeSeconds: Number, // Total time spent
      averageTimePerVisit: Number, // Calculated field
      lastVisit: Date,
    },
    default: new Map(),
  },

  // Browsing Path Analytics
  browsingPath: {
    totalPagesVisited: Number,
    avgTimePerPage: Number,
    mostVisitedPageType: String,
    bounceRate: Number, // % of single-page sessions
    lastPathSequence: [String], // Last 10 page types visited
    lastUpdated: { type: Date, default: Date.now },
  },

  // Review Interaction Data
  reviewAnalytics: {
    reviewsViewed: Number,
    reviewsSubmitted: Number,
    averageRatingGiven: Number,
    reviewsMarkedHelpful: Number,
    reviewsReported: Number,
    lastReviewDate: Date,
  },

  // Cart Abandonment Metrics
  cartAnalytics: {
    cartCreated: Number, // How many times user initiated cart
    avgItemsPerCart: Number,
    checkoutAttempts: Number, // How many times started checkout
    checkoutCompletionRate: Number, // % of checkouts completed
    avgTimeToCheckout: Number, // Seconds
    abandonedCarts: Number, // Times added items but didn't purchase
    lastCheckoutAttempt: Date,
    totalSpentViaCart: Number, // Total amount purchased through cart
  },

  // Engagement Score (0-100)
  engagementScore: {
    score: { type: Number, default: 0, min: 0, max: 100 },
    factors: {
      activityFrequency: Number, // 0-25
      contentDiversity: Number, // 0-25 (different categories)
      reviewParticipation: Number, // 0-25
      purchaseFrequency: Number, // 0-25
    },
    lastCalculated: Date,
  },

  // Cohort Analysis
  cohorts: {
    acquisitionDate: Date,
    lifetimeValue: Number,
    segment: String, // 'high-value', 'regular', 'at-risk', 'inactive'
    churnRisk: { type: Number, default: 0, min: 0, max: 1 }, // 0-1 risk score
    lastActivityDate: Date,
  },

  // Time-based Analytics
  timePatterns: {
    preferredAccessTime: String, // morning, afternoon, evening, night
    weekdayVsWeekend: {
      weekdayActivity: Number, // % of activity on weekdays
      weekendActivity: Number, // % of activity on weekends
    },
    seasonalPreference: String, // Q1, Q2, Q3, Q4
  },

  // Metadata
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastSyncedAt: Date,
});

// Index for faster queries
userAnalyticsSchema.index({ userId: 1, updatedAt: -1 });
userAnalyticsSchema.index({ 'cohorts.segment': 1 });
userAnalyticsSchema.index({ 'engagementScore.score': -1 });

// Update timestamp on save
userAnalyticsSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('UserAnalytics', userAnalyticsSchema);
