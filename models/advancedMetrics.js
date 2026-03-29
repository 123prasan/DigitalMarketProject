const mongoose = require('mongoose');

// Advanced Metrics Schema - stores detailed activity metrics for analysis
const advancedMetricsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },

  // Review & Rating Metrics
  reviews: {
    totalReviewsViewed: { type: Number, default: 0 },
    totalReviewsSubmitted: { type: Number, default: 0 },
    avgRatingSubmitted: { type: Number, min: 1, max: 5 },
    reviewsMarkedHelpful: { type: Number, default: 0 },
    reviewsReported: { type: Number, default: 0 },
    reviewSubmissions: [{
      fileId: mongoose.Schema.Types.ObjectId,
      rating: { type: Number, min: 1, max: 5 },
      reviewLength: Number,
      submittedAt: Date,
      helpfulCount: { type: Number, default: 0 },
    }],
  },

  // Cart Abandonment Metrics
  cartMetrics: {
    cartsCreated: { type: Number, default: 0 },
    cartAbandonments: { type: Number, default: 0 },
    checkoutAttempts: { type: Number, default: 0 },
    completedCheckouts: { type: Number, default: 0 },
    conversionRate: { type: Number, default: 0 }, // % of carts → purchases
    avgCartValue: { type: Number, default: 0 },
    cartAbandonmentDetails: [{
      cartId: String,
      itemsCount: Number,
      cartValue: Number,
      timeInCartSeconds: Number,
      abandonedAt: Date,
      recoveredAt: { type: Date, default: null },
    }],
  },

  // Category Engagement by device type
  categoryEngagementByDevice: {
    type: Map,
    of: {
      mobile: {
        visits: Number,
        timeSpentSeconds: Number,
        conversionRate: Number,
      },
      tablet: {
        visits: Number,
        timeSpentSeconds: Number,
        conversionRate: Number,
      },
      desktop: {
        visits: Number,
        timeSpentSeconds: Number,
        conversionRate: Number,
      },
    },
  },

  // Device Preferences
  devicePreference: {
    mostUsedDevice: String, // mobile, tablet, desktop
    deviceDistribution: {
      mobile: { type: Number, default: 0 }, // %
      tablet: { type: Number, default: 0 }, // %
      desktop: { type: Number, default: 0 }, // %
    },
    crossDeviceCount: { type: Number, default: 1 }, // How many devices used
  },

  // Browsing Path Intelligence
  browsingPathMetrics: {
    totalSessionsTracked: { type: Number, default: 0 },
    avgPagesPerSession: { type: Number, default: 0 },
    avgSessionDurationSeconds: { type: Number, default: 0 },
    commonPathSequences: [{
      sequence: [String], // Path of page types
      frequency: Number,
      conversionRate: Number,
    }],
    bounceRate: { type: Number, default: 0 }, // % of single-page sessions
    exitPageTypes: [String], // Most common exit points
  },

  // Engagement Scoring
  engagementMetrics: {
    engagementScore: { type: Number, default: 0, min: 0, max: 100 },
    scoringComponents: {
      reviewEngagement: { type: Number, default: 0, min: 0, max: 25 },
      categoryDiversity: { type: Number, default: 0, min: 0, max: 25 },
      purchaseFrequency: { type: Number, default: 0, min: 0, max: 25 },
      deviceDiversity: { type: Number, default: 0, min: 0, max: 25 },
    },
    lastScoreCalculation: Date,
  },

  // Churn & Retention Prediction
  churnAnalysis: {
    churnPredictionScore: { type: Number, default: 0, min: 0, max: 1 }, // 0=safe, 1=high risk
    daysInactive: { type: Number, default: 0 },
    daysSinceLastPurchase: { type: Number, default: 0 },
    predictedChurnReason: String, // low_engagement, no_purchases, no_reviews, etc
    retentionInterventions: [{
      intervention: String, // 'discount_offer', 'recommend_new', 'review_reminder', 'cart_recovery'
      suggestedAt: Date,
      executedAt: Date,
      wasEffective: Boolean,
    }],
  },

  // Time-based Patterns
  timePatterns: {
    preferredDayOfWeek: String, // Monday, Tuesday, etc
    preferredHourOfDay: Number, // 0-23
    peakActivityDay: String, // Weekday or Weekend
    seasonalData: {
      Q1_activity: Number,
      Q2_activity: Number,
      Q3_activity: Number,
      Q4_activity: Number,
    },
  },

  // Metadata
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastAnalyzedAt: Date,
});

// Indexes
advancedMetricsSchema.index({ userId: 1, updatedAt: -1 });
advancedMetricsSchema.index({ 'churnAnalysis.churnPredictionScore': -1 });
advancedMetricsSchema.index({ 'engagementMetrics.engagementScore': -1 });

advancedMetricsSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('AdvancedMetrics', advancedMetricsSchema);
