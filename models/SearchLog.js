const mongoose = require("mongoose");

const searchLogSchema = new mongoose.Schema(
  {
    query: {
      type: String,
      required: true,
      index: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },
    userAgent: {
      type: String,
      default: null
    },
    ipAddress: {
      type: String,
      default: null
    },
    resultsCount: {
      type: Number,
      default: 0
    },
    clicked: {
      type: Boolean,
      default: false
    },
    clickedItemId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null
    },
    clickedItemType: {
      type: String,
      enum: ['file', 'course'],
      default: null
    },
    duration: {
      type: Number,
      default: 0 // milliseconds spent on search results
    },
    filters: {
      type: Object,
      default: {}
    },
    sortBy: {
      type: String,
      default: 'relevance'
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    }
  },
  { timestamps: true }
);

// TTL index: Auto-delete old logs after 90 days
searchLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 7776000 });

module.exports = mongoose.model("SearchLog", searchLogSchema);
