const mongoose = require("mongoose");

const fileReviewSchema = new mongoose.Schema({
  fileId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "doccollection",
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5,
  },
  title: {
    type: String,
    required: true,
    maxlength: 100,
  },
  reviewText: {
    type: String,
    required: true,
    maxlength: 1000,
  },
  helpful: {
    type: Number,
    default: 0, // Count of users who found this review helpful
  },
}, {
  timestamps: true  // This automatically adds createdAt and updatedAt
});

// Index for faster queries
fileReviewSchema.index({ fileId: 1, createdAt: -1 });
fileReviewSchema.index({ userId: 1 });

module.exports = mongoose.model("FileReview", fileReviewSchema);