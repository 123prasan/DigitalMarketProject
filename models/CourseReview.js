const mongoose = require("mongoose");

const courseReviewSchema = new mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
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
  likedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  }], // Array of users who liked this review
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true
});

// Index for faster queries
courseReviewSchema.index({ courseId: 1, createdAt: -1 });
courseReviewSchema.index({ userId: 1 });

module.exports = mongoose.model("CourseReview", courseReviewSchema);
