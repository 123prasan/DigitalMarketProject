const express = require("express");
const router = express.Router();
const CourseReview = require("../models/CourseReview");
const Course = require("../models/course");
const mongoose = require("mongoose");

// Import authentication middleware
const authenticateJWT = require("./authentication/jwtAuth");

/**
 * @desc    Submit a review for a course
 * @route   POST /api/reviews/submit
 * @access  Private (requires authentication)
 */
router.post("/submit", authenticateJWT, async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ message: "You must be logged in to submit a review" });
    }

    const { courseId, rating, title, reviewText } = req.body;
    const userId = req.user._id;

    // Validation
    if (!courseId || !rating || !title || !reviewText) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ message: "Rating must be between 1 and 5" });
    }

    // Check if course exists
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    // Check if user already reviewed this course
    const existingReview = await CourseReview.findOne({ courseId, userId });
    if (existingReview) {
      return res.status(400).json({ message: "You have already reviewed this course" });
    }

    // Create new review
    const newReview = new CourseReview({
      courseId,
      userId,
      rating: parseInt(rating),
      title,
      reviewText,
    });

    await newReview.save();

    // Populate reviewer info
    await newReview.populate("userId", "fullName profilePicUrl username");

    // Update course rating and enroll count
    const allReviews = await CourseReview.find({ courseId });
    const totalRating = allReviews.reduce((sum, review) => sum + review.rating, 0);
    const averageRating = totalRating / allReviews.length;

    // Update course with new rating
    await Course.findByIdAndUpdate(courseId, {
      rating: averageRating,
      enrollCount: Math.max(course.enrollCount + 1, allReviews.length), // Ensure enrollCount is at least number of reviews
    });

    res.status(201).json({
      message: "Review submitted successfully",
      review: newReview,
    });
  } catch (error) {
    console.error("Error submitting review:", error);
    res.status(500).json({ message: "Failed to submit review", error: error.message });
  }
});

/**
 * @desc    Get all reviews for a course
 * @route   GET /api/reviews/course/:courseId
 * @access  Public
 */
router.get("/course/:courseId", async (req, res) => {
  try {
    const { courseId } = req.params;

    // Validate course ID
    if (!mongoose.Types.ObjectId.isValid(courseId)) {
      return res.status(400).json({ message: "Invalid course ID" });
    }

    const reviews = await CourseReview.find({ courseId })
      .populate("userId", "fullName profilePicUrl username")
      .sort({ createdAt: -1 })
      .limit(50); // Limit to last 50 reviews

    // Add liked status for authenticated users
    const userId = req.user ? req.user._id : null;
    const reviewsWithLikedStatus = reviews.map(review => {
      const reviewObj = review.toObject();
      reviewObj.isLikedByCurrentUser = userId ? review.likedBy.includes(userId) : false;
      return reviewObj;
    });

    res.status(200).json({
      count: reviews.length,
      reviews: reviewsWithLikedStatus,
    });
  } catch (error) {
    console.error("Error fetching reviews:", error);
    res.status(500).json({ message: "Failed to fetch reviews", error: error.message });
  }
});

/**
 * @desc    Toggle helpful status for a review (like/unlike)
 * @route   POST /api/reviews/:reviewId/helpful
 * @access  Private
 */
router.post("/:reviewId/helpful", authenticateJWT, async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ message: "You must be logged in to mark reviews as helpful" });
    }

    const { reviewId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(reviewId)) {
      return res.status(400).json({ message: "Invalid review ID" });
    }

    // Find the review
    const review = await CourseReview.findById(reviewId);
    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    // Check if user already liked this review
    const userIndex = review.likedBy.indexOf(userId);
    let isLiked = false;

    if (userIndex > -1) {
      // User already liked, so unlike
      review.likedBy.splice(userIndex, 1);
      review.helpful = Math.max(0, review.helpful - 1);
      isLiked = false;
    } else {
      // User hasn't liked, so like
      review.likedBy.push(userId);
      review.helpful = review.helpful + 1;
      isLiked = true;
    }

    await review.save();

    res.status(200).json({
      message: isLiked ? "Review marked as helpful" : "Review unmarked as helpful",
      isLiked,
      helpfulCount: review.helpful,
    });
  } catch (error) {
    console.error("Error toggling review helpful status:", error);
    res.status(500).json({ message: "Failed to update review", error: error.message });
  }
});

/**
 * @desc    Delete a review
 * @route   DELETE /api/reviews/:reviewId
 * @access  Private (only review owner or admin)
 */
router.delete("/:reviewId", authenticateJWT, async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ message: "You must be logged in to delete reviews" });
    }

    const { reviewId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(reviewId)) {
      return res.status(400).json({ message: "Invalid review ID" });
    }

    const review = await CourseReview.findById(reviewId);
    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    // Check if user is the review owner
    if (review.userId.toString() !== userId.toString()) {
      return res.status(403).json({ message: "You can only delete your own reviews" });
    }

    await CourseReview.findByIdAndDelete(reviewId);

    // Recalculate course rating
    const allReviews = await CourseReview.find({ courseId: review.courseId });
    if (allReviews.length === 0) {
      await Course.findByIdAndUpdate(review.courseId, { rating: 0 });
    } else {
      const totalRating = allReviews.reduce((sum, r) => sum + r.rating, 0);
      const averageRating = totalRating / allReviews.length;
      await Course.findByIdAndUpdate(review.courseId, { rating: averageRating });
    }

    res.status(200).json({ message: "Review deleted successfully" });
  } catch (error) {
    console.error("Error deleting review:", error);
    res.status(500).json({ message: "Failed to delete review", error: error.message });
  }
});

module.exports = router;
