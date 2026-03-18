const express = require("express");
const router = express.Router();
const FileReview = require("../models/FileReview");
const File = require("../models/file");
const mongoose = require("mongoose");

// Import authentication middleware
const authenticateJWT = require("./authentication/jwtAuth");

/**
 * @desc    Submit a review for a file
 * @route   POST /api/file-reviews/submit
 * @access  Private (requires authentication)
 */
router.post("/submit", authenticateJWT, async (req, res) => {
  try {
    const { fileId, rating, title, reviewText } = req.body;
    const userId = req.user._id;

    if (!req.user) {
      return res.status(401).json({ message: "Authentication required to submit reviews" });
    }

    // Validation
    if (!fileId || !rating || !title || !reviewText) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ message: "Rating must be between 1 and 5" });
    }

    // Check if file exists
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    // Check if user already reviewed this file
    const existingReview = await FileReview.findOne({ fileId, userId });
    if (existingReview) {
      return res.status(400).json({ message: "You have already reviewed this file" });
    }

    // Create new review
    const newReview = new FileReview({
      fileId,
      userId,
      rating: parseInt(rating),
      title,
      reviewText,
    });

    await newReview.save();

    // Populate reviewer info
    await newReview.populate("userId", "fullName profilePicUrl username");

    // Update file rating (we'll add a rating field to the file model if needed)
    const allReviews = await FileReview.find({ fileId });
    const totalRating = allReviews.reduce((sum, review) => sum + review.rating, 0);
    const averageRating = totalRating / allReviews.length;

    // For now, we'll store the rating in a way that can be retrieved
    // You might want to add a rating field to the File model
    await File.findByIdAndUpdate(fileId, {
      // Add rating field to file model if needed
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
 * @desc    Get all reviews for a file
 * @route   GET /api/file-reviews/file/:fileId
 * @access  Public
 */
router.get("/file/:fileId", async (req, res) => {
  try {
    const { fileId } = req.params;

    // Validate file ID
    if (!mongoose.Types.ObjectId.isValid(fileId)) {
      return res.status(400).json({ message: "Invalid file ID" });
    }

    const reviews = await FileReview.find({ fileId })
      .populate("userId", "fullName profilePicUrl username")
      .sort({ createdAt: -1 })
      .limit(50); // Limit to last 50 reviews

    // Calculate rating distribution
    const ratingDistribution = {
      1: 0, 2: 0, 3: 0, 4: 0, 5: 0
    };

    reviews.forEach(review => {
      ratingDistribution[review.rating] = (ratingDistribution[review.rating] || 0) + 1;
    });

    const totalReviews = reviews.length;
    const averageRating = totalReviews > 0
      ? reviews.reduce((sum, review) => sum + review.rating, 0) / totalReviews
      : 0;

    res.status(200).json({
      count: totalReviews,
      averageRating: Math.round(averageRating * 10) / 10,
      ratingDistribution,
      reviews,
    });
  } catch (error) {
    console.error("Error fetching reviews:", error);
    res.status(500).json({ message: "Failed to fetch reviews", error: error.message });
  }
});

/**
 * @desc    Mark review as helpful
 * @route   POST /api/file-reviews/:reviewId/helpful
 * @access  Private
 */
router.post("/:reviewId/helpful", authenticateJWT, async (req, res) => {
  try {
    const { reviewId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(reviewId)) {
      return res.status(400).json({ message: "Invalid review ID" });
    }

    const review = await FileReview.findByIdAndUpdate(
      reviewId,
      { $inc: { helpful: 1 } },
      { new: true }
    );

    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    res.status(200).json({
      message: "Review marked as helpful",
      review,
    });
  } catch (error) {
    console.error("Error marking review helpful:", error);
    res.status(500).json({ message: "Failed to update review", error: error.message });
  }
});

/**
 * @desc    Delete a review
 * @route   DELETE /api/file-reviews/:reviewId
 * @access  Private (only review owner or admin)
 */
router.delete("/:reviewId", authenticateJWT, async (req, res) => {
  try {
    const { reviewId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(reviewId)) {
      return res.status(400).json({ message: "Invalid review ID" });
    }

    const review = await FileReview.findById(reviewId);
    if (!review) {
      return res.status(404).json({ message: "Review not found" });
    }

    // Check if user is the review owner
    if (review.userId.toString() !== userId.toString()) {
      return res.status(403).json({ message: "You can only delete your own reviews" });
    }

    await FileReview.findByIdAndDelete(reviewId);

    res.status(200).json({ message: "Review deleted successfully" });
  } catch (error) {
    console.error("Error deleting review:", error);
    res.status(500).json({ message: "Failed to delete review", error: error.message });
  }
});

module.exports = router;