const UserProgress = require('../models/courseProgress'); // Ensure this model name is correct
const mongoose = require('mongoose');

/**
 * @desc    Get a user's progress for a specific course
 * @route   GET /api/progress/:courseId
 * @access  Private
 */
exports.getProgressForCourse = async (req, res) => {
    try {
        console.log("user progres colleged")
        const { courseId } = req.params;
        const userId = req.user._id; // From auth middleware

        const progress = await UserProgress.findOne({ userId, courseId });

        // If no progress exists for a new user, return a default structure.
        if (!progress) {
            return res.status(200).json({
                courseId: courseId,
                userId: userId,
                progress: [],
                lastAccessed: null
            });
        }

        res.status(200).json(progress);
    } catch (error) {
        console.error("Error fetching progress:", error);
        res.status(500).json({ message: "Server error while fetching progress." });
    }
};

/**
 * @desc    Update a user's progress for a lesson (Robust Version)
 * @route   POST /api/progress/update
 * @access  Private
 */
exports.updateProgress = async (req, res) => {
    const { courseId, lessonId, status, percentage } = req.body;
    const userId = req.user._id;

    // Log incoming data for easy debugging
    console.log(`[Progress Update] User: ${userId}, Course: ${courseId}, Lesson: ${lessonId}, Status: ${status}, Percent: ${percentage}%`);

    if (!courseId || !lessonId || !status) {
        return res.status(400).json({ message: "courseId, lessonId, and status are required." });
    }

    try {
        const lessonObjectId = new mongoose.Types.ObjectId(lessonId);

        // Find the main progress document.
        let userProgress = await UserProgress.findOne({ userId, courseId });

        // If no progress document exists, create one.
        if (!userProgress) {
            userProgress = await UserProgress.create({
                userId,
                courseId,
                progress: [{ lessonId: lessonObjectId, status, percentage }],
                lastAccessed: lessonObjectId
            });
            console.log("Created new progress document.");
            return res.status(200).json({ message: "Progress created successfully." });
        }

        // If the document exists, find the specific lesson to update.
        const lessonIndex = userProgress.progress.findIndex(p => p.lessonId.equals(lessonObjectId));

        if (lessonIndex > -1) {
            // If lesson exists, update it. Don't overwrite a 'completed' status.
            if (userProgress.progress[lessonIndex].status !== 'completed') {
                 userProgress.progress[lessonIndex].status = status;
                 if (percentage >= 0) {
                    userProgress.progress[lessonIndex].percentage = percentage;
                 }
                 userProgress.progress[lessonIndex].updatedAt = new Date();
            }
        } else {
            // If lesson doesn't exist in the progress array, add it.
            userProgress.progress.push({ lessonId: lessonObjectId, status, percentage });
        }
        
        // Always update the last accessed lesson.
        userProgress.lastAccessed = lessonObjectId;

        await userProgress.save();
        
        console.log("Progress successfully updated in database.");
        res.status(200).json({ message: "Progress updated successfully." });

    } catch (error) {
        console.error("Error updating progress in database:", error);
        res.status(500).json({ message: "Server error while updating progress." });
    }
};
