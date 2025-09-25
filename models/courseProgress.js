// In /models/userProgressModel.js

const mongoose = require("mongoose");

const progressItemSchema = new mongoose.Schema({
    // NOTE: The ref to 'submoduleSchema' from your example is removed.
    // We store the ObjectId of the lesson directly, as it's an embedded document.
    lessonId: { type: mongoose.Schema.Types.ObjectId, required: true },
    status: { 
        type: String, 
        enum: ["not_started", "in_progress", "completed"],
        default: "not_started"
    },
    percentage: { type: Number, default: 0 },
    updatedAt: { type: Date, default: Date.now }
});

const userProgressSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    courseId: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
    progress: [progressItemSchema],
    lastAccessed: { type: mongoose.Schema.Types.ObjectId }, // The _id of the last submodule
}, { timestamps: true });

// Create a compound index to ensure a user has only one progress document per course
userProgressSchema.index({ userId: 1, courseId: 1 }, { unique: true });

module.exports = mongoose.model("UserProgress", userProgressSchema);