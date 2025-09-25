const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

  type: { 
    type: String, 
    enum: ["system", "purchase", "report", "comment", "follow"], 
    default: "system" 
  },

  message: { type: String, required: true },

  isRead: { type: Boolean, default: false },

  link: { type: String }, // frontend route or URL to open
  targetId: { type: mongoose.Schema.Types.ObjectId }, // e.g. File, Course, etc.

}, { timestamps: true });

module.exports = mongoose.model("Notification", notificationSchema);
