const mongoose = require("mongoose");

const userdownloadsSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    filename: { type: String, required: true },
    fileId: { type: String, required: true },
    fileUrl: { type: String, required: true },
    fileType: { type: String, required: true },
  },
  { timestamps: true }
);

// ✅ Uniqueness per user + file combination
userdownloadsSchema.index({ userId: 1, fileId: 1 }, { unique: true });

module.exports = mongoose.model("UserDownload", userdownloadsSchema);
