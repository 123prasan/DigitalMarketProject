const mongoose = require("mongoose");

const userdownloads = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    filename: { type: String, required: true },
    fileId: { type: mongoose.Schema.Types.ObjectId, ref: "File", required: true },
    fileUrl: { type: String, required: true },
    fileType: { type: String, required: true },
  },
  { timestamps: true }
);

// Compound unique index: one user can't download same file twice,
// but different users can download the same file
userdownloads.index({ userId: 1, fileId: 1 }, { unique: true });

module.exports = mongoose.model("userdownloads", userdownloads);
