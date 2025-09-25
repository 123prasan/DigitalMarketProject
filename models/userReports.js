const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // user being reported
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // who reported
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "File", required: true }, // product/file/course

  reason: { type: String, required: true }, // could be "spam", "abuse", etc.
  details: { type: String }, // optional extra description

  resolved: { type: Boolean, default: false },
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // admin/mod who resolved
  resolutionNote: { type: String },

}, { timestamps: true });

module.exports = mongoose.model("Report", reportSchema);
