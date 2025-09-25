const mongoose = require("mongoose");

// Submodule (Lesson) schema
// Submodule (Lesson) schema
const submoduleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  type: { type: String, enum: ["Video", "Document"], required: true },
  fileUrl: { type: String },       // uploaded file path
  externalUrl: { type: String },   // YouTube, Vimeo, etc.
  duration: { type: Number },      // in minutes
  order: { type: Number }
}, { _id: true });   // <-- IMPORTANT: give each submodule its own _id


// Module schema
const moduleSchema = new mongoose.Schema({
  unit: { type: String, required: true },
  submodules: [submoduleSchema],
  order: { type: Number }
}, { _id: true });

// Course schema
const courseSchema = new mongoose.Schema({
  category: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  thumbnailUrl: { type: String },
  title: { type: String, required: true, unique: true },
  discountPrice: { type: Number },
  contentTypeId: { type: mongoose.Schema.Types.ObjectId, ref: "ContentType" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  modules: [moduleSchema],
tags: [{ type: String }],
  rating: { type: Number, default: 0 },
  enrollCount: { type: Number, default: 0 },
  duration: { type: Number }, // total course duration
  isFree: { type: Boolean, default: false },
  published: { type: Boolean, default: false },
  version: { type: String },
  releaseDate: { type: Date },
}, {
  timestamps: true
});

module.exports = mongoose.model("Course", courseSchema);
