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
  discountPrice: { type: Number },
  thumbnailUrl: { type: String },
  introVideoUrl: { type: String },        // ✅ Intro video URL (uploaded file or external URL)
  title: { type: String, required: true, unique: true },
  slug: { type: String, unique: true, sparse: true }, // URL-friendly version of title
  contentTypeId: { type: mongoose.Schema.Types.ObjectId, ref: "ContentType" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  modules: [moduleSchema],
  tags: [{ type: String }],
  rating: { type: Number, default: 0 },
  enrollCount: { type: Number, default: 0 },
  duration: { type: Number }, // total course duration in minutes (auto-calculated from modules)
  learningOutcomes: [{ type: String }], // What students will learn
  requirements: [{ type: String }], // Course prerequisites and requirements
  level: { type: String, enum: ["Beginner", "Intermediate", "Advanced", "All Levels"], default: "All Levels" }, // Difficulty level
  isFree: { type: Boolean, default: false },
  published: { type: Boolean, default: false },
  version: { type: String },
  releaseDate: { type: Date },
  enrolledStudents: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Students enrolled in course
}, {
  timestamps: true
});

// Pre-save middleware to generate slug from title
courseSchema.pre('save', async function() {
  if ((this.isModified('title') || this.isNew) && this.title) {
    // Generate slug from title: lowercase, replace spaces with hyphens, remove special chars
    this.slug = this.title
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '') // Remove special characters except spaces and hyphens
      .replace(/\s+/g, '-') // Replace spaces with hyphens
      .replace(/-+/g, '-') // Replace multiple hyphens with single hyphen
      .trim(); // Remove leading/trailing whitespace
  }
});

module.exports = mongoose.model("Course", courseSchema);
