const mongoose=require("mongoose")
const slugify = require('slugify');
const fileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  filedescription: String,
  user: String,
  filename: String,
  fileUrl: String,
  storedFilename: String,
  price: {type: Number, required: true, default: 0},
  uploadedAt: { type: Date, default: Date.now },
  category: { type: String, required: true },
  imageType:{type:String},
  fileSize: Number,
  downloadCount: { type: Number, default: 0 },
 fileType: { type: String, enum: ["pdf", "docx", "pptx"]},
  likes: { type: Number, default: 0 },
 
  // 1. ADD THE NEW SLUG FIELD
  slug: {
    type: String,
    unique: true, // Slugs should be unique
  },
},{timestamps:true});

// 2. ADD THIS FUNCTION to automatically create a slug before saving
// This will work for all NEW files you upload in the future.
fileSchema.pre("save", function (next) {
  if (this.isModified("filename") || this.isNew) {
    // Create the slug from the filename and add a unique suffix
    const randomSuffix = (Math.random() + 1).toString(36).substring(7);
    this.slug = `${slugify(this.filename)}-${randomSuffix}`;
  }
  next();
});

const File = mongoose.models.doccollection || mongoose.model("doccollection", fileSchema);

module.exports = File;