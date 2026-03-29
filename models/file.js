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
  category: { type: String, default: 'Uncategorized' },
  imageType:{type:String},
  fileSize: Number,
  downloadCount: { type: Number, default: 0 },
  fileType: { type: String, enum: ["pdf", "docx", "pptx"]},
  likes: { type: Number, default: 0 },
  
  // Security fields
  securityHash: { type: String, default: null }, // SHA256 hash of file for integrity verification
  securityValidated: { type: Boolean, default: false }, // Whether file passed security checks
  validationTimestamp: { type: Date, default: null }, // When security validation occurred
  validationErrors: [String], // Any errors during validation (if failed)
  validationWarnings: [String], // Non-critical warnings
 
  // 1. ADD THE NEW SLUG FIELD
  slug: {
    type: String,
    unique: true, // Slugs should be unique
  },
},{timestamps:true});

// Pre-save hook to auto-generate slug
fileSchema.pre("save", async function() {
  if (this.isModified("filename") || this.isNew) {
    const randomSuffix = (Math.random() + 1).toString(36).substring(7);
    this.slug = `${slugify(this.filename)}-${randomSuffix}`;
  }
});

let File;
if (mongoose.models.doccollection) {
  File = mongoose.models.doccollection;
} else {
  File = mongoose.model("doccollection", fileSchema);
}

module.exports = File;