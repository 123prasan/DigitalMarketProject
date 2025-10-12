const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, trim: true, unique: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    fullName: { type: String },

    // For normal login
    passwordHash: { type: String },

    // For Google login
    googleId: { type: String },

    ph: { type: Number },
    role: {
      type: String,
      enum: ["Buyer", "seller", "Admin"],
      default: "Buyer",
    },

    bio: { type: String, maxlength: 300 },
    isEmailVerified: { type: Boolean, default: false },
    profilePicUrl: { type: String },

    ISVERIFIED: { type: Boolean, default: false },

    isSuspended: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },

    DOB: { type: Date },
    location: { type: String },
    instagramUrl: { type: String },
    githubUrl: { type: String },

    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    
    // 👇 New property for formatted date
    joinedOn: { type: String },
  },
  { timestamps: true }
);

// Remove spaces from username and set joinedOn
userSchema.pre("save", function (next) {
  if (this.username) {
    this.username = this.username.replace(/\s+/g, "");
  }

  // Auto set ISVERIFIED if followers >= 1000
 

  // Set joinedOn only when creating a new document
  if (this.isNew) {
    const d = new Date();
    this.joinedOn = d.toLocaleDateString("en-US", {
      day: "numeric",
      month: "long",
      year: "numeric",
    });
  }

  next();
});

// Also handle updates (findOneAndUpdate, updateOne, etc.)
userSchema.pre("findOneAndUpdate", function (next) {
  const update = this.getUpdate();

  if (update.$push?.followers || update.$addToSet?.followers || update.followers) {
    this.model.findOne(this.getQuery()).then((doc) => {
      const followersCount =
        update.followers?.length ??
        (update.$push?.followers ? doc.followers.length + 1 : doc.followers.length);

      if (followersCount >= 1000) {
        this.set({ ISVERIFIED: true });
      } else {
        this.set({ ISVERIFIED: false });
      }

      next();
    });
  } else {
    next();
  }
});

// const User = mongoose.model("User", userSchema);
module.exports = mongoose.models.User || mongoose.model("User", userSchema);
