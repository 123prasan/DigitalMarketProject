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

    ISVERIFIED: { type: Boolean, default: false }, // Manual/Follower verification

    isSuspended: { type: Boolean, default: false },
    isBanned: { type: Boolean, default: false },

    DOB: { type: Date },
    location: { type: String },
    instagramUrl: { type: String },
    githubUrl: { type: String },

    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

    // 👇 Subscription & Revenue Fields
    isPro: {
      type: Boolean,
      default: false
    },
    pendingSubscriptionFee: {
      type: Number,
      default: 0 // Debt for the "Pay via Wallet" model
    },
   
    proBillingCycleStart: {
      type: Date
    },
    proBillingCycleEnd: {
      type: Date
    },

    joinedOn: { type: String },
  },
  { timestamps: true }
);

// Pre-save middleware
userSchema.pre("save", function (next) {
  // 1. Remove spaces from username
  if (this.username) {
    this.username = this.username.replace(/\s+/g, "");
  }

  // 2. Set joinedOn only when creating a new document
  if (this.isNew) {
    const d = new Date();
    this.joinedOn = d.toLocaleDateString("en-US", {
      day: "numeric",
      month: "long",
      year: "numeric",
    });
  }

  // 3. Auto-verify based on follower count (Initial Save)
  if (this.followers && this.followers.length >= 1000) {
    this.ISVERIFIED = true;
  }

  next();
});

// Middleware for updates to handle verification based on follower count
userSchema.pre("findOneAndUpdate", function (next) {
  const update = this.getUpdate();

  // Check if followers are being updated
  if (update.$push?.followers || update.$addToSet?.followers || update.followers) {
    this.model.findOne(this.getQuery()).then((doc) => {
      if (!doc) return next();

      const currentCount = doc.followers ? doc.followers.length : 0;
      let newCount = currentCount;

      if (update.$push?.followers || update.$addToSet?.followers) {
        newCount += 1;
      } else if (update.followers) {
        newCount = update.followers.length;
      }

      if (newCount >= 1000) {
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

module.exports = mongoose.models.User || mongoose.model("User", userSchema);