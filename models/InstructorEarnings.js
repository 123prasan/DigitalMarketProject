const mongoose = require("mongoose");

const instructorEarningsSchema = new mongoose.Schema(
  {
    // Identifiers
    earningsId: {
      type: String,
      unique: true,
      required: true,
      default: () => "EARN_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
    },

    // User Info
    instructorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Payment Reference
    paymentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "CoursePayment",
      required: true,
    },
    courseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
      required: true,
    },

    // Earnings Breakdown
    grossAmount: {
      type: Number,
      required: true,
      min: 0,
    },
    platformFeeDeducted: {
      type: Number,
      required: true,
      default: 0,
      min: 0,
    },
    taxDeducted: {
      type: Number,
      required: true,
      default: 0,
      min: 0,
    },
    netEarnings: {
      type: Number,
      required: true,
      min: 0,
    },
    currency: {
      type: String,
      default: "INR",
      enum: ["INR", "USD", "EUR"],
    },

    // Status
    status: {
      type: String,
      enum: ["PENDING", "AVAILABLE", "PROCESSING", "PAID", "CANCELLED", "REFUNDED", "REFUND_PENDING"],
      default: "PENDING",
    },
    payoutId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "InstructorPayout",
    },
    paidAt: Date,

    // Refund details
    refundAmount: Number,
    refundReason: String,
    refundRequest: mongoose.Schema.Types.Mixed, // { amount, reason, requestedAt }
    refundedAt: Date,

    // Metadata
    notes: String,

    // Timestamps
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { 
    timestamps: true
  }
);

// Create indexes
instructorEarningsSchema.index({ instructorId: 1 });
instructorEarningsSchema.index({ paymentId: 1 });
instructorEarningsSchema.index({ courseId: 1 });
instructorEarningsSchema.index({ status: 1 });
instructorEarningsSchema.index({ createdAt: -1 });

// Auto-update updatedAt
instructorEarningsSchema.pre("save", async function () {
  this.updatedAt = new Date();
});

module.exports = mongoose.model("InstructorEarnings", instructorEarningsSchema);
