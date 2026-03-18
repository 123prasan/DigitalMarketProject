const mongoose = require("mongoose");

const instructorPayoutSchema = new mongoose.Schema(
  {
    // Identifiers
    payoutId: {
      type: String,
      unique: true,
      required: true,
      default: () => "PAYOUT_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
    },

    // Instructor Info
    instructorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    paymentMethodId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Paymentouts",
    },

    // Payout Details
    totalAmount: {
      type: Number,
      required: true,
      min: 0,
    },
    currency: {
      type: String,
      default: "INR",
      enum: ["INR", "USD", "EUR"],
    },
    minimumPayoutThreshold: {
      type: Number,
      default: 500, // Minimum Rs 500 for payout
    },

    // Earnings Included
    earningsIncluded: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "InstructorEarnings",
      },
    ],
    earningsCount: {
      type: Number,
      default: 0,
    },

    // Status
    status: {
      type: String,
      enum: ["PENDING", "APPROVED", "PROCESSING", "COMPLETED", "FAILED", "CANCELLED"],
      default: "PENDING",
    },

    // Payment Gateway Response
    paymentGateway: {
      type: String,
      enum: ["RAZORPAY", "BANK_TRANSFER", "UPI", "STRIPE"],
      default: "RAZORPAY",
    },
    gatewayPayoutId: String,
    gatewayResponse: mongoose.Schema.Types.Mixed,

    // Dates
    requestedAt: {
      type: Date,
      default: Date.now,
    },
    approvedAt: Date,
    processedAt: Date,
    completedAt: Date,
    failedAt: Date,

    // Retry Logic
    failureReason: String,
    failureCode: String,
    retryCount: {
      type: Number,
      default: 0,
    },
    maxRetries: {
      type: Number,
      default: 3,
    },
    nextRetryAt: Date,

    // Verification
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // Admin who approved
    },
    notes: String,
    remarks: String,

    // Audit Trail
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
instructorPayoutSchema.index({ payoutId: 1 });
instructorPayoutSchema.index({ instructorId: 1 });
instructorPayoutSchema.index({ status: 1 });
instructorPayoutSchema.index({ createdAt: -1 });
instructorPayoutSchema.index({ requestedAt: -1 });

// Auto-update updatedAt
instructorPayoutSchema.pre("save", async function () {
  this.updatedAt = new Date();
});

// Method to check if eligible for payout
instructorPayoutSchema.methods.isEligibleForProcessing = function () {
  return (
    this.status === "APPROVED" &&
    this.totalAmount >= this.minimumPayoutThreshold &&
    this.retryCount < this.maxRetries
  );
};

// Method to mark as completed
instructorPayoutSchema.methods.markAsCompleted = function (gatewayPayoutId, response) {
  this.status = "COMPLETED";
  this.gatewayPayoutId = gatewayPayoutId;
  this.gatewayResponse = response;
  this.processedAt = new Date();
  this.completedAt = new Date();
  return this.save();
};

// Method to mark as failed
instructorPayoutSchema.methods.markAsFailed = function (reason, code, retryAfterMinutes = 60) {
  this.status = "FAILED";
  this.failureReason = reason;
  this.failureCode = code;
  this.failedAt = new Date();
  this.retryCount += 1;
  this.nextRetryAt = new Date(Date.now() + retryAfterMinutes * 60 * 1000);
  return this.save();
};

module.exports = mongoose.model("InstructorPayout", instructorPayoutSchema);
