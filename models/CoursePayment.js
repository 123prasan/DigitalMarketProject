const mongoose = require("mongoose");
const crypto = require("crypto");

const coursePaymentSchema = new mongoose.Schema(
  {
    // Identifiers
    paymentId: {
      type: String,
      unique: true,
      required: true,
      default: () => "PAY_" + crypto.randomBytes(16).toString("hex"),
    },
    orderId: {
      type: String,
      unique: true,
      required: true,
      default: () => "ORD_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
    },
    transactionId: {
      type: String,
      unique: true,
      sparse: true, // Allows null for failed payments
    },

    // Course & User Info
    courseId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
      required: true,
    },
    instructorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Pricing
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    currency: {
      type: String,
      default: "INR",
      enum: ["INR", "USD", "EUR"],
    },
    discountApplied: {
      type: Number,
      default: 0,
    },
    finalAmount: {
      type: Number,
      required: true,
      min: 0,
    },
    taxAmount: {
      type: Number,
      default: 0,
    },
    platformFeePercentage: {
      type: Number,
      default: 10, // Platform takes 10%, instructor gets 90%
    },
    platformFee: {
      type: Number,
      default: 0,
    },
    instructorEarnings: {
      type: Number,
      default: 0,
    },

    // Payment Gateway
    paymentGateway: {
      type: String,
      enum: ["RAZORPAY", "STRIPE", "PAYPAL"],
      default: "RAZORPAY",
    },
    paymentMethod: {
      type: String,
      enum: ["CARD", "UPI", "NETBANKING", "WALLET"],
    },

    // Status
    status: {
      type: String,
      enum: ["PENDING", "INITIATED", "PROCESSING", "COMPLETED", "FAILED", "REFUNDED", "CANCELLED"],
      default: "PENDING",
    },
    paymentStatus: {
      type: String,
      enum: ["CREATED", "AUTHORIZED", "CAPTURED", "FAILED", "REFUNDED"],
    },

    // Security
    ipAddress: String,
    userAgent: String,
    signatureVerified: {
      type: Boolean,
      default: false,
    },

    // Metadata
    notes: String,
    metadata: mongoose.Schema.Types.Mixed,

    // Timestamps
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 3600, // Auto-delete after 1 hour if not completed
    },
    completedAt: Date,
    refundedAt: Date,

    // Refund details
    refundReason: String,
    refundAmount: Number,
    refundPercentage: Number,

    // Error handling
    failureReason: String,
    failureCode: String,
    retryCount: {
      type: Number,
      default: 0,
    },
    maxRetries: {
      type: Number,
      default: 3,
    }
  },
  { 
    timestamps: true
  }
);

// Create indexes
coursePaymentSchema.index({ paymentId: 1 });
coursePaymentSchema.index({ orderId: 1 });
coursePaymentSchema.index({ transactionId: 1 });
coursePaymentSchema.index({ courseId: 1, studentId: 1 });
coursePaymentSchema.index({ instructorId: 1 });
coursePaymentSchema.index({ status: 1 });
coursePaymentSchema.index({ createdAt: 1 });

// Calculate fees before saving
coursePaymentSchema.pre("save", async function () {
  if (!this.amount || !this.finalAmount) {
    return;
  }

  this.taxAmount = Math.round(this.finalAmount * 0.05); // 5% tax
  this.platformFee = Math.round(this.finalAmount * (this.platformFeePercentage / 100));
  this.instructorEarnings = this.finalAmount - this.platformFee - this.taxAmount;
});

// Method to verify payment signature
coursePaymentSchema.methods.verifySignature = function (secret, signature, body) {
  const generatedSignature = crypto
    .createHmac("sha256", secret)
    .update(JSON.stringify(body))
    .digest("hex");

  return generatedSignature === signature;
};

// Method to check if payment can be retried
coursePaymentSchema.methods.canRetry = function () {
  return this.retryCount < this.maxRetries && ["PENDING", "FAILED"].includes(this.status);
};

// Method to mark as completed
coursePaymentSchema.methods.markAsCompleted = function (transactionId) {
  this.status = "COMPLETED";
  this.paymentStatus = "CAPTURED";
  this.transactionId = transactionId;
  this.completedAt = new Date();
  this.signatureVerified = true;
  return this.save();
};

// Method to mark as failed
coursePaymentSchema.methods.markAsFailed = function (reason, code) {
  this.status = "FAILED";
  this.paymentStatus = "FAILED";
  this.failureReason = reason;
  this.failureCode = code;
  this.retryCount += 1;
  return this.save();
};

module.exports = mongoose.model("CoursePayment", coursePaymentSchema);
