const mongoose = require("mongoose");

const refundSchema = new mongoose.Schema({
  deductedAccId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, 
  beneficiaryAccId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

  orderId: { type: mongoose.Schema.Types.ObjectId, ref: "Order", required: true }, // link to purchase
  transactionId: { type: String }, // payment gateway transaction reference

  reason: { type: String, required: true },
  amount: { type: Number, required: true },

  status: { 
    type: String, 
    enum: ["Pending", "Processing", "Completed", "Failed", "Cancelled"], 
    default: "Pending" 
  },

  initiatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // admin/system/user
  processedAt: { type: Date }

}, { timestamps: true });

module.exports = mongoose.model("Refund", refundSchema);
