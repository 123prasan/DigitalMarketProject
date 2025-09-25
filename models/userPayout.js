const mongoose = require("mongoose");

const PaymentMethodSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name: { type: String, required: true },
  type: { type: String, enum: ["UPI", "BankAccount", "Card"] },
  isDefault: { type: Boolean, default: false },
  status: { type: String, enum: ["active", "inactive", "blocked"], default: "active" },
  
  upi: {type:String},

  bankAccount: {
    name: { type: String },
    accNum: { type: String },
    ifsc: { type: String },
    branchName: { type: String },
    accountType: { type: String },
    swiftCode: { type: String },
    verified: { type: Boolean, default: false }
  },

  card: {
    name: { type: String },
    last4Digits: { type: String }, // safer to store only last 4
    expiryMonth: { type: Number },
    expiryYear: { type: Number },
    cardType: { type: String },
    token: { type: String } // token from gateway instead of full card data
  },

  lastUsedAt: { type: Date }
}, { timestamps: true });

module.exports = mongoose.model("Paymentouts", PaymentMethodSchema);
