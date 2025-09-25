const mongoose = require("mongoose");

const userPurchaseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  productName: { type: String, required: true },
  price: { type: Number, required: true },    // price per item at time of purchase
  quantity: { type: Number, required: true, default: 1 },
  totalPrice: { type: Number, required: true }, // price * quantity
  productType: { type: String },
  status: { type: String, enum: ["completed", "pending", "refunded"], default: "completed" },
  purchaseDate: { type: Date, default: Date.now }
}, { timestamps: true });

module.exports = mongoose.model("UserPurchase", userPurchaseSchema);

