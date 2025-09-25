const mongoose = require("mongoose");

const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  quantity: { type: Number, required: true },
  price: { type: Number, required: true }
});

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  transactionId: { type: String, required: true, unique: true },
  dateTime: { type: Date, default: Date.now },
  customer: { type: String, required: true },
  payment: { type: String, required: true },
  total: { type: Number, required: true },
  items: [itemSchema],
  productId: { type:String, required: true },
  productName:{type:String,required:true},
  status: { 
    type: String, 
    enum: ["Successfull","unsuccessfull", "Pending"], 
    default: "Pending" 
  }
});

const Order = mongoose.model("Order", orderSchema);

module.exports = Order;