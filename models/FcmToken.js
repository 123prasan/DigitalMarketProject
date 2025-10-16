// models/FcmToken.js
const mongoose = require("mongoose");

const fcmTokenSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("FcmToken", fcmTokenSchema);
