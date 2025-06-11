const mongoose = require('mongoose');

const visitorSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  city: String,
  region: String,
  country: String,
  postal_code: String,
  latitude: Number,
  longitude: Number,
  full_address: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Visitor', visitorSchema);
