const mongoose = require("mongoose");

const category = new mongoose.Schema({
  name: { type: String, required: true,unique: true },

});
const categories = mongoose.model("category", category);


module.exports = categories;
// This code defines a Mongoose schema for a "category" collection in MongoDB.