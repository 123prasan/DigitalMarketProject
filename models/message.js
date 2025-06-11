const mongoose = require("mongoose");

const notifications = new mongoose.Schema({
    message: { type: String, required: true },
    DateTime: { type: Date, default: Date.now },

});
const Message = mongoose.model("Message", notifications);
module.exports = Message;