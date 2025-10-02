// models/Message.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    // A compound index of the two participants for fast lookups
    conversationId: {
        type: String,
        required: true,
        index: true // Creates a database index for efficient querying
    },
    senderId: {
        type: String, // You can change this to ObjectId if you link to a User collection
        required: true
    },
    recipientId: {
        type: String,
        required: true
    },
    text: {
        type: String,
        required: true
    }
}, {
    timestamps: true // Automatically adds createdAt and updatedAt fields
});

const UserMessage = mongoose.model('UserMessage', messageSchema);

module.exports = UserMessage;