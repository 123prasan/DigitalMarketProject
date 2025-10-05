const mongoose = require('mongoose');

const userMessageSchema = new mongoose.Schema({
    // For client-side tracking before a DB ID is assigned
    id: { 
        type: String, 
        required: true, 
        unique: true 
    },
    conversationId: { 
        type: String, 
        required: true, 
        index: true 
    },
    senderId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    recipientId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    // For message content and type
    type: { 
        type: String, 
        default: 'private_message' 
    },
    text: { 
        type: String 
    },
    // For file/image sharing
    fileUrl: { 
        type: String 
    },
    // For product sharing
    productInfo: {
        productId: String,
        name: String,
        price: String,
        imageUrl: String,
slug: String
    },
    // For message replies
    repliedTo: {
        senderName: String,
        text: String
    },
    // For message metadata
    status: {
        type: String,
        enum: ['sent', 'delivered', 'read'],
        default: 'sent'
    },
    isEdited: {
        type: Boolean,
        default: false
    },
    isDeleted: {
        type: Boolean,
        default: false
    }
}, { 
    // Automatically adds createdAt and updatedAt fields
    timestamps: true 
});

module.exports = mongoose.model('UserMessage', userMessageSchema);