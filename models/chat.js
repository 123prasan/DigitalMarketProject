// models/Message.js
const mongoose = require('mongoose');

const replySchema = new mongoose.Schema({
  author: {
    userId: { type: String, required: true },
    username: { type: String, required: true },
    badge: { type: String, enum: ['mod', 'verified', null], default: null }
  },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  reactions: {
    likes: [{ type: String }],
    dislikes: [{ type: String }]
  }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  chatFileId: { type: String, required: true, index: true },
  author: {
    userId: { type: String, required: true },
    username: { type: String, required: true },
    badge: { type: String, enum: ['mod', 'verified', null], default: null }
  },
  createdAt: { type: Date, default: Date.now },
  text: { type: String, required: true },
  reactions: {
    likes: [{ type: String }],
    dislikes: [{ type: String }]
  },
  replies: [replySchema]
}, { timestamps: true });

module.exports = mongoose.model('Chats', messageSchema);
