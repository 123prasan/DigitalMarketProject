// routes/chatRoutes.js
const mongoose=require('mongoose')
const express = require('express');
const router = express.Router();
const Message = require('../models/chat');
// const MONGO_URI = 'mongodb://localhost:27017/livechat'; 
//  mongoose.connect(MONGO_URI) .then(() => console.log('Successfully connected to MongoDB.')) .catch(err => console.error('Connection error', err));
// GET all messages for a chat
router.get('/:chatFileId/messages', async (req, res) => {
  try {
    const messages = await Message.find({ chatFileId: req.params.chatFileId }).sort({ createdAt: 'asc' });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching messages', error });
  }
});

// POST new message
router.post('/:chatFileId/messages', async (req, res) => {
  try {
    const newMessage = new Message({
      chatFileId: req.params.chatFileId,
      author: req.body.author,
      text: req.body.text
    });
    const savedMessage = await newMessage.save();
    res.status(201).json(savedMessage);
  } catch (error) {
    res.status(500).json({ message: 'Error posting message', error });
  }
});

// POST reply to a message
router.post('/messages/:messageId/replies', async (req, res) => {
  try {
    const parentMessage = await Message.findById(req.params.messageId);
    if (!parentMessage) return res.status(404).json({ message: 'Parent message not found' });

    parentMessage.replies.push({
      author: req.body.author,
      text: req.body.text
    });

    const updatedMessage = await parentMessage.save();
    res.status(201).json(updatedMessage);
  } catch (error) {
    res.status(500).json({ message: 'Error posting reply', error });
  }
});

// POST react
router.post('/react', async (req, res) => {
  try {
    const { messageId, replyId, userId, reactionType } = req.body;
    const parentMessage = await Message.findById(messageId);
    if (!parentMessage) return res.status(404).json({ message: 'Message not found' });

    const target = replyId ? parentMessage.replies.id(replyId) : parentMessage;
    if (!target) return res.status(404).json({ message: 'Target for reaction not found' });

    const likes = target.reactions.likes;
    const dislikes = target.reactions.dislikes;
    const otherReaction = reactionType === 'likes' ? dislikes : likes;

    const userIndexInOther = otherReaction.indexOf(userId);
    if (userIndexInOther > -1) otherReaction.splice(userIndexInOther, 1);

    const reactionArray = target.reactions[reactionType];
    const userIndex = reactionArray.indexOf(userId);
    if (userIndex > -1) {
      reactionArray.splice(userIndex, 1);
    } else {
      reactionArray.push(userId);
    }

    const updatedParentMessage = await parentMessage.save();
    res.json(updatedParentMessage);
  } catch (error) {
    res.status(500).json({ message: 'Error handling reaction', error });
  }
});

module.exports = router;
