const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');

// Import your Mongoose models
const User = require('./models/UserData.js');
const UserMessage = require('./models/UserMessage.js');
const File = require('./models/file.js');
const authenticateJWT_user  = require('./routes/authentication/jwtAuth.js');
const requireAuth = require('./routes/authentication/reaquireAuth.js');

const router = express.Router();

// --- HELPER FUNCTION for finding image URLs ---
async function getValidFileUrl(file) {
    const CF_DOMAIN = process.env.CF_DOMAIN || "https://d3tonh6o5ach9f.cloudfront.net";
    const VALID_IMAGE_TYPES = ["jpg", "jpeg", "png", "webp", "gif"];
    const triedExtensions = new Set();
    if (file.imageType) {
        const url = `${CF_DOMAIN}/files-previews/images/${file._id}.${file.imageType}`;
        triedExtensions.add(file.imageType);
        try {
            const res = await axios.head(url);
            if (res.status === 200) return url;
        } catch (err) { /* ignore */ }
    }
    for (const ext of VALID_IMAGE_TYPES) {
        if (triedExtensions.has(ext)) continue;
        const url = `${CF_DOMAIN}/files-previews/images/${file._id}.${ext}`;
        try {
            const res = await axios.head(url);
            if (res.status === 200) {
                File.updateOne({ _id: file._id }, { $set: { imageType: ext } }).exec();
                return url;
            }
        } catch (err) { /* ignore */ }
    }
    return null; // Return null if no valid image is found
}

// --- PAGE RENDERING ROUTES ---

// Route for the main chat list page
router.get('/chats',authenticateJWT_user,requireAuth, async (req, res) => {
    const myUserId = req.user._id; 
    res.render('chat-list', { myUserId, isLoggedin: true });
});

// Route for a specific one-on-one chat page
router.get('/user/chat/:userId',authenticateJWT_user,requireAuth, async (req, res) => {
    try {
        const recipientId = req.params.userId;
        const myUserId = req.query.user || '68de9bfaf800ec98aea8b6f3'; // Placeholder for testing
     console.log("recipient",recipientId)
     console.log("myUserId",myUserId)
        const [user, recipientUser] = await Promise.all([
            User.findById(myUserId).lean(),
            User.findById(recipientId).lean()
        ]);

        if (!user || !recipientUser) {
            return res.status(404).send("User not found");
        }

        res.render('user-chat', {
            myUserId,
            recipientId,
            recipientUsername: recipientUser.username,
            recipientProfileUrl: recipientUser.profilePicUrl,
            isVerified: recipientUser.ISVERIFIED || false,
            isLoggedin: true,
            username: user.username,
        });
    } catch (error) {
        console.error("❌ Error in /chat/:userId route:", error);
        res.status(500).send("Server error");
    }
});


// --- API ROUTES ---

// API to get all active conversations for a user
router.get('/api/conversations',authenticateJWT_user,requireAuth, async (req, res) => {
    try {
        const myUserId = new mongoose.Types.ObjectId(req.query.myId);
        const conversations = await UserMessage.aggregate([
            { $match: { $or: [{ senderId: myUserId }, { recipientId: myUserId }] } },
            { $sort: { createdAt: -1 } },
            { $group: { _id: "$conversationId", lastMessage: { $first: "$$ROOT" } } },
            { $addFields: { "partnerId": { $cond: { if: { $eq: ["$lastMessage.senderId", myUserId] }, then: "$lastMessage.recipientId", else: "$lastMessage.senderId" } } } },
            { $lookup: { from: "users", localField: "partnerId", foreignField: "_id", as: "partnerDetails" } },
            { $project: { _id: 0, conversationId: "$_id", lastMessage: "$lastMessage", partner: { $arrayElemAt: ["$partnerDetails", 0] } } },
            { $sort: { "lastMessage.createdAt": -1 } }
        ]);
        res.json(conversations);
    } catch (error) {
        console.error("Error fetching conversations:", error);
        res.status(500).json([]);
    }
});

// API to search for new users to chat with
router.get('/api/users/search',authenticateJWT_user,requireAuth, async (req, res) => {
    try {
        const myUserId = new mongoose.Types.ObjectId(req.query.myId);
        const query = req.query.q;
        if (!query) return res.json([]);

        const messages = await UserMessage.find({ $or: [{ senderId: myUserId }, { recipientId: myUserId }] }).select('senderId recipientId').lean();
        const existingPartnerIds = new Set();
        messages.forEach(msg => {
            if (String(msg.senderId) !== String(myUserId)) existingPartnerIds.add(String(msg.senderId));
            if (String(msg.recipientId) !== String(myUserId)) existingPartnerIds.add(String(msg.recipientId));
        });
        const idsToExclude = [myUserId, ...Array.from(existingPartnerIds).map(id => new mongoose.Types.ObjectId(id))];

        const users = await User.find({
            username: { $regex: query, $options: 'i' },
            _id: { $nin: idsToExclude }
        }).select('username profilePicUrl isVerified').limit(10).lean();
        res.json(users);
    } catch (error) {
        console.error("❌ Error searching users:", error);
        res.status(500).json([]);
    }
});

// API to get products for the "Share Product" modal
router.get('/api/products',authenticateJWT_user,requireAuth, async (req, res) => {
    try {
        const files = await File.find({}).limit(20);
        const productsForFrontend = await Promise.all(
            files.map(async (file) => {
                const imageUrl = await getValidFileUrl(file);
                return { 
                    _id: file._id, 
                    name: file.filename, 
                    price: `₹${file.price}`, 
                    imageUrl, 
                    slug: file.slug 
                };
            })
        );
        res.json(productsForFrontend);
    } catch (error) {
        console.error("❌ Error fetching products:", error);
        res.status(500).json({ error: 'Failed to fetch products.' });
    }
});

// API to clear a chat history
router.delete('/api/messages/:conversationId',authenticateJWT_user,requireAuth, async (req, res) => {
    try {
        const { conversationId } = req.params;
        const result = await UserMessage.deleteMany({ conversationId: conversationId });
        console.log(`[Clear Chat] Deleted ${result.deletedCount} messages for ${conversationId}`);
        res.status(200).json({ success: true, message: 'Chat history cleared.' });
    } catch (error) {
        console.error("❌ Error clearing chat history:", error);
        res.status(500).json({ success: false, message: 'Failed to clear chat.' });
    }
});

// API to fetch a specific conversation's history with pagination
router.get('/UserMessages/:userId',authenticateJWT_user,requireAuth, async (req, res) => {
    try {
        const { myId: selfId, before: beforeTimestamp } = req.query;
        const { userId: partnerId } = req.params;
        const query = { conversationId: [selfId, partnerId].sort().join('--') };
        if (beforeTimestamp) {
            query.createdAt = { $lt: new Date(beforeTimestamp) };
        }
        const history = await UserMessage.find(query).sort({ createdAt: -1 }).limit(30).lean();
        res.json(history.reverse());
    } catch (error) {
        console.error("❌ Error fetching message history:", error);
        res.status(500).json({ message: "Could not fetch message history." });
    }
});

module.exports = router;