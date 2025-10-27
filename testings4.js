const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');

// Import your Mongoose models
const User = require('./models/userData.js');
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
router.get('/user/chat/:userId', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const recipientId = req.params.userId;
        
        // 1. **Get the authenticated user's ID.** // We prioritize req.user._id (set by authenticateJWT_user/requireAuth) for security.
        // We keep the placeholder fallback for local testing if necessary.
        const myUserId = req.user ? req.user._id.toString() : (req.query.user || '68de9bfaf800ec98aea8b6f3'); 
        
        console.log("recipient", recipientId);
        console.log("myUserId", myUserId);

        // 2. **CRITICAL CHECK: Prevent Self-Chatting**
        if (String(recipientId) === String(myUserId)) {
            // Option 1: Redirect to the main chat list or home page
            // return res.redirect('/user/chats'); 
            
            // Option 2: Render an error page or send a forbidden status
            return res.status(403).send("You cannot chat with yourself.");
        }

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
});;

const NodeCache = require("node-cache");
const conversationCache = new NodeCache({ stdTTL: 600, checkperiod: 120 }); // 10 min TTL
const CLOUDFRONT_AVATAR_URL = "https://previewfiles.vidyari.com/avatars";

router.get('/api/conversations', authenticateJWT_user, requireAuth, async (req, res) => {
  try {
    const myUserId = new mongoose.Types.ObjectId(req.query.myId);
    const cacheKey = `conversations:${myUserId}`;

    // 🧠 STEP 1 — Try Cache First
    const cachedData = conversationCache.get(cacheKey);
    if (cachedData) {
      // Extend TTL if it's popular (less than 3 min remaining)
      const ttl = conversationCache.getTtl(cacheKey) - Date.now();
      if (ttl < 3 * 60 * 1000) {
        conversationCache.ttl(cacheKey, 15 * 60); // extend by 15 min
      }
      return res.json(cachedData);
    }

    // 🧩 STEP 2 — DB Query (if not cached)
    const conversations = await UserMessage.aggregate([
      {
        $match: {
          $or: [
            { senderId: myUserId },
            { recipientId: myUserId }
          ],
          $expr: { $ne: ["$senderId", "$recipientId"] }
        }
      },
      { $sort: { createdAt: -1 } },
      { $group: { _id: "$conversationId", lastMessage: { $first: "$$ROOT" } } },
      {
        $addFields: {
          partnerId: {
            $cond: {
              if: { $eq: ["$lastMessage.senderId", myUserId] },
              then: "$lastMessage.recipientId",
              else: "$lastMessage.senderId"
            }
          }
        }
      },
      {
        $lookup: {
          from: "users",
          localField: "partnerId",
          foreignField: "_id",
          as: "partnerDetails"
        }
      },
      {
        $addFields: {
          partner: { $arrayElemAt: ["$partnerDetails", 0] }
        }
      },
      // 🚫 Filter out deleted or missing users
      {
        $match: {
          partner: { $ne: null },
          "partner.deleted": { $ne: true }
        }
      },
      {
        $lookup: {
          from: "usermessages",
          let: { convoId: "$_id", userId: myUserId },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ["$conversationId", "$$convoId"] },
                    { $eq: ["$recipientId", "$$userId"] },
                    { $in: ["$status", ["sent", "delivered"]] }
                  ]
                }
              }
            },
            { $count: "unreadCount" }
          ],
          as: "unreadMessages"
        }
      },
      {
        $project: {
          _id: 0,
          conversationId: "$_id",
          lastMessage: {
            $mergeObjects: [
              "$lastMessage",
              { unreadCount: { $arrayElemAt: ["$unreadMessages.unreadCount", 0] } }
            ]
          },
          partner: 1
        }
      },
      { $sort: { "lastMessage.createdAt": -1 } }
    ]);

    // 🧩 STEP 3 — Transform partner URLs (CloudFront Optimization)
    const updatedConversations = conversations.map(conv => {
      if (conv.partner && conv.partner.avatar) {
        conv.partner.avatar = `${CLOUDFRONT_AVATAR_URL}/${conv.partner.avatar}`;
      }
      if (conv.partner && conv.partner.profileUrl) {
        conv.partner.profileUrl = `${CLOUDFRONT_PROFILE_URL}/${conv.partner.profileUrl}`;
      }
      return conv;
    });

    // 🧠 STEP 4 — Cache Results for 10 min
    if (updatedConversations.length > 0) {
      conversationCache.set(cacheKey, updatedConversations, 10 * 60); // 10 min cache
    }

    res.json(updatedConversations);
  } catch (error) {
    console.error("🚨 Error fetching conversations:", error);
    res.status(500).json([]);
  }
});


// API to search for new users to chat with
router.get('/api/users/search', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        // 1. Get the current user's ID securely and reliably.
        // Assume req.user is set by authenticateJWT_user middleware.
        // Fallback to req.query.myId if req.user is not available, but req.user is highly recommended.
        const currentUserId = req.user ? req.user._id : req.query.myId;
        
        if (!currentUserId) {
             return res.status(401).json({ message: "Authentication required." });
        }

        const myObjectId = new mongoose.Types.ObjectId(currentUserId);
        const query = req.query.q;
        
        if (!query) return res.json([]);

        // 2. Simplification: Only exclude the current user (myUserId).
        // If the intention is to allow searching for existing partners to resume the chat,
        // this is the correct behavior. If the intention is STRICTLY "New Chats Only," 
        // the original complex logic is needed, but simplified below.
        
        const users = await User.find({
            username: { $regex: query, $options: 'i' },
            
            // 💡 CRITICAL CHANGE: Exclude the current user from the results.
            _id: { $ne: myObjectId } 
            
        }).select('_id username profilePicUrl isVerified').limit(10).lean();

        res.json(users);
        
    } catch (error) {
        console.error("❌ Error searching users:", error);
        res.status(500).json([]);
    }
});;

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
router.get('/UserMessages/:userId', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const { myId: selfId, before: beforeTimestamp } = req.query;
        const { userId: partnerId } = req.params;

        // 1. **CRITICAL CHECK: Prevent Self-Chatting**
        if (String(partnerId) === String(selfId)) {
            console.warn(`[Security] User ${selfId} attempted to load history with self.`);
            // Return an empty array or a forbidden status, as there should be no self-history
            return res.status(403).json({ message: "Self-chat history retrieval is not allowed." });
        }

        // 2. Proceed with history retrieval for the valid conversation
        const query = { conversationId: [selfId, partnerId].sort().join('--') };

        if (beforeTimestamp) {
            query.createdAt = { $lt: new Date(beforeTimestamp) };
        }

        const history = await UserMessage.find(query)
            .sort({ createdAt: -1 })
            .limit(30)
            .lean();

        // Return messages in chronological order (oldest first)
        res.json(history.reverse()); 
    } catch (error) {
        console.error("❌ Error fetching message history:", error);
        res.status(500).json({ message: "Could not fetch message history." });
    }
});

module.exports = router;