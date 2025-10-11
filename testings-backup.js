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
router.get('/user/community-chats', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const myUserId = req.user._id.toString();

        // --- Placeholder/Mock Community Data ---
        // In a real app, you would fetch this from a Community/Group model based on a communityId.
        const mockCommunityId = 'community_global_1'; 
        const mockCommunityName = "Vidyari Dev Community";
        const mockActiveUsers = 42;
        const myUser = await User.findById(myUserId).lean();

        if (!myUser) return res.status(404).send("User not found");
        
        res.render('community-chat', {
            myUserId: myUserId,
            myUsername: myUser.username,
            communityId: mockCommunityId,
            communityName: mockCommunityName,
            communityProfileUrl: '/images/group-icon.jpg', // Placeholder for group icon
            activeUsersCount: mockActiveUsers,
            isLoggedin: true,
        });

    } catch (error) {
        console.error("❌ Error in /user/community-chats route:", error);
        res.status(500).send("Server error");
    }
});
router.get('/CommunityMessages/:communityId', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const { myId: selfId, before: beforeTimestamp } = req.query;
        const { communityId } = req.params;

        // In a real app, you'd check if the user belongs to the community here.
        
        const query = { communityId: communityId }; // Assuming communityId is stored on the messages

        if (beforeTimestamp) {
            query.createdAt = { $lt: new Date(beforeTimestamp) };
        }

        const history = await UserMessage.aggregate([
            { $match: query },
            { $sort: { createdAt: -1 } },
            { $limit: 30 },
            // Join with User model to get sender's username and profile pic for display
            { $lookup: {
                from: "users", 
                localField: "senderId", 
                foreignField: "_id", 
                as: "senderDetails" 
            }},
            { $project: {
                _id: 1,
                id: 1,
                senderId: 1,
                communityId: 1,
                text: 1,
                createdAt: 1,
                // Project sender info into the senderInfo object expected by the frontend
                senderInfo: {
                    username: { $arrayElemAt: ["$senderDetails.username", 0] },
                    profilePicUrl: { $arrayElemAt: ["$senderDetails.profilePicUrl", 0] }
                }
            }}
        ]);

        // Return messages in chronological order (oldest first)
        res.json(history.reverse());
    } catch (error) {
        console.error(`❌ Error fetching community history for ${req.params.communityId}:`, error);
        res.status(500).json({ message: "Could not fetch community history." });
    }
});
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


// --- API ROUTES ---

// API to get all active conversations for a user
router.get('/api/conversations', authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const myUserId = new mongoose.Types.ObjectId(req.query.myId);
        
        const conversations = await UserMessage.aggregate([
            { 
                $match: { 
                    // 1. Match messages involving the current user (myUserId)
                    $or: [
                        { senderId: myUserId }, 
                        { recipientId: myUserId }
                    ],
                    // 2. CRITICAL FIX: Exclude self-chats where senderId equals recipientId
                    $expr: {
                        $ne: ["$senderId", "$recipientId"] 
                    }
                } 
            },
            { $sort: { createdAt: -1 } },
            { $group: { _id: "$conversationId", lastMessage: { $first: "$$ROOT" } } },
            { $addFields: { "partnerId": { $cond: { if: { $eq: ["$lastMessage.senderId", myUserId] }, then: "$lastMessage.recipientId", else: "$lastMessage.senderId" } } } },
            
            // 💡 ADDED FOR UNREAD COUNT: Calculate unread count for each conversation
            {
                $lookup: {
                    from: "usermessages",
                    let: { convoId: "$conversationId", userId: myUserId },
                    pipeline: [
                        { 
                            $match: {
                                $expr: {
                                    $and: [
                                        { $eq: ["$conversationId", "$$convoId"] },
                                        { $eq: ["$recipientId", "$$userId"] }, // Sent to me
                                        { $in: ["$status", ["sent", "delivered"]] } // Unread status
                                    ]
                                }
                            }
                        },
                        { $count: "unreadCount" }
                    ],
                    as: "unreadMessages"
                }
            },
            
            { $lookup: { from: "users", localField: "partnerId", foreignField: "_id", as: "partnerDetails" } },
            { 
                $project: { 
                    _id: 0, 
                    conversationId: "$_id", 
                    lastMessage: {
                        // Project all existing fields from lastMessage
                        $mergeObjects: ["$lastMessage", {
                            // Embed the unread count into the lastMessage object for client consumption
                            unreadCount: { $arrayElemAt: ["$unreadMessages.unreadCount", 0] } 
                        }]
                    },
                    partner: { $arrayElemAt: ["$partnerDetails", 0] } 
                } 
            },
            { $sort: { "lastMessage.createdAt": -1 } }
        ]);
        
        res.json(conversations);
    } catch (error) {
        console.error("Error fetching conversations:", error);
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