const express = require('express');
const router = express.Router();
const WebSocket = require('ws');
const User = require("../models/userData.js"); // Ensure path is correct
const UserMessage = require('../models/UserMessage'); // Ensure path is correct
// const { requireAuth } = require('../middleware/auth'); // Assuming your auth middleware is here
const authenticateJWT_user=require('../routes/authentication/jwtAuth.js');
const requireAuth=require('../routes/authentication/reaquireAuth.js');
const sendNotification=require("../test.js")
// --- WebSocket Setup ---

// This map will store WebSocket connections, mapping userId to the WebSocket object.
const clients = new Map();

// --- WebSocket Initialization Function ---
// This function will be called from your main server.js file
// NOTE: 'clients', 'UserMessage', 'sendNotification', and 'imageUrl'
// are assumed to be defined/imported in the scope where initializeChat is called.
// For example:
// const clients = new Map();
// const UserMessage = require('./models/UserMessage');
// const sendNotification = require('./utils/sendNotification');
// const imageUrl = 'default_image_url';

const initializeChat = (server) => {
    // 1. WebSocket Server Initialization
    const wss = new WebSocket.Server({ server });
    console.log("WebSocket server initialized."); // More descriptive log

    wss.on('connection', (ws, req) => {
        let userId;
        // NOTE: req.socket.remoteAddress might be null/incorrect in proxy environments (e.g., behind Nginx/Load Balancer)
        console.log("✅ WebSocket client connected:", req.socket.remoteAddress || 'Unknown Address');

        // 2. Message Handler
        ws.on('message', async (msg) => { // IMPORTANT: 'message' handler is now async
            const data = JSON.parse(msg);

            switch (data.type) {
                case 'register':
                    userId = data.userId;
                    clients.set(userId, ws);
                    console.log(`User ${userId} connected to chat.`);
                    break;

                case 'private_message':
                    const { recipientId, text } = data;
                    const recipientSocket = clients.get(recipientId);
                    // Standard way to create a consistent conversation ID
                    const conversationId = [userId, recipientId].sort().join('--');

                    const UserMessageToSave = new UserMessage({
                        conversationId,
                        senderId: userId,
                        recipientId,
                        text,
                    });

                    try {
                        // --- CRITICAL FIX: AWAITING ASYNCHRONOUS NOTIFICATIONS ---
                        const notifications = [
                            sendNotification({
                                userId: recipientId,
                                title: `Message from ${userId}`, // Added sender to title
                                body: `${text}`,
                                image: imageUrl,
                                target_link: `/user/chat/${userId}`, // Link to sender's chat
                                notification_type: "Message",
                            })
                        ];

                        // Run and wait for all notification attempts
                        const results = await Promise.allSettled(notifications);
             
                        results.forEach((result) => {
                            if (result.status === "rejected") {
                                // Log the failure but allow the message save/send to proceed
                                console.error(`⚠️ Notification failed:`, result.reason);
                            }
                        });
                        // --------------------------------------------------------

                        // Save message to database
                        await UserMessageToSave.save();

                        // Send message to recipient if they are currently connected
                        if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) {
                            recipientSocket.send(JSON.stringify({
                                type: 'private_message',
                                senderId: userId,
                                text,
                            }));
                        }
                    } catch (error) {
                        console.error("❌ Error saving/sending chat message:", error);
                    }
                    break;

                case 'typing':
                    const recipientSocket2 = clients.get(data.recipientId);
                    if (recipientSocket2 && recipientSocket2.readyState === WebSocket.OPEN) {
                        recipientSocket2.send(JSON.stringify({
                            type: 'typing',
                            senderId: userId
                        }));
                    }
                    break;
            }
        });

        // 3. Close Handler
        ws.on('close', () => {
            if (userId) {
                clients.delete(userId);
                console.log(`User ${userId} disconnected from chat.`);
            }
        });
    });
};

// --- HTTP Routes ---

// Route to serve the chat page using EJS
router.get('/chat/:userId',authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const recipientId = req.params.userId;
        const myUserId = req.user.username; // Or req.user.id, depending on your setup
        
        // Ensure the user being chatted with exists
        const recipientUser = await User.findById(recipientId);
        if (!recipientUser) {
            return res.status(404).send("User not found");
        }

        // Fetch any other data needed for your header
        const user = await User.findById(req.user.id);

        res.render('user-chat', { // Assuming your EJS file is named 'chat.ejs'
            myUserId: myUserId,
            recipientId: recipientId,
            // Pass other necessary data for your header
            isLoggedin: !!req.user,
            username: user.username,
            profileUrl: user.profilePicUrl,
            useremail: user.email
        });
    } catch (error) {
        console.error("Error loading chat page:", error);
        res.status(500).send("Server error");
    }
});

// API route to get the UserMessage history for a conversation
router.get('/UserMessages/:userId',authenticateJWT_user, requireAuth, async (req, res) => {
    try {
        const selfId = req.user.username;
        const partnerId = req.params.userId;
        
        const conversationId = [selfId, partnerId].sort().join('--');
        
        const history = await UserMessage.find({ conversationId })
            .sort({ createdAt: 'asc' })
            .lean();

        res.json(history);
    } catch (error) {
        console.error("Error fetching UserMessage history:", error);
        res.status(500).json({ UserMessage: "Could not fetch UserMessage history." });
    }
});

// Export both the router and the WebSocket initializer
module.exports = { UserChats: router, initializeChat };