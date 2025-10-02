const express = require('express');
const router = express.Router();
const WebSocket = require('ws');
const User = require("../models/userData.js"); // Ensure path is correct
const UserMessage = require('../models/UserMessage'); // Ensure path is correct
// const { requireAuth } = require('../middleware/auth'); // Assuming your auth middleware is here
const authenticateJWT_user=require('../routes/authentication/jwtAuth.js');
const requireAuth=require('../routes/authentication/reaquireAuth.js');

// --- WebSocket Setup ---

// This map will store WebSocket connections, mapping userId to the WebSocket object.
const clients = new Map();

// --- WebSocket Initialization Function ---
// This function will be called from your main server.js file
const initializeChat = (server) => {
    const wss = new WebSocket.Server({ server });
    console.log("user websocket")
    wss.on('connection', (ws) => {
        let userId;

        ws.on('UserMessage', async (UserMessage) => {
            const data = JSON.parse(UserMessage);

            switch (data.type) {
                case 'register':
                    userId = data.userId;
                    clients.set(userId, ws);
                    console.log(`User ${userId} connected to chat.`);
                    break;

                case 'private_UserMessage':
                    const { recipientId, text } = data;
                    const recipientSocket = clients.get(recipientId);
                    const conversationId = [userId, recipientId].sort().join('--');

                    const UserMessageToSave = new UserMessage({
                        conversationId,
                        senderId: userId,
                        recipientId,
                        text,
                    });

                    try {
                        // Save the UserMessage to the database
                        await UserMessageToSave.save();

                        // If the recipient is online, send the UserMessage in real-time
                        if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) {
                            recipientSocket.send(JSON.stringify(UserMessageToSave));
                        }
                    } catch (error) {
                        console.error("Error saving/sending chat UserMessage:", error);
                    }
                    break;
                     case 'typing': {
            const recipientSocket = clients.get(data.recipientId);
            if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) {
                recipientSocket.send(JSON.stringify({
                    type: 'typing',
                    senderId: userId
                }));
            }
            break;
        }
            }
        });

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