// notificationRoutes.js
const express = require('express');
const admin = require('firebase-admin');
const FcmToken = require("./models/FcmToken"); // Assuming this path is correct

const router = express.Router();

// Route to register an FCM token in the database
router.post("/register-token", async (req, res) => {
    const { userId, token } = req.body;
    if (!userId || !token) return res.status(400).json({ message: "Missing data" });

    try {
        // Find by userId. If found, update the token. If not found, create a new document.
        await FcmToken.findOneAndUpdate(
            { userId }, // <-- CORRECTED: Find by userId
            { userId, token }, // Data to set (will update 'token' if 'userId' is found)
            { upsert: true, new: true, setDefaultsOnInsert: true } // Options
        );

        console.log("Token saved/updated for user:", userId);
        res.json({ message: "Token saved successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "DB error" });
    }
});


// Route to send a notification
router.post("/send", async (req, res) => {
    // Destructure all expected fields, including custom data fields
    const { 
        userId, 
        title, 
        body, 
        image, 
        target_link,        // e.g., /chats/123 or /course/new
        notification_type,  // e.g., CHAT, NEW_COURSE, PROMO
        ...customData       // Catch-all for any other custom key/values
    } = req.body; 

    if (!userId) return res.status(400).json({ message: "Missing userId." });

    try {
        let userTokens = await FcmToken.find({ userId }).sort({ _id: 1 }).select("token -_id");
        if (!userTokens.length) {
            return res.status(404).json({ message: "No tokens for this user." });
        }

        let sentSuccessfully = false;
        let tokensToRemove = [];

        // Build the standard custom data payload (all values must be strings)
        const dataPayload = {
            // Standard custom fields for client-side routing
            target_link: target_link || '/', 
            notification_type: notification_type || 'GENERAL',
            imageUrl: image || '',
            
            // Merge any extra custom key/value pairs
            ...Object.fromEntries(
                Object.entries(customData).map(([key, value]) => [key, String(value)])
            )
        };

        // Loop through each token, trying to send the message until one succeeds
        for (const doc of userTokens) {
            const token = doc.token;

            const message = {
                // 1. Notification Payload (System handles display: title, body, small icon)
               notification: {
    title: title || 'New Update from Vidyari',
    body: body || 'You have an important message.',
    image: image || '',   // ✅ Add this line
},

                
                // 2. Data Payload (App handles processing: deep links, types, custom data)
                data: dataPayload,
                
                token: token, 
            };

            try {
                // Attempt to send the notification
                await admin.messaging().send(message);
                console.log(`Notification sent to a device for user ${userId}. Token: ${token.substring(0, 10)}...`);
                sentSuccessfully = true;
                break; // Success! Stop and return.

            } catch (err) {
                // Check if the error indicates a permanent token failure
                if (
                    err.code === 'messaging/registration-token-not-registered' ||
                    err.code === 'messaging/invalid-argument'
                ) {
                    tokensToRemove.push(token); // Mark this token for deletion
                } else {
                    console.error(`Unexpected send error for token ${token.substring(0, 10)}...:`, err.message);
                }
            }
        } // End of loop

        // Cleanup: Remove all invalid tokens found
        if (tokensToRemove.length > 0) {
            await FcmToken.deleteMany({ token: { $in: tokensToRemove } });
            console.log(`Cleaned up ${tokensToRemove.length} expired/invalid tokens.`);
        }
        
        // Final response
        if (sentSuccessfully) {
            res.json({ message: `Notification sent successfully to at least one active device.${userId}` });
        } else {
            res.status(503).json({ 
                message: "Failed to send notification to any registered device.",
                details: "All tokens were either invalid or resulted in an unexpected error."
            });
        }

    } catch (err) {
        console.error("Database or Critical error:", err);
        res.status(500).json({ 
            message: "A critical database error occurred.", 
            error: err.toJSON ? err.toJSON() : err 
        });
    }
});

module.exports = router;