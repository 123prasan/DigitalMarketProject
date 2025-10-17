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
  const { userId, title, body, image, target_link, notification_type, ...customData } = req.body;

  if (!userId) return res.status(400).json({ message: "Missing userId." });

  try {
    // Query FcmTokens by string userId
    const userTokens = await FcmToken.find({ userId: String(userId) }).select("token -_id");

    if (!userTokens.length) {
      return res.status(404).json({ message: "No tokens for this user." });
    }

    let tokensToRemove = [];
    let sentCount = 0;

    for (const doc of userTokens) {
      const token = doc.token;

      const message = {
        notification: {
          title: title || "New Update from Vidyari",
          body: body || "You have an important message.",
          image: image || undefined,
        },
        data: {
          target_link: target_link || "/",
          notification_type: notification_type || "GENERAL",
          ...Object.fromEntries(Object.entries(customData).map(([k, v]) => [k, String(v)])),
        },
        token,
      };

      try {
        await admin.messaging().send(message);
        console.log(`✅ Notification sent to token: ${token.substring(0, 10)}...`);
        sentCount++;
      } catch (err) {
        console.error(`❌ Error for token ${token.substring(0, 10)}:`, err.message);
        if (err.code === "messaging/registration-token-not-registered" || err.code === "messaging/invalid-argument") {
          tokensToRemove.push(token);
        }
      }
    }

    // Remove invalid tokens
    if (tokensToRemove.length > 0) {
      await FcmToken.deleteMany({ token: { $in: tokensToRemove } });
      console.log(`🗑 Cleaned up ${tokensToRemove.length} invalid tokens.`);
    }

    if (sentCount > 0) {
      res.json({ message: `Notifications sent to ${sentCount} device(s).` });
    } else {
      res.status(503).json({ message: "Failed to send notification to any device." });
    }
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ message: "Internal server error", error: err.toString() });
  }
});


module.exports = router;