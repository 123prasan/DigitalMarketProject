// sendTestNotification.js

const admin = require('firebase-admin');
const path = require('path');

// 1️⃣ Initialize Firebase Admin with your service account
const serviceAccount = require(path.join(__dirname, 'serviceAccountKey.json')); // <-- Replace with your file path

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

console.log("Firebase Admin Initialized ✅");

// 2️⃣ Replace this with the device token you want to test
const testToken = "f-nVRb-HbAZZEp5K2OehB7:APA91bHqpyu66kUeOVUFAdc6oGhyQIONrTfAeWxm_HW_7lAoYQuRaUZf7Nss25Oywd1ebfOV2O6OHehA_aTXFSi6mWPgqUlTDHsmjEhCSpEAShg230j0nIc"; // <-- Replace with actual FCM token

// 3️⃣ Build the message
const message = {
  token: testToken,
  notification: {
    title: "Test Notification",
    body: "This is a test message to check FCM delivery.",
    image: "www.vidyari.com/images/logo.svg", // Optional: add URL if you want an image
  },
  data: {
    customKey: "customValue", // Optional: add custom data
  },
};

// 4️⃣ Send the message
admin.messaging().send(message)
  .then((response) => {
    console.log("✅ Message sent successfully:", response);
  })
  .catch((error) => {
    console.error("❌ Error sending message:", error);
  });
