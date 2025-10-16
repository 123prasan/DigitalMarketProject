const axios = require("axios");

async function sendNotification({
  userId,
  title,
  body,
  image = "",
  target_link = "/",
  notification_type = "GENERAL",
}) {
  try {
    const res = await axios.post("https:www.vidyari.com/send", {
      userId,
      title,
      body,
      image,
      target_link,
      notification_type,
    });

    console.log("✅ Notification sent:", res.data);
    return res.data;
  } catch (err) {
    console.error("❌ Error sending notification:", err.response?.data || err.message);
    throw err;
  }
}

// ✅ Export the function
module.exports = sendNotification;
