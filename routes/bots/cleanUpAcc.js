const cron = require("node-cron");
const path=require("path")
const User=require('../../models/userData')

// Run every day at midnight
cron.schedule("0 0 * * *", async () => {
  try {
    const cutoffDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24h ago


    const result = await User.deleteMany({
      isEmailVerified: false,
      createdAt: { $lt: cutoffDate }
    });

    console.log(`🧹 Cleanup Job: Deleted ${result.deletedCount} unverified users`);
  } catch (error) {
    console.error("Cleanup job failed:", error);
  }
});


