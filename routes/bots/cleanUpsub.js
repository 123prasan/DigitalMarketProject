const cron = require('node-cron');
const User=require('../../models/userData') // Adjust path

// Runs at 00:00 every day
cron.schedule('0 0 * * *', async () => {
    console.log('Running daily subscription expiry check...');
    try {
        const now = new Date();

        // Find users where Pro is active but the end date has passed
        const expiredUsers = await User.updateMany(
            { 
                isPro: true, 
                proBillingCycleEnd: { $lt: now } 
            },
            { 
                $set: { 
                    isPro: false,
                    pendingSubscriptionFee: 0 // Clear debt for next cycle
                } 
            }
        );

        console.log(`Successfully downgraded ${expiredUsers.modifiedCount} expired accounts.`);
    } catch (error) {
        console.error('Error in subscription cron job:', error);
    }
});