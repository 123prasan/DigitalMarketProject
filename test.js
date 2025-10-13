const mongoose = require("mongoose");
const UserTransaction = require("./models/usertransactions.js"); // adjust path to your model

mongoose.connect("mongodb+srv://prasannaprasanna35521:YyWbAq2FoOietc7B@cluster0.0ytfuyz.mongodb.net/documents?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
})
.then(() => console.log("✅ MongoDB connected"))
.catch((err) => console.error("❌ MongoDB connection error:", err));

async function calculateTotalIncome() {
  try {
    const incomeData = await UserTransaction.aggregate([
      // 1️⃣ Only completed transactions count
      { $match: { status: "Completed" } },

      // 2️⃣ Group by userId (seller) to sum totalAmount
      {
        $group: {
          _id: "$userId",
          totalIncome: { $sum: "$totalAmount" },
          totalSales: { $sum: 1 },
        },
      },

      // 3️⃣ Lookup user details from "users" collection
      {
        $lookup: {
          from: "users",          // your User model collection name
          localField: "_id",      // _id from group (userId)
          foreignField: "_id",    // match user’s _id
          as: "user",
        },
      },

      // 4️⃣ Flatten user array (since lookup returns an array)
      { $unwind: "$user" },

      // 5️⃣ Shape the final output
      {
        $project: {
          _id: 0,
          userId: "$_id",
          user: {
            _id: "$user._id",
            username: "$user.username", // change if your User schema uses 'name'
            email: "$user.email",
          },
          totalIncome: 1,
          totalSales: 1,
        },
      },

      // 6️⃣ Optional: sort by highest income
      { $sort: { totalIncome: -1 } },
    ]);

    console.log("💰 Total income per user:\n", incomeData);
  } catch (err) {
    console.error("❌ Error calculating total income:", err);
  }
}

calculateTotalIncome();
