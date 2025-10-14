const mongoose = require("mongoose");
const WithDraw = require("./models/userWithdrawels.js"); // replace with the actual path

// Connect to MongoDB
mongoose.connect("mongodb+srv://prasannaprasanna35521:YyWbAq2FoOietc7B@cluster0.0ytfuyz.mongodb.net/documents?retryWrites=true&w=majority", {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.error("MongoDB connection error:", err));

// Create a new WithDraw document
async function createWithDraw() {
  try {
    const newWithDraw = new WithDraw({
      totalAmount: 2800,
      userId: "68d65ce593f888f73f63413c",
      status: "success",
      transactionId: "112650986138"
    });

    const savedDoc = await newWithDraw.save();
    console.log("Document saved:", savedDoc);
  } catch (err) {
    console.error("Error creating document:", err);
  } finally {
    mongoose.connection.close();
  }
}

// Run the function
createWithDraw();
