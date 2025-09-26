const mongoose = require("mongoose");
const File = require("./models/file"); // path to your File model

async function updateFiles() {
  await mongoose.connect("mongodb+srv://prasannaprasanna35521:YyWbAq2FoOietc7B@cluster0.0ytfuyz.mongodb.net/documents?retryWrites=true&w=majority"); // replace with your DB

  // Update all files where userId is missing or null
  const result = await File.updateMany(
    { $or: [ { userId: { $exists: false } }, { userId: null } ] },
    { $set: { username: "vidyari" } }
  );

  console.log("Updated files:", result.modifiedCount);
  mongoose.disconnect();
}

updateFiles().catch(console.error);
