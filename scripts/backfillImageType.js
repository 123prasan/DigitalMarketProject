// run with `node scripts/backfillImageType.js` from project root

const mongoose = require('mongoose');
const File = require('../models/file');

// change URI to your connection string
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/documents';

async function main() {
  await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('connected');

  const cursor = File.find({ imageType: { $exists: false } }).cursor();
  let count = 0;
  for (let doc = await cursor.next(); doc; doc = await cursor.next()) {
    let ext = null;
    if (doc.imageName) {
      ext = doc.imageName.split('.').pop().toLowerCase();
    } else if (doc.imageUrl) {
      const parts = doc.imageUrl.split('.');
      ext = parts.pop().split('?')[0].toLowerCase();
    }
    if (ext) {
      // normalise jpeg → jpg for consistency with new upload logic
      if (ext === 'jpeg') ext = 'jpg';
      if (['jpg','png','webp'].includes(ext)) {
        doc.imageType = ext;
        await doc.save();
        count++;
      }
    }
  }
  console.log(`updated ${count} documents`);
  mongoose.disconnect();
}

main().catch(err => {
  console.error(err);
  mongoose.disconnect();
});
