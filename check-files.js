const mongoose = require('mongoose');
const File = require('./models/file');

async function checkFiles() {
  try {
    await mongoose.connect('mongodb+srv://prasannaprasanna35521:YyWbAq2FoOietc7B@cluster0.0ytfuyz.mongodb.net/documents?retryWrites=true&w=majority');
    const count = await File.countDocuments();
    console.log('Total files in database:', count);
    
    const files = await File.find().select('filename uploadedAt').limit(10);
    console.log('\nFirst 10 files:');
    files.forEach(f => console.log(`- ${f.filename} (${f.uploadedAt})`));
    
    process.exit(0);
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

checkFiles();
