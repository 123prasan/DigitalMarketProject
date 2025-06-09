console.log("Server is starting...");
const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const Order = require('./Order');
// const pdfPoppler = require("pdf-poppler");
const fs = require("fs");
const Message=require("./message")
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
const session = require('express-session');
require("dotenv").config();
const mongoose = require("mongoose");
const dayjs = require('dayjs');   // npm install dayjs

// C:\Users\prasa\Music\uploads
const app = express();
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Connect to MongoDB with error handling
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.error("MongoDB connection error:", err));

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Parse JSON bodies
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key', // Use a strong secret in production!
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Only send cookie over HTTPS in production
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
}));

// Set views and static folder
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// Define Mongoose schema and model
const fileSchema = new mongoose.Schema({
  filedescription: String,
  user: String,
  filename: String,
  fileUrl: String,
  storedFilename: String, // <-- ADD THIS LINE
  price: Number,
  uploadedAt: { type: Date, default: Date.now },
  category: { type: String, required: true },
});

const File = mongoose.model('doccollection', fileSchema);

// Razorpay instance from env variables
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});

// Routes

// Create Razorpay order
app.post("/create-order", async (req, res) => {
  try {
    const { fileId, filename, price } = req.body;

    // Basic validation
    if (!fileId || !filename || !price || isNaN(price)) {
      return res.status(400).json({ error: "Missing or invalid fileId, filename, or price" });
    }
    // console.log({ fileId, filename, price })
    // Amount should ideally come from client or DB, hardcoded here for example
    const amountInPaise = Math.round(price * 100);
    // console.log(amountInPaise)
    const options = {
      amount: amountInPaise, // 100 INR in paise
      currency: "INR",
      receipt: `receipt_${fileId}`, // unique receipt using fileId // unique receipt id
    };
    const order = await razorpay.orders.create(options);
    // console.log("Order created:", order);
    
    res.json(order);
  } catch (error) {
    console.error("Order creation failed:", error);
    res.status(500).json({ error: "Failed to create order" });
  }
});

// Verify payment signature
app.post("/verify-payment", async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, fileId } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ success: false, message: "Incomplete payment details" });
  }

  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_SECRET)
    .update(body)
    .digest("hex");

  if (expectedSignature === razorpay_signature) {
    // Fetch payment details from Razorpay
    let paymentDetails;
    try {
      paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);
    } catch (err) {
      return res.status(500).json({ success: false, message: "Failed to fetch payment details" });
    }

    // Find file details for order info
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ success: false, message: "File not found" });
    }

    // Create order in DB
    const orderData = {
      orderId: razorpay_order_id,
      transactionId: razorpay_payment_id,
      customer: paymentDetails.email || paymentDetails.contact || "Online Customer",
      payment: paymentDetails.method, // This is the payment method (e.g., upi, card, netbanking, wallet)
      total: file.price,
      items: [{ name: file.filename, quantity: 1, price: file.price }],
      status: "Successfull",
      dateTime: new Date()
    };
    const order = new Order(orderData);
    await order.save();

    // Respond with order details
    res.json({
      success: true,
      order: {
        orderId: order.orderId,
        dateTime: order.dateTime,
        customer: order.customer,
        transactionId: order.transactionId,
        payment: order.payment, // This will be 'upi', 'card', 'netbanking', etc.
        total: order.total,
        items: order.items,
        status: order.status
      }
    });
  } else {
    res.status(400).json({ success: false, message: "Invalid signature" });
  }
});

// Render home page with file data
app.get("/", async (req, res) => {
  try {
    const files = await File.find();
    const filesWithPreviews = await Promise.all(
  files.map(async file => {
    const { data: previewData } = await supabase
      .storage
      .from('files')
      .createSignedUrl(`previews/${file._id}.jpg`, 60 * 5);

    const { data: pdfData } = await supabase
      .storage
      .from('files')
      .createSignedUrl(file.fileUrl, 60 * 5);

    return {
      ...file.toObject(),
      previewUrl: previewData?.signedUrl || null,
      pdfUrl: pdfData?.signedUrl || null
    };
  })
);
res.render('index', { files: filesWithPreviews });
  } catch (err) {
    console.error("DB fetch error:", err);
    res.status(500).send("Failed to load files");
  }
});

// PDF to image conversion endpoint
const pdfPath = path.join(__dirname, "uploads", "namdmfewfweewre.pdf");
const outputDir = path.join(__dirname, "public", "images");

app.get("/save", async (req, res) => {
  try {
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const options = {
      format: "jpeg",
      out_dir: outputDir,
      out_prefix: "page",
      page: 1,
    };

    await pdfPoppler.convert(pdfPath, options);

    const outputFile = path.join(outputDir, "page-1.jpg");

    if (fs.existsSync(outputFile)) {
      res.sendFile(outputFile);
    } else {
      res.status(404).send("Converted image not found");
    }
  } catch (err) {
    console.error("PDF conversion error:", err.message);
    res.status(500).send("Failed to convert PDF");
  }
});

// Sample thank you page after download or payment
app.get("/download-pdf", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "thankyou.html"));
});



// const newOrder = new Order({
//   orderId: "OR0D7",
//   transactionId: "TXN451047",
//   customer: "Neha Sharma",
//   payment: "Razorpay",
//   total: 799,
//   items: [{ name: "AI Notes", quantity: 1, price: 799 }],
//   status: "Successfull",
//   dateTime: new Date(),
// });

//  newOrder.save();

app.get("/admin", requireAdmin, async (req, res) => {
  const now = dayjs();
  const startCurrent = now.subtract(6, 'day').startOf('day').toDate();
  const endCurrent = now.endOf('day').toDate();
  const startPrev = now.subtract(13, 'day').startOf('day').toDate();
  const endPrev = now.subtract(7, 'day').endOf('day').toDate();

  // Current period
  const ordersCurrent = await Order.find({ dateTime: { $gte: startCurrent, $lte: endCurrent } });
  const totalOrders = ordersCurrent.length;
  const failedOrders = ordersCurrent.filter(o => o.status.toLowerCase().includes("unsuccess")).length;
  const successfulOrders = ordersCurrent.filter(o => o.status.toLowerCase().includes("success")).length;

  // Previous period
  const ordersPrev = await Order.find({ dateTime: { $gte: startPrev, $lte: endPrev } });
  const totalOrdersPrev = ordersPrev.length;
  const failedOrdersPrev = ordersPrev.filter(o => o.status.toLowerCase().includes("unsuccess")).length;
  const successfulOrdersPrev = ordersPrev.filter(o => o.status.toLowerCase().includes("success")).length;

  function calcTrend(current, prev) {
    if (prev === 0) return current === 0 ? 0 : 100;
    return (((current - prev) / prev) * 100).toFixed(1);
  }

  const totalOrdersTrend = calcTrend(totalOrders, totalOrdersPrev);
  const failedOrdersTrend = calcTrend(failedOrders, failedOrdersPrev);
  const successfulOrdersTrend = calcTrend(successfulOrders, successfulOrdersPrev);

  const uploadedFiles = await File.find({}).sort({ uploadedAt: -1 });

  const fileUpdated = req.query.fileUpdated === '1';
  const orderamount = await Order.aggregate([
    {
      $group: {
        _id: null,
        totalAmount: { $sum: "$total" }
      }
    }
  ]);
  const totalAmount = (orderamount[0] && orderamount[0].totalAmount) || 0;

  const files = await File.find({});
  const filesWithUrls = await Promise.all(
    files.map(async file => {
      const { data, error } = await supabase
        .storage
        .from('files')
        .createSignedUrl(file.fileUrl, 60 * 5); // 5 minutes

      return {
        ...file.toObject(),
        downloadUrl: data?.signedUrl || '#'
      };
    })
  );

  res.render("admin", {
    orders: await Order.find({}),
    uploadedFiles: filesWithUrls,
    totalOrders: totalOrders || 0,
    failedOrders: failedOrders || 0,
    successfulOrders: successfulOrders || 0,
    totalOrdersTrend: totalOrdersTrend || 0,
    failedOrdersTrend: failedOrdersTrend || 0,
    successfulOrdersTrend: successfulOrdersTrend || 0,
    fileUpdated,
    totalAmount: totalAmount || 0,
  });
});

// Protect /edit-filede
app.post('/edit-file', requireAdmin, async (req, res) => {
  const { fileId, filename, filedescription, price } = req.body;
  await File.findByIdAndUpdate(fileId, {
    filename,
    filedescription,
    price
  });
  res.redirect('/admin?fileUpdated=1');
});

// Protect /send-notification
app.post("/send-notification", requireAdmin, async (req, res) => {
  const message = req.body.message;
  if (!message) {
    return res.status(400).json({ error: "Message is required" });
  }
  try {
    const newMessage = new Message({ message });
    await newMessage.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Can't store message" });
  }
});

// const upload = multer({ dest: path.join(__dirname, 'uploads') });

app.post('/upload-file', upload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'previewImage', maxCount: 1 }
]), async (req, res) => {
  const { filename, filedescription, price, category } = req.body;
  const pdfFile = req.files['file']?.[0];
  const imageFile = req.files['previewImage']?.[0];
  if (!pdfFile || !imageFile) return res.status(400).send('PDF and image are required');

  // 1. Upload PDF to Supabase
  const { data: pdfData, error: pdfError } = await supabase.storage
    .from('files')
    .upload(`${Date.now()}_${pdfFile.originalname}`, pdfFile.buffer, {
      contentType: pdfFile.mimetype,
      upsert: false
    });
  if (pdfError) return res.status(500).send('Supabase PDF upload failed');

  // 2. Save metadata in MongoDB
  const newFile = await File.create({
    filename,
    filedescription,
    price,
    category,
    fileUrl: pdfData.path,
    uploadedAt: new Date(),
    user: req.user ? req.user.name : 'Admin'
  });

  // 3. Upload image to Supabase with the same file ID
  const { error: imgError } = await supabase.storage
    .from('files')
    .upload(`previews/${newFile._id}.jpg`, imageFile.buffer, {
      contentType: imageFile.mimetype,
      upsert: true
    });
  if (imgError) {
    console.error('Preview image upload failed:', imgError);
  }

  res.redirect('/admin?fileUploaded=1');
});


app.get('/viewfile/:id', async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file) return res.status(404).send('File not found');

  // Get signed URL from Supabase
  const { data, error } = await supabase
    .storage
    .from('files')
    .createSignedUrl(file.fileUrl, 30); // 30 seconds

  if (error || !data?.signedUrl) return res.status(404).send('File not found in storage');

  // Stream file from Supabase to user
  const axios = require('axios');
  const fileResponse = await axios.get(data.signedUrl, { responseType: 'stream' });
 res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
  res.setHeader('Content-Type', fileResponse.headers['content-type'] || 'application/octet-stream');
  fileResponse.data.pipe(res);
});

const bcrypt = require('bcrypt'); // npm install bcrypt

// Use environment variables for admin credentials
const ADMIN_USER = {
  username: process.env.ADMIN_USERNAME || 'admin',
  // Store a bcrypt hash in your .env, not the plain password!
  passwordHash: process.env.ADMIN_PASSWORD_HASH // bcrypt hash
};

// Login page
app.get('/login', (req, res) => {
  if (req.session.isAdmin) {
    return res.redirect('/admin');
  }
  res.render('login', { error: null });
});

// Handle login POST
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (
    username === ADMIN_USER.username &&
    ADMIN_USER.passwordHash &&
    await bcrypt.compare(password, ADMIN_USER.passwordHash)
  ) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.render('login', { error: 'Invalid username or password.' });
  }
});

// Middleware to protect /admin
function requireAdmin(req, res, next) {
  if (req.session.isAdmin) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Delete order
app.post('/delete-order', async (req, res) => {
  const { orderId } = req.body;
  // console.log("Deleting order with ID:", orderId);
  try {
    const result = await Order.deleteOne({ orderId });
    if (result.deletedCount > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: 'Order not found' });
    }
  } catch (err) {
    res.json({ success: false, message: 'Error deleting order' });
  }
});

// Notifications route
app.get('/notifications', async (req, res) => {
  // If you want to show only unseen, use req.query.unseen
  const query = {};
  if (req.query.unseen) query.seen = false;
  const notifications = await Message.find().sort({ DateTime: -1 });
  // console.log(notifications) // Sort by DateTime descending
  res.json({ notifications });
});

app.get('/file/:id', async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file) return res.status(404).send('File not found');

  // Get signed URL for the preview image from Supabase
  const { data: previewData } = await supabase
    .storage
    .from('files')
    .createSignedUrl(`previews/${file._id}.jpg`, 60 * 5);

  res.render('file-details', {
    file,
    razorpayKey: process.env.RAZORPAY_KEY_ID,
    previewUrl: previewData?.signedUrl || null
  });
});


app.post('/delete-file', async (req, res) => {
  const { fileId, fileUrl } = req.body;
  try {
    // Delete from Supabase Storage
    const { error: supabaseError } = await supabase
      .storage
      .from('files')
      .remove([fileUrl]);
    if (supabaseError) return res.json({ success: false, message: 'Supabase delete failed' });

    // Delete from MongoDB
    await File.deleteOne({ _id: fileId });

    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: 'Server error' });
  }
});
// Supabase client setup
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


async function pdfFirstPageToImage(pdfBuffer, outputPath) {
  const fontPath = path.join(
    require.resolve('pdfjs-dist/package.json'),
    '..',
    'standard_fonts'
  );

  const pdf = await pdfjsLib.getDocument({
    data: pdfBuffer,
    standardFontDataUrl: fontPath
  }).promise;

  const page = await pdf.getPage(1);
  const viewport = page.getViewport({ scale: 2 });
  const canvas = createCanvas(viewport.width, viewport.height);
  const context = canvas.getContext('2d');
  await page.render({ canvasContext: context, viewport }).promise;
  const out = fs.createWriteStream(outputPath);
  const stream = canvas.createJPEGStream();
  await new Promise((resolve, reject) => {
    stream.pipe(out);
    out.on('finish', resolve);
    out.on('error', reject);
  });
}
