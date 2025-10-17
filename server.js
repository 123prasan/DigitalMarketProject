/**
 * The code is a Node.js application that uses Express to create a server for handling file uploads,
 * user authentication, order processing with Razorpay, MongoDB database interactions, and various
 * routes for managing files, admin dashboard, notifications, and error handling.
 * @returns The code provided is a Node.js application using Express framework. It includes routes for
 * handling file uploads, user authentication, file management, order processing, notifications, and
 * admin functionalities. The application interacts with MongoDB for data storage and Supabase for file
 * storage. It also integrates with Razorpay for payment processing.
 */

const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const Order = require("./models/Order");
const { fileroute } = require("./fileupload.js");

const { authRouter } = require("./routes/authentication/googleAuth");
// const pdfPoppler = require("pdf-poppler"); // Commented out in original, remains commented
const fs = require("fs");
const Message = require("./models/message");
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
// require("dotenv").config();
// const useLocalStorage = process.env.USE_LOCAL_STORAGE === 'true';
const mongoose = require("mongoose");
const dayjs = require("dayjs");
const bcrypt = require("bcrypt");
const mime = require("mime-types");
const axios = require("axios");
const http=require('http');

// const logVisitorMiddleware = require("./middlewares/ipmiddleware");
const categories = require("./models/categories"); // Assuming categories.js exports a Mongoose model
const { createClient } = require("@supabase/supabase-js");
const Location = require("./models/userlocation"); // Assuming Location.js exports a Mongoose model
const chatRoutes = require("./routes/chat.js");
const File = require("./models/file");
const courseRoutes = require("./routes/courseroutes");
const progressRoutes = require("./routes/progressroutes");
const authenticateJWT_user = require("./routes/authentication/jwtAuth.js");
const User = require("./models/userData");
const UserDownloads = require("./models/userDownloads.js");
const Userpurchases = require("./models/userPerchase.js");
const requireAuth = require("./routes/authentication/reaquireAuth.js");
const Usernotifications = require("./models/userNotifications");
const CF_DOMAIN = "https://d3tonh6o5ach9f.cloudfront.net"; // e.g., https://d123abcd.cloudfront.net
const Usertransaction = require("./models/userTransactions.js");
const UserChats = require('./testings4.js'); // <-- IMPORT THE NEW ROUTER
const Coupon=require("./models/couponschema.js");
const WebSocket = require('ws');
const admin = require('firebase-admin');
const UserMessage = require('./models/UserMessage.js');
const userbal=require("./models/userBalance.js");
const pushNotificationroute = require('./pushNotification.js');
const serviceAccount = require('./serviceAccountKey.json');
const sendNotification=require("./test.js")
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const app = express();
app.use(cookieParser());

app.use("/",UserChats);
 // Use cookie-parser middleware

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();
// --- Helper Functions ---

/**

 * Sends a JSON payload to a specific user if they are online.

 * @param {string} userId - The ID of the user to notify.

 * @param {object} payload - The JSON object to send.

 */

// --- In your Node.js Server file ---



// ... (keep your existing setup code)



// Helper function to broadcast a message to a user if they are online

function notifyUser(userId, payload) {

  // CRITICAL FIX: Always convert the userId to a string before looking it up in the Map.

  const userSocket = clients.get(String(userId));



  // Optional: Add a log to see if the user was found

  console.log(`Attempting to notify user ${String(userId)}. Online: ${!!userSocket}`);



  if (userSocket && userSocket.readyState === WebSocket.OPEN) {

    userSocket.send(JSON.stringify(payload));

  }

}



// --- WebSocket Logic (REPLACE THIS ENTIRE SECTION) ---

// --- ASSUMED EXTERNAL SETUP ---
// const WebSocket = require('ws');
// const wss = new WebSocket.Server({ port: 8000 });
// const clients = new Map(); // Global map of connected clients: Map<userId, ws>
// const UserMessage = require('./models/UserMessage'); // Your Mongoose model
// const User = require('./models/User'); // Your User model to fetch profile info



wss.on('connection', (ws) => {
    let userId; // This will store the ID for this specific connection

    const broadcastStatus = (targetUserId, isOnline) => {
        const statusPayload = JSON.stringify({
            type: 'user_status_update',
            userId: targetUserId,
            isOnline: isOnline
        });
        // Inform all connected clients of the status change
        clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(statusPayload);
            }
        });
        console.log(`[Status] Broadcast: User ${targetUserId} is ${isOnline ? 'Online' : 'Offline'}`);
    };

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);

            if (data.type !== 'register' && !userId) {
                return console.error("Message received from unregistered client.");
            }

            switch (data.type) {
                case 'register':
                    userId = String(data.userId);
                    clients.set(userId, ws);
                    console.log(`[Connect] User ${userId} connected.`);

                    // Broadcast that this new user is online to everyone
                    broadcastStatus(userId, true);

                    // Check the status of the person this user is talking to and send it back ONLY to them.
                    const recipientId = String(data.recipientId);
                    if (clients.has(recipientId)) {
                        const statusPayload = {
                            type: 'user_status_update',
                            userId: recipientId,
                            isOnline: true
                        };
                        // Send the recipient's status back to the newly registered user
                        ws.send(JSON.stringify(statusPayload));
                    }
                    break;

                case 'private_message':
                case 'reply_message':
                case 'product_message': {
                    const { id, recipientId, text, repliedTo, productInfo, createdAt } = data;
                    const conversationId = [userId, recipientId].sort().join('--');
                    const isProduct = data.type === 'product_message';
                    
                    // 1. Get sender profile for chat list update
                    const senderProfile = await User.findById(userId).select('username profilePicUrl isVerified');

                    // 2. Create and save the message
                    const messageDoc = new UserMessage({
                        id,
                        conversationId,
                        senderId: userId,
                        recipientId,
                        text: isProduct ? `Shared product: ${productInfo.name}` : text,
                        repliedTo: repliedTo || null,
                        productInfo: productInfo || null,
                        createdAt,
                        // Determine status based on recipient's connection
                        status: clients.has(String(recipientId)) ? 'delivered' : 'sent', 
                    });
                    await messageDoc.save();

                    // 3. Prepare payload for the RECIPIENT
                    // This payload needs the sender's details for the recipient's chat list to update
                    const fullMessagePayload = { 
                        ...messageDoc.toObject(), 
                        type: data.type,
                        partner: {
                            _id: userId,
                            username: senderProfile.username,
                            profilePicUrl: senderProfile.profilePicUrl,
                            isVerified: senderProfile.isVerified
                        }
                    };
                    notifyUser(recipientId, fullMessagePayload);

                    // 4. Notify the SENDER of delivery status if client is connected
                    if (messageDoc.status === 'delivered') {
                        notifyUser(userId, { type: 'message_status_update', messageId: id, status: 'delivered' });
                    }
                    console.log(`[Message] User ${userId} sent a message to ${recipientId} (${data.type})`);
                    break;
                }

                case 'mark_as_read': {
                    // This action comes from the CHAT PAGE when the user opens the conversation
                    const { partnerId } = data; 

                    // 1. Update all UNREAD incoming messages from the partner to 'read'
                    const result = await UserMessage.updateMany(
                        {
                            senderId: partnerId, // Messages SENT by the partner
                            recipientId: userId, // Messages RECEIVED by the current user
                            status: { $in: ['sent', 'delivered'] } 
                        },
                        { $set: { status: 'read' } }
                    );

                    console.log(`[Read All] User ${userId} marked ${result.modifiedCount} messages from ${partnerId} as read.`);

                    // 2. Notify the chat list client to remove the badge.
                    // This is essential for real-time badge clearance across devices/tabs.
                    const badgeClearPayload = {
                        type: 'unread_count_clear',
                        partnerId: partnerId // Client uses this to identify which chat to clear
                    };
                    notifyUser(userId, badgeClearPayload); 
                    
                    break;
                }

                case 'message_read': {
                    // This action comes from the CHAT PAGE when the user SCROLLS to see the message
                    const { messageId, senderId } = data; 
                    console.log(`[Read Status] Message: ${messageId}. Notifying sender: ${senderId}`);

                    await UserMessage.updateOne(
                        { id: messageId, status: { $ne: 'read' } },
                        { $set: { status: 'read' } }
                    );

                    const readPayload = { type: 'message_status_update', messageId, status: 'read' };
                    notifyUser(senderId, readPayload);
                    break;
                }

                case 'delete_message': {
                    const { messageId, recipientId } = data;

                    await UserMessage.updateOne(
                        { id: messageId, senderId: userId },
                        { $set: { isDeleted: true, text: "" } }
                    );

                    const deletePayload = { type: 'message_deleted', messageId };
                    notifyUser(userId, deletePayload);
                    notifyUser(recipientId, deletePayload);
                    console.log(`[Delete] User ${userId} deleted message ${messageId}`);
                    break;
                }

                case 'edit_message': {
                    const { messageId, newText, recipientId } = data;

                    await UserMessage.updateOne(
                        { id: messageId, senderId: userId },
                        { $set: { text: newText, isEdited: true } }
                    );

                    const editPayload = { type: 'message_edited', messageId, newText };
                    notifyUser(userId, editPayload);
                    notifyUser(recipientId, editPayload);
                    console.log(`[Edit] User ${userId} edited message ${messageId}`);
                    break;
                }

                case 'typing': {
                    // Forward the typing status to the recipient without saving to DB
                    notifyUser(data.recipientId, {
                        type: 'typing_status',
                        senderId: userId,
                        isTyping: data.isTyping
                    });
                    break;
                }
            }
        } catch (err) {
            console.error("❌ Failed to process message:", err);
        }
    });

    ws.on('close', () => {
        if (userId) {
            clients.delete(String(userId));
            console.log(`[Disconnect] User ${String(userId)} disconnected.`);
            broadcastStatus(userId, false);
        }
    });
});
// --- Middleware Setup ---
// Make sure you have your standard middleware here
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// app.use(cookieParser());
// app.set('view engine', 'ejs');
// ... etc.



app.use(express.json());
const cors = require("cors");
app.use(cors());

app.use("/api/courses", courseRoutes);
app.use("/api/progress", progressRoutes);

// app.use(cookieParser())
function getcategories() {
  return categories.find({}).then((cats) => cats.map((cat) => cat.name));
}

app.use(authRouter);
app.use((req, res, next) => {
  // console.log('Cookies Received by Server:', req.cookies);
  next();
});



// your normal routes

app.use(fileroute);
app.use( pushNotificationroute);
app.post("/save-location", async (req, res) => {
  let ip = req.body.ip;

  // Handle localhost IPs for development
  const check = await Location.findOne({ ip: ip });

  if (!check) {
    try {
      const geoRes = await fetch(`http://ip-api.com/json/${ip}`);
      const geoData = await geoRes.json();

      const savedLocation = await Location.create({
        ip: ip,
        city: geoData.city,
        region: geoData.regionName,
        country: geoData.country,
        postal_code: geoData.zip,
        latitude: geoData.lat,
        longitude: geoData.lon,
        full_address: `${geoData.city}, ${geoData.regionName}, ${geoData.country} - ${geoData.zip}`,
        createdAt: new Date(),
      });
      savedLocation.save();

      // console.log("Location saved:", savedLocation);
    } catch (err) {
      console.error("Location error:", err);
    }
  } else {
    console.log("Location already exists for this IP:", ip);
  }

  //    const ipadd=await axios.get('https://api64.ipify.org?format=json');
  //    console.log("IP Address:", ipadd);
});

// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Connect to MongoDB with error handling
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Middlewares
require("./routes/bots/cleanUpAcc.js");
require("./video-trans/sql.js");
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Parse JSON bodies

// Set views and static folder
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/chat", chatRoutes);


// This is a helper function to create a clean, URL-safe string
function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, "-") // Replace spaces with -
    .replace(/[^\w\-]+/g, "") // Remove all non-word chars
    .replace(/\-\-+/g, "-") // Replace multiple - with single -
    .replace(/^-+/, "") // Trim - from start of text
    .replace(/-+$/, ""); // Trim - from end of text
}

// This must match the collection name in your database

// Razorpay instance from env variables
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});

// Supabase client setup
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Middleware for JWT authentication
function authenticateJWT(req, res, next) {
  const token = req.cookies.jwt; // Get token from HTTP-only cookie

  if (!token) {
    // No token provided, redirect to login
    return res.render("login", { error: "Access denied. Please log in." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // Token is invalid or expired, clear the cookie and redirect
      res.clearCookie("jwt");
      return res.render("login", {
        error: "Session expired or invalid. Please log in again.",
      });
    }
    // Token is valid, attach user payload to request (e.g., req.user.isAdmin, req.user.username)
    req.user = user;
    next();
  });
}

// Admin User configuration (from .env)
const ADMIN_USER = {
  username: process.env.ADMIN_USERNAME,
  passwordHash: process.env.ADMIN_PASSWORD_HASH,
};

// --- Routes ---
app.get("/files/impression/:id/:impression",authenticateJWT_user,requireAuth, async (req, res) => {
  try {
    const { id, impression } = req.params;
    const update = {};

    if (impression === "like") {
      update.$inc = { likes: 1 };
    } else if (impression === "dislike") {
      update.$inc = { likes: -1 };
    } else {
      return res.status(400).json({ error: "Invalid impression type" });
    }

    const updated = await File.findByIdAndUpdate(id, update, { new: true });
    if (!updated) return res.status(404).json({ error: "File not found" });

    res.json({ likes: updated.likes });
  } catch (err) {
    console.error("Error updating likes:", err);
    res.status(500).json({ error: "Server error" });
  }
});


app.get("/dashboard", (req, res) => {
  res.render("createcourse");
});
// Razorpay Order Creation - No auth needed (public)
app.post("/create-order", async (req, res) => {
  try {
    const { fileId, filename, price } = req.body;

    if (!fileId || !filename || !price || isNaN(price)) {
      return res
        .status(400)
        .json({ error: "Missing or invalid fileId, filename, or price" });
    }
    const amountInPaise = Math.round(price * 100);
    const options = {
      amount: amountInPaise,
      currency: "INR",
      receipt: `receipt_${fileId}`,
    };
    const order = await razorpay.orders.create(options);
    // console.log(order);
    res.json(order);
  } catch (error) {
    console.error("Order creation failed:", error);
    res.status(500).json({ error: "Failed to create order" });
  }
});
app.get("/privacy-policy", (req, res) => {
  res.render("privacy-policy");
});
app.get("/refund-policy", (req, res) => {
  res.render("refundpolicy");
});
app.get("/terms-and-conditions", (req, res) => {
  res.render("terms&conditions");
});
let token;
const Adminbal = require("./models/admin/adminBal.js");

// Razorpay Payment Verification - No auth needed (public)
app.post("/verify-payment", authenticateJWT_user, async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    fileId,
    totalprice,
  } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({
      success: false,
      message: "Incomplete payment details",
    });
  }

  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_SECRET)
    .update(body)
    .digest("hex");

  if (expectedSignature !== razorpay_signature) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid signature" });
  }

  try {
    // Fetch Razorpay payment details
    let paymentDetails;
    try {
      paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);
    } catch (err) {
      console.error("Razorpay fetch failed:", err);
      return res.status(502).json({
        success: false,
        message: "Payment gateway error",
      });
    }

    // Fetch file
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ success: false, message: "File not found" });
    }

    const platformCut = totalprice * 0.3;
    const sellerShare = totalprice - platformCut;
    const discount =
      req.body.CouponData?.priceDetails?.discountedPrice
        ? file.price - req.body.CouponData.priceDetails.discountedPrice
        : 0;

    const token = jwt.sign(
      { fileId, orderId: razorpay_order_id, transactionId: razorpay_payment_id },
      process.env.JWT_SECRET_FILE_PURCHASE,
      { expiresIn: "10m" }
    );

    const imageUrl = await getValidFileUrl(file);

    // Parallel DB writes (independent)
    await Promise.all([
      // Transaction record
      Usertransaction.findOneAndUpdate(
        { transactionId: razorpay_payment_id },
        {
          userId: file.userId,
          ProductId: file._id,
          totalAmount: sellerShare,
          ProductName: file.filename,
          purchaserId: req.user._id,
          transactionId: razorpay_payment_id,
          discount,
        },
        { upsert: true, new: true }
      ),

      // Seller balance
      userbal.findOneAndUpdate(
        { UserId: file.userId },
        { $inc: { Balance: sellerShare } },
        { upsert: true, new: true }
      ),

      // Admin balance
      Adminbal.findOneAndUpdate(
        {},
        { $inc: { totalAmount: platformCut, cutOffbal: sellerShare } },
        { upsert: true, new: true }
      ),

      // Order record
      Order.findOneAndUpdate(
        { orderId: razorpay_order_id },
        {
          orderId: razorpay_order_id,
          transactionId: razorpay_payment_id,
          customer: paymentDetails.email || paymentDetails.contact || "Online Customer",
          payment: paymentDetails.method,
          total: totalprice,
          productId: file._id,
          productName: file.filename,
          items: [{ name: file.filename, quantity: 1, price: file.price }],
          status: "Successful",
          dateTime: new Date(),
        },
        { upsert: true, new: true }
      ),

      // User purchase
      Userpurchases.create({
        userId: req.user._id,
        productId: file._id,
        price: file.price,
        totalPrice: totalprice,
        productName: file.filename,
        orderId: razorpay_order_id,
        purchaseId: razorpay_payment_id,
        quantity: 1,
      }),

      // User download
      UserDownloads.findOneAndUpdate(
        { userId: req.user._id, fileId: file._id },
        {
          userId: req.user._id,
          fileId: file._id,
          filename: file.filename,
          fileUrl: file.fileUrl,
          fileType: path.extname(file.fileUrl).toLowerCase() || "pdf",
        },
        { upsert: true, setDefaultsOnInsert: true }
      ),

      // User notification
      Usernotifications.create({
        userId: req.user._id,
        type: "purchase",
        message: `Your purchase of the file <strong>${file.filename}</strong> has been successful.`,
        targetId: file._id,
      }),
    ]);

    // Fire-and-forget push notification
(async () => {
  const notifications = [
    sendNotification({
      userId: req.user._id,
      title: "Your product Purchase is Successful",
      body: `You can see your Files in the My Downloads section. Your Product: ${file.filename}`,
      image: imageUrl,
      target_link: "/downloads",
      notification_type: "purchase",
    }),
    sendNotification({
      userId: file.userId,
      title: `Someone Bought Your Product ${file.filename}`,
      body: `🤑 You Earned Amount of ₹ ${sellerShare}`,
      image: imageUrl,
      target_link: "/dashboard",
      notification_type: "transaction",
    }),
  ];

  const results = await Promise.allSettled(notifications);

  results.forEach((result, index) => {
    if (result.status === "rejected") {
      const type = index === 0 ? "Purchase" : "Transaction";
      console.error(`${type} notification failed:`, result.reason);
    }
  });
})();


    // Send response immediately
    return res.json({
      success: true,
      downloadUrl: `/viewfile/${file.slug}/${file._id}?token=${token}`,
    });
  } catch (err) {
    console.error("Error in /verify-payment:", err);
    return res.status(500).json({
      success: false,
      message: "Payment verification failed",
    });
  }
});


// Home Page - Render files
app.get("/", authenticateJWT_user, async (req, res) => {
  try {
    const files = await File.find().sort({ downloadCount: -1 }).limit(5);
    const filesWithPreviews = await Promise.all(
      files.map(async (file) => {
        const { data: previewData } = await supabase.storage
          .from("files")
          .createSignedUrl(`previews/${file._id}.jpg`, 60 * 5);

        const { data: pdfData } = await supabase.storage
          .from("files")
          .createSignedUrl(file.fileUrl, 60 * 5);

        return {
          ...file.toObject(),
          previewUrl: previewData?.signedUrl || null,
          pdfUrl: pdfData?.signedUrl || null,
        };
      })
    );

    let user = null;

    if (req.user) {
      const userId = req.user._id;
      // Fetch only the necessary fields
      user = await User.findById(userId).select("profilePicUrl username email");
      if (user) {
        console.log("User profile pic URL:", user.profilePicUrl);
      }
    }
    res.render("landing", {
      popularFiles: filesWithPreviews,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      uId: user?._id || null,
    });
  } catch (err) {
    console.error("DB fetch error:", err);
    res.status(500).send("Something Went Wrong");
  }
});

// PDF to Image Conversion (Utility - currently commented out in original)
const pdfPath = path.join(__dirname, "uploads", "namdmfewfweewre.pdf");
const outputDir = path.join(__dirname, "public", "images");

app.get("/save", async (req, res) => {
  try {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    const options = {
      format: "jpeg",
      out_dir: outputDir,
      out_prefix: "page",
      page: 1,
    };
    // await pdfPoppler.convert(pdfPath, options); // Requires pdf-poppler to be uncommented
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

// Download PDF - No auth needed (public, post-payment)
// app.post("/download-pdf", async (req, res) => {
//     const { fileId, paymentId } = req.body;

//     if (!fileId) return res.status(400).send("Missing fileId");

//     const file = await File.findById(fileId);
//     if (!file) return res.status(404).send("File not found");

//     // Increment download count here
//     await File.updateOne({ _id: file._id }, { $inc: { downloadCount: 1 } });

//     const { data, error } = await supabase
//         .storage
//         .from('files')
//         .createSignedUrl(file.fileUrl.replace(/^\/+/, ''), 30);

//     if (error || !data?.signedUrl) return res.status(404).send("File not found in storage");

//     try {
//         const fileResponse = await axios.get(data.signedUrl, { responseType: 'stream' });
//         const contentType = fileResponse.headers['content-type'];
//         let extension = mime.extension(contentType) || 'pdf';
//         let baseName = file.filename ? file.filename.split('.')[0] : 'file';
//         const safeFilename = encodeURIComponent(`${baseName}.${extension}`);

//         res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
//         res.setHeader('Content-Type', contentType || 'application/octet-stream');

//         fileResponse.data.on('error', (err) => {
//             console.error('Stream error:', err);
//             res.status(500).send('Error streaming file');
//         });

//         fileResponse.data.pipe(res);

//     } catch (err) {
//         console.error('Axios download error:', err);
//         res.status(500).send('Failed to download file');
//     }
// });

// --- Admin Authentication & Routes ---

// Login Page (GET)
app.get("/admin-login", (req, res) => {
  // If a valid JWT cookie exists, redirect to admin immediately
  if (req.cookies.jwt) {
    try {
      jwt.verify(req.cookies.jwt, process.env.JWT_SECRET);
      return res.redirect("/admin");
    } catch (error) {
      // Token is invalid, clear it and proceed to login page to show error
      res.clearCookie("jwt");
    }
  }
  res.render("login", { error: null });
});
app.get("/user-login", (req, res) => {
  res.render("user-login.ejs");
});
// Handle Login (POST) - No auth check needed here, this is auth itself
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (
    username === ADMIN_USER.username &&
    ADMIN_USER.passwordHash &&
    (await bcrypt.compare(password, ADMIN_USER.passwordHash))
  ) {
    // Generate JWT token with 24h expiry
    const token = jwt.sign(
      { isAdmin: true, username: ADMIN_USER.username },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set the token as an HTTP-only cookie with 24h maxAge
    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      sameSite: "Lax",
    });

    // Redirect to admin page upon successful login
    res.redirect("/admin");
  } else {
    // Render login page with error for invalid credentials
    res.render("login", { error: "Invalid username or password." });
  }
});

// Logout Route - Clears the JWT cookie
app.get("/logout", (req, res) => {
  res.clearCookie("jwt"); // Clear the JWT cookie from the browser
  res.redirect("/login"); // Redirect to login page
});

// Admin Dashboard (Protected by JWT)
// const dayjs = require('dayjs');
const quarterOfYear = require("dayjs/plugin/quarterOfYear"); // Import the plugin
dayjs.extend(quarterOfYear); // Extend dayjs with the plugin
async function fetchaddress() {
  const allAddresses = await Location.find({}).sort({ createdAt: -1 });
  return allAddresses; // Fetch last 100 addresses
}
// Fetch last 100 addresses

app.get("/admin", authenticateJWT, async (req, res) => {
  const now = dayjs();
  const startCurrent = now.subtract(6, "day").startOf("day").toDate();
  const endCurrent = now.endOf("day").toDate();
  const startPrev = now.subtract(13, "day").startOf("day").toDate();
  const endPrev = now.subtract(7, "day").endOf("day").toDate();

  const ordersCurrent = await Order.find({
    dateTime: { $gte: startCurrent, $lte: endCurrent },
  });
  const totalOrders = ordersCurrent.length;
  const failedOrders = ordersCurrent.filter((o) =>
    o.status.toLowerCase().includes("unsuccessfull")
  ).length;
  const successfulOrders = ordersCurrent.filter((o) =>
    o.status.toLowerCase().includes("successfull")
  ).length;

  const ordersPrev = await Order.find({
    dateTime: { $gte: startPrev, $lte: endPrev },
  });
  const totalOrdersPrev = ordersPrev.length;
  const failedOrdersPrev = ordersPrev.filter((o) =>
    o.status.toLowerCase().includes("unsuccessfull")
  ).length;
  const successfulOrdersPrev = ordersPrev.filter((o) =>
    o.status.toLowerCase().includes("successfull")
  ).length;

  function calcTrend(current, prev) {
    if (prev === 0) return current === 0 ? 0 : 100;
    return (((current - prev) / prev) * 100).toFixed(1);
  }

  const totalOrdersTrend = calcTrend(totalOrders, totalOrdersPrev);
  const failedOrdersTrend = calcTrend(failedOrders, failedOrdersPrev);
  const successfulOrdersTrend = calcTrend(
    successfulOrders,
    successfulOrdersPrev
  );

  const uploadedFiles = await File.find({}).sort({ uploadedAt: -1 });

  const fileUpdated = req.query.fileUpdated === "1";
  const orderamount = await Order.aggregate([
    {
      $group: {
        _id: null,
        totalAmount: { $sum: "$total" },
      },
    },
  ]);
  const totalAmount = (orderamount[0] && orderamount[0].totalAmount) || 0;

  const files = await File.find({});
  const filesWithUrls = await Promise.all(
    files.map(async (file) => {
      try {
        // Construct the S3 key
        const key = `main-files/${file.fileUrl}`; // adapt if your file structure is different

        // Generate pre-signed URL (valid for 5 minutes)
        const downloadUrl = s3.getSignedUrl("getObject", {
          Bucket: "vidyarimain",
          Key: key,
          Expires: 5 * 60, // 5 minutes
        });

        return {
          ...file.toObject(),
          downloadUrl,
        };
      } catch (err) {
        console.error(`Error generating URL for ${file.fileUrl}`, err);
        return {
          ...file.toObject(),
          downloadUrl: "#",
        };
      }
    })
  );

  // --- NEW DATA FETCHING FOR CHARTS ---

  // 1. Data for "Orders & Revenue Trends" Chart (Dashboard) - Last 12 months
  const monthlyData = await Order.aggregate([
    {
      $match: {
        // Filter for orders within the last 12 months
        dateTime: {
          $gte: dayjs().subtract(11, "month").startOf("month").toDate(),
          $lte: dayjs().endOf("month").toDate(),
        },
        // Only count successful orders for revenue
        status: { $in: ["Successfull"] },
      },
    },
    {
      $group: {
        _id: {
          year: { $year: "$dateTime" },
          month: { $month: "$dateTime" },
        },
        totalOrders: { $sum: 1 },
        totalRevenue: { $sum: "$total" },
      },
    },
    {
      $sort: { "_id.year": 1, "_id.month": 1 },
    },
  ]);

  const monthlyLabels = [];
  const monthlyTotalOrdersData = [];
  const monthlyTotalRevenueData = [];

  // Populate data for the last 12 months, filling with 0 if no orders exist for a month
  let currentMonth = dayjs().subtract(11, "month").startOf("month");
  for (let i = 0; i < 12; i++) {
    const monthName = currentMonth.format("MMM YYYY"); // e.g., "Jan 2024"
    monthlyLabels.push(monthName);

    const foundMonthData = monthlyData.find(
      (item) =>
        item._id.year === currentMonth.year() &&
        item._id.month === currentMonth.month() + 1
    );

    monthlyTotalOrdersData.push(
      foundMonthData ? foundMonthData.totalOrders : 0
    );
    monthlyTotalRevenueData.push(
      foundMonthData ? foundMonthData.totalRevenue : 0
    );

    currentMonth = currentMonth.add(1, "month");
  }

  // 2. Data for "Revenue Trends Over Time" Chart (Analytics section) - Last 4 weeks
  const weeklyRevenueDataPoints = [];
  const weeklyRevenueLabels = [];

  for (let i = 3; i >= 0; i--) {
    // Loop from 3 weeks ago down to current week
    const weekStart = dayjs().subtract(i, "week").startOf("week").toDate();
    const weekEnd = dayjs().subtract(i, "week").endOf("week").toDate();

    const revenueForWeek = await Order.aggregate([
      {
        $match: {
          dateTime: { $gte: weekStart, $lte: weekEnd },
          status: { $in: ["Successfull"] },
        },
      },
      { $group: { _id: null, total: { $sum: "$total" } } },
    ]);

    weeklyRevenueDataPoints.push(
      parseFloat(
        ((revenueForWeek[0] && revenueForWeek[0].total) || 0).toFixed(2)
      )
    );
    weeklyRevenueLabels.push(dayjs(weekStart).format("MMM D")); // e.g., "Jun 3"
  }

  // 3. Data for "Order Status Distribution" Chart (Analytics section)
  const successfulOrdersCount = await Order.countDocuments({
    status: "Successfull",
  });
  const unsuccessfulOrdersCount = await Order.countDocuments({
    status: "unsuccessfull",
  });
  const pendingOrdersCount = await Order.countDocuments({ status: "Pending" });

  const orderStatusCounts = {
    successful: successfulOrdersCount,
    unsuccessful: unsuccessfulOrdersCount,
    pending: pendingOrdersCount,
  };

  // 4. Data for "Average Order Value" Chart (Analytics section) - Last 4 quarters
  const aovDataPoints = [];
  const aovLabels = [];

  for (let i = 3; i >= 0; i--) {
    // Loop from 3 quarters ago down to current quarter
    const quarterStart = dayjs()
      .subtract(i, "quarter")
      .startOf("quarter")
      .toDate();
    const quarterEnd = dayjs().subtract(i, "quarter").endOf("quarter").toDate();

    const aovForQuarter = await Order.aggregate([
      {
        $match: {
          dateTime: { $gte: quarterStart, $lte: quarterEnd },
          status: { $in: ["Successfull"] },
        },
      },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: "$total" },
          totalOrders: { $sum: 1 },
        },
      },
    ]);

    const aov =
      aovForQuarter[0] && aovForQuarter[0].totalOrders > 0
        ? aovForQuarter[0].totalRevenue / aovForQuarter[0].totalOrders
        : 0;

    aovDataPoints.push(parseFloat(aov.toFixed(2)));
    aovLabels.push(dayjs(quarterStart).format("Q [Q] YYYY")); // e.g., "2 Q 2024"
  }

  const categories = await getcategories(); // Fetch c
  const allAddresses = await fetchaddress(); // Fetch last 100 addresses
  res.render("admin", {
    orders: await Order.find({}).sort({ dateTime: -1 }), // Ensure orders are sorted for "Recent Orders"
    uploadedFiles: filesWithUrls,
    totalOrders: totalOrders || 0,
    failedOrders: failedOrders || 0,
    successfulOrders: successfulOrders || 0,
    totalOrdersTrend: totalOrdersTrend || 0,
    failedOrdersTrend: failedOrdersTrend || 0,
    successfulOrdersTrend: successfulOrdersTrend || 0,
    fileUpdated,
    totalAmount: totalAmount || 0,
    categories,
    // NEW DATA FOR CHARTS
    monthlyLabels: monthlyLabels,
    monthlyTotalOrdersData: monthlyTotalOrdersData,
    monthlyTotalRevenueData: monthlyTotalRevenueData,
    weeklyRevenueLabels: weeklyRevenueLabels,
    weeklyRevenueData: weeklyRevenueDataPoints,
    orderStatusCounts: orderStatusCounts,
    aovLabels: aovLabels,
    aovData: aovDataPoints,
    allAddresses,
  });
});

function getCSSVariables() {
  // Create a dummy element, attach to the DOM, get styles, and remove
  const dummy = document.createElement("div");
  dummy.style.display = "none";
  document.body.appendChild(dummy);
  const computedStyle = window.getComputedStyle(dummy);

  const colors = {
    primary: computedStyle.getPropertyValue("--primary").trim(),
    primaryLight: computedStyle.getPropertyValue("--primary-light").trim(),
    success: computedStyle.getPropertyValue("--success").trim(),
    badgeSuccessBg: computedStyle.getPropertyValue("--badge-success-bg").trim(),
    danger: computedStyle.getPropertyValue("--danger").trim(),
    textDark: computedStyle.getPropertyValue("--text-dark").trim(),
    textLight: computedStyle.getPropertyValue("--text-light").trim(),
    border: computedStyle.getPropertyValue("--border").trim(),
    background: computedStyle.getPropertyValue("--background").trim(),
  };

  document.body.removeChild(dummy); // Clean up
  return colors;
}

// Edit File Details (Protected by JWT)
app.post("/edit-file", authenticateJWT, async (req, res) => {
  const { fileId, filename, filedescription, price } = req.body;
  await File.findByIdAndUpdate(fileId, {
    filename,
    filedescription,
    price,
  });
  res.redirect("/admin?fileUpdated=1");
});

// Send Notification (Protected by JWT)
app.post("/send-notification", authenticateJWT, async (req, res) => {
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

// Upload File (Protected by JWT)
app.post(
  "/upload-file",
  upload.fields([
    { name: "file", maxCount: 1 },
    { name: "previewImage", maxCount: 1 },
  ]),
  authenticateJWT,
  async (req, res) => {
    const { filename, filedescription, price, category } = req.body;
    const pdfFile = req.files["file"]?.[0];
    const imageFile = req.files["previewImage"]?.[0];
    if (!pdfFile || !imageFile)
      return res.status(400).send("PDF and image are required");

    // 1. Upload PDF to Supabase
    const { data: pdfData, error: pdfError } = await supabase.storage
      .from("files")
      .upload(`${Date.now()}_${pdfFile.originalname}`, pdfFile.buffer, {
        contentType: pdfFile.mimetype,
        upsert: false,
      });
    if (pdfError) return res.status(500).send("Supabase PDF upload failed");

    // 2. Save metadata in MongoDB, including file size
    const newFile = await File.create({
      filename,
      filedescription,
      price,
      category,
      fileUrl: pdfData.path,
      uploadedAt: new Date(),
      user: req.user ? req.user.username : "Admin",
      fileSize: pdfFile.size, // <-- Add this line
    });
    //notification update
    const newMessage = new Message({
      message: `New file uploaded: ${filename} by ${req.user ? req.user.username : "Admin"
        }`,
    });
    await newMessage.save();
    const { error: imgError } = await supabase.storage
      .from("files")
      .upload(`previews/${newFile._id}.jpg`, imageFile.buffer, {
        contentType: imageFile.mimetype,
        upsert: true,
      });
    if (imgError) {
      console.error("Preview image upload failed:", imgError);
    }

    res.redirect("/admin?fileUploaded=1");
    // ...rest of your code...
  }
);

// Delete Order - NOW PROTECTED BY JWT
app.post("/delete-order", authenticateJWT, async (req, res) => {
  const { orderId } = req.body;
  try {
    const result = await Order.deleteOne({ orderId });
    if (result.deletedCount > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: "Order not found" });
    }
  } catch (err) {
    res.json({ success: false, message: "Error deleting order" });
  }
});

// Notifications API
app.get("/notifications", async (req, res) => {
  const query = {};
  if (req.query.unseen) query.seen = false;
  const notifications = await Message.find().sort({ DateTime: -1 });
  res.json({ notifications });
});

// File Details Page
// The route now expects a slug and an id
// const CF_DOMAIN = process.env.CF_DOMAIN; // e.g., https://d123abcd.cloudfront.net

// const axios = require("axios");

const VALID_IMAGE_TYPES = ["jpg", "jpeg", "png", "webp", "gif"];

// const axios = require('axios');

// const VALID_IMAGE_TYPES = ['jpg', 'jpeg', 'png', 'webp'];

async function getValidFileUrl(file, REGION = 'ap-south-1', validTypes = VALID_IMAGE_TYPES) {
  const triedExtensions = new Set();

  // 👇 Replace CF domain with your actual S3 bucket URL
  const S3_BUCKET = 'vidyari2';
  const BASE_URL = `https://${S3_BUCKET}.s3.${REGION}.amazonaws.com`;

  // 1️⃣ Try the file.imageType first
  if (file.imageType) {
    const url = `${BASE_URL}/files-previews/images/${file._id}.${file.imageType}`;
    triedExtensions.add(file.imageType);
    try {
      const res = await axios.head(url);
      if (res.status === 200) return url;
    } catch (err) {
      // Ignore 403/404 errors (not found)
    }
  }

  // 2️⃣ Try other possible extensions
  for (const ext of validTypes) {
    if (triedExtensions.has(ext)) continue;
    const url = `${BASE_URL}/files-previews/images/${file._id}.${ext}`;
    try {
      const res = await axios.head(url);
      if (res.status === 200) {
        // ✅ Found valid image — update DB if needed
        if (file.imageType !== ext) {
          file.imageType = ext;
          await file.save();
        }
        return url;
      }
    } catch (err) {
      if (err.response && (err.response.status === 403 || err.response.status === 404)) continue;
      console.error("Unexpected error checking file:", err.message);
    }
  }

  // 3️⃣ Fallback (default to .jpg)
  return `${BASE_URL}/files-previews/images/${file._id}.jpg`;
}


app.get("/file/:slug/:id", authenticateJWT_user, async (req, res) => {
  try {
    // Validate ID length
    if (req.params.id.length !== 24) {
      return res.render("file-not-found");
    }

    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).render("404", { message: "File not found" });
    }
let ISVERIFIED=false;
    // Get seller profile picture
    let sellerprofilepic = "/images/avatar.jpg"; // default
    if (file.userId) {
      const findUser = await User.findById(file.userId);
      if (findUser?.profilePicUrl) {
        sellerprofilepic = findUser.profilePicUrl;
      }
      ISVERIFIED=findUser.ISVERIFIED || false;
    }

    // Redirect if slug is incorrect
    if (file.slug !== req.params.slug) {
      return res.redirect(301, `/file/${file.slug}/${file._id}`);
    }

    // Build URLs (CloudFront) with valid preview URL
    const previewUrl = await getValidFileUrl(file);
    const pdfUrl = `${CF_DOMAIN}/${file.fileUrl}`;

    console.log("Preview URL:", previewUrl);

    // Logged in user
    let user = null;
    if (req.user) {
      user = await User.findById(req.user._id);
    }
   
    res.render("file-details", {
      file,
      sellerprofilepic,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
      previewUrl,
      pdfUrl,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
     ISVERIFIED,
      uId: user?._id || null,
    });
  } catch (error) {
    console.error("Error fetching file:", error);
    res.status(500).send("Server error");
  }
});
;
;

// Delete File - NOW PROTECTED BY JWT
// const AWS = require("aws-sdk");
// const File = require("./models/file");

// Configure S3
// const s3 = new AWS.S3({
//   accessKeyId: process.env.AWS_ACCESS_KEY_ID,
//   secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
//   region: process.env.AWS_REGION, // e.g., "ap-south-1"
// });

app.post("/delete-file", authenticateJWT, async (req, res) => {
  const { fileId, fileUrl } = req.body;

  try {
    const file = await File.findById(fileId);
    if (!file) return res.json({ success: false, message: "File not found" });

    // Construct S3 keys
    const mainFileKey = `main-files/${fileUrl}`;             // for vidyari-main bucket
    const previewKey = `/files-previews/images/${file._id}.${file.imageType || "jpg"}`; // for vidyari2 bucket

    // Delete main file from vidyari-main
    await s3
      .deleteObject({ Bucket: "vidyarimain", Key: mainFileKey })
      .promise();

    // Delete preview image from vidyari2
    await s3
      .deleteObject({ Bucket: "vidyari2", Key: previewKey })
      .promise();

    // Delete MongoDB record
    await File.deleteOne({ _id: fileId });
    console.log("file deleted")
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Server error" });
  }
});
//user-notifications

// Start Server
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Helper function (from original code, requires external libs if uncommented)
async function pdfFirstPageToImage(pdfBuffer, outputPath) {
  // This function is still using commented-out pdfjsLib and canvas, leaving it as is.
  // Ensure you have `pdfjs-dist` and `canvas` installed if you intend to use this.
  // const fontPath = path.join(
  //     require.resolve('pdfjs-dist/package.json'),
  //     '..',
  //     'standard_fonts'
  // );
  // const pdf = await pdfjsLib.getDocument({
  //     data: pdfBuffer,
  //     standardFontDataUrl: fontPath
  // }).promise;
  // const page = await pdf.getPage(1);
  // const viewport = page.getViewport({ scale: 2 });
  // const canvas = createCanvas(viewport.width, viewport.height);
  // const context = canvas.getContext('2d');
  // await page.render({ canvasContext: context, viewport }).promise;
  // const out = fs.createWriteStream(outputPath);
  // const stream = canvas.createJPEGStream();
  // await new Promise((resolve, reject) => {
  //     stream.pipe(out);
  //     out.on('finish', resolve);
  //     out.on('error', reject);
  // });
}

// View File Route
// You will need axios and path for this route
// const axios = require('axios');
// const path = require('path');

app.get("/viewfile/:slug/:id", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(403).send("Missing token");

    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET_FILE_PURCHASE);
    } catch (err) {
      return res.status(403).send("Link expired or invalid");
    }

    // Validate file matches token
    if (payload.fileId !== req.params.id) {
      return res.status(403).send("Invalid file");
    }
    const file = await File.findById(payload.fileId);
    // ✅ Generate Supabase signed URL
    // const { data, error } = await supabase.storage
    //   .from("files")
    //   .createSignedUrl(file.fileUrl, 60); // link valid 1 min

    // if (error || !data?.signedUrl) {
    //   return res.status(500).send("Could not fetch file");
    // }

    res.render("thank-you", { file, expiry: 120 });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});
// const path = require("path");
// const fs = require("fs");
// const fs = require("fs");
const AWS = require("aws-sdk");
// const path = require("path");
// const mime = require("mime-types");

// AWS S3 config
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || "ap-south-1",
});

// Route
app.get("/download", authenticateJWT_user, requireAuth, async (req, res) => {
  try {
    const fileId = req.query.file_id;

    // Validate fileId
    if (!fileId || fileId.length !== 24) return res.render("file-not-found");

    // Find file
    const file = await File.findById(fileId);
    if (!file) return res.render("file-not-found");

    // Purchase check for paid files
    if (file.price > 0) {
      const purchase = await Userpurchases.findOne({
        userId: req.user._id,
        productId: fileId,
      });
      if (!purchase) return res.render("404");
    }

    const extension = path.extname(file.fileUrl).toLowerCase() || ".pdf";
    const baseName = path.basename(file.filename, path.extname(file.filename));
    const finalFilename = `${baseName}${extension}`;
    const fileKey = `main-files/${file.fileUrl}`;

    // Increment total download count in File document
    await File.findByIdAndUpdate(fileId, { $inc: { downloadCount: 1 } });
const imageUrl=await getValidFileUrl(file);
    // Log per-user download and increment count
    await UserDownloads.findOneAndUpdate(
      { userId: req.user._id, fileId: file._id },
      {
        $setOnInsert: {
          filename: file.filename,
          fileUrl: file.fileUrl,
          fileType: extension,
        },
        $inc: { downloadCount: 1 },
      },
      { upsert: true, new: true }
    );
   

    // Get S3 object stream
    const s3Stream = s3
      .getObject({
        Bucket: "vidyarimain",
        Key: fileKey,
      })
      .createReadStream();
(async () => {
  const notifications = [
    sendNotification({
      userId: req.user._id,
      title: `Downloading is Started ${file.filename}`,
      body: `Please Check Your Notifications`,
      image: imageUrl,
      target_link: "/downloads",
      notification_type: "Download",
    })
   
  ];

  const results = await Promise.allSettled(notifications);

  results.forEach((result, index) => {
    if (result.status === "rejected") {
      const type = index === 0 ? "Purchase" : "Transaction";
      console.error(`${type} notification failed:`, result.reason);
    }
  });
})();
    // Set headers for direct download
    res.setHeader("Content-Disposition", `attachment; filename="${finalFilename}"`);
    res.setHeader("Content-Type", mime.lookup(extension) || "application/octet-stream");

    // Pipe S3 stream to response
    s3Stream.pipe(res).on("error", (err) => {
      console.error("S3 stream error:", err);
      res.status(500).render("500");
    });
  } catch (error) {
    console.error("Error in /download route:", error);
    res.status(500).render("500");
  }
});
;

const dotenv = require("dotenv");
const usernotifications = require("./models/userNotifications.js");
dotenv.config();

// const axios = require("axios");

// const axios = require('axios');

// const VALID_IMAGE_TYPES = ['jpg', 'jpeg', 'png', 'webp'];

async function getValidFileUrl(file, REGION = 'ap-south-1', validTypes = VALID_IMAGE_TYPES) {
  const triedExtensions = new Set();

  // 👇 Replace CF domain with your actual S3 bucket URL
  const S3_BUCKET = 'vidyari2';
  const BASE_URL = `https://${S3_BUCKET}.s3.${REGION}.amazonaws.com`;

  // 1️⃣ Try the file.imageType first
  if (file.imageType) {
    const url = `${BASE_URL}/files-previews/images/${file._id}.${file.imageType}`;
    triedExtensions.add(file.imageType);
    try {
      const res = await axios.head(url);
      if (res.status === 200) return url;
    } catch (err) {
      // Ignore 403/404 errors (not found)
    }
  }

  // 2️⃣ Try other possible extensions
  for (const ext of validTypes) {
    if (triedExtensions.has(ext)) continue;
    const url = `${BASE_URL}/files-previews/images/${file._id}.${ext}`;
    try {
      const res = await axios.head(url);
      if (res.status === 200) {
        // ✅ Found valid image — update DB if needed
        if (file.imageType !== ext) {
          file.imageType = ext;
          await file.save();
        }
        return url;
      }
    } catch (err) {
      if (err.response && (err.response.status === 403 || err.response.status === 404)) continue;
      console.error("Unexpected error checking file:", err.message);
    }
  }

  // 3️⃣ Fallback (default to .jpg)
  return `${BASE_URL}/files-previews/images/${file._id}.jpg`;
}


// app.get("/documents", authenticateJWT_user, async (req, res) => {
//   try {
//     const files = await File.find();
//     const categories = await getcategories();

//     const filesWithPreviews = await Promise.all(
//       files.map(async (file) => {
//         const previewUrl = await getValidFileUrl(file, CF_DOMAIN);
//         const pdfUrl = `${CF_DOMAIN}/${file.fileUrl}`;

//         return {
//           ...file.toObject(),
//           previewUrl,
//           pdfUrl,
//         };
//       })
//     );

//     let user = null;
//     if (req.user) {
//       user = await User.findById(req.user._id).select(
//         "profilePicUrl username email"
//       );
//     }

//     res.render("index", {
//       files: filesWithPreviews,
//       categories,
//       isLoggedin: !!req.user,
//       profileUrl: user?.profilePicUrl || null,
//       username: user?.username || null,
//       useremail: user?.email || null,
//     });
//   } catch (err) {
//     console.error("DB fetch error:", err);
//     res.status(500).send("Failed to load files");
//   }
// });

// This route now ONLY sends the page template.
// This is your existing page-loading route. It is correct and does not need changes.
app.get("/documents", authenticateJWT_user, async (req, res) => {
  try {
    // We still get categories for the filter modal.
    const categories = await getcategories();

    let user = null;
    if (req.user) {
      user = await User.findById(req.user._id).select("profilePicUrl username email");
    }

    // Render the page WITHOUT the 'files' data.
    // The JavaScript on this page will fetch the files from /api/files.
    res.render("index", {
      categories,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
       uId: user?._id || null,
    });
  } catch (err) {
    console.error("Page load error:", err);
    res.status(500).send("Failed to load page");
  }
});


// *** THIS IS THE CORRECTED AND UPDATED API ROUTE ***
app.get('/files', async (req, res) => {
    try {
        // --- 1. PARSE & VALIDATE QUERY PARAMETERS ---
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 12;
        const skip = (page - 1) * limit;

        const search = req.query.search || '';
        const sort = req.query.sort || 'popular';
        const priceFilter = req.query.price || 'all';
        
        let categories = req.query.category || [];
        if (typeof categories === 'string') categories = [categories];
        
        let fileTypes = req.query.fileType || [];
        if (typeof fileTypes === 'string') fileTypes = [fileTypes];

        // --- 2. BUILD ADVANCED DATABASE QUERY ---
        const queryConditions = [];

        if (search) {
            queryConditions.push({
                $or: [
                    { filename: { $regex: search, $options: 'i' } },
                    { filedescription: { $regex: search, $options: 'i' } },
                    { user: { $regex: search, $options: 'i' } }
                ]
            });
        }

        if (priceFilter === 'free') queryConditions.push({ price: 0 });
        else if (priceFilter === 'paid') queryConditions.push({ price: { $gt: 0 } });
        
        if (categories.length > 0) {
            const categoryRegex = categories.map(c => new RegExp(`^${c}$`, 'i'));
            queryConditions.push({ category: { $in: categoryRegex } });
        }

        if (fileTypes.length > 0) {
            const fileTypeRegex = fileTypes.map(t => new RegExp(`^${t}$`, 'i'));
            queryConditions.push({ fileType: { $in: fileTypeRegex } });
        }
        
        const query = queryConditions.length > 0 ? { $and: queryConditions } : {};
        
        // --- 3. BUILD SORT OPTIONS ---
        let sortOptions = {};
        switch (sort) {
            case 'newest': sortOptions = { createdAt: -1 }; break;
            case 'price-asc': sortOptions = { price: 1 }; break;
            case 'price-desc': sortOptions = { price: -1 }; break;
            case 'popular': default: sortOptions = { downloadCount: -1 }; break;
        }

        // --- 4. EXECUTE ALL QUERIES IN PARALLEL ---
        // This is more efficient. We now fetch everything at once.
        const [
            filesFromDB, 
            totalFiles,
            categoryResults,
            fileTypeResults
        ] = await Promise.all([
            File.find(query).sort(sortOptions).skip(skip).limit(limit).lean(),
            File.countDocuments(query),
            // This query now runs every time to ensure filters are always populated
            File.aggregate([
                { $match: { category: { $ne: null, $ne: "" } } },
                { $group: { _id: { $toLower: "$category" }, originalCase: { $first: "$category" } } },
                { $project: { _id: 0, category: "$originalCase" } }
            ]),
            File.distinct('fileType')
        ]);
        
        // --- 5. PROCESS PREVIEW URLS ---
        const filesWithPreviews = await Promise.all(
            filesFromDB.map(async (file) => {
                const previewUrl = await getValidFileUrl(file);
                return { ...file, previewUrl };
            })
        );
        
        // --- 6. SEND FINAL JSON RESPONSE ---
        res.status(200).json({
            files: filesWithPreviews,
            totalFiles,
            totalPages: Math.ceil(totalFiles / limit),
            currentPage: page,
            // This data is now included in EVERY response, fixing the bug
            allCategories: categoryResults.map(c => c.category).sort(), 
            allFileTypes: fileTypeResults.filter(t => t),
        });

    } catch (error) {
        console.error('API Error in /api/files:', error);
        res.status(500).json({ message: "Server error while fetching files." });
    }
});
// ASSUMPTIONS:
// 1. You are using Mongoose/MongoDB.
// 2. The File model has fields: _id, filename, filedescription, category, price, user.

// Your Mongoose model

app.get('/products/related', async (req, res) => {
  const currentFileId = req.query.fileId;

  if (!currentFileId) {
    return res.status(400).json({ message: 'Missing fileId parameter.' });
  }

  try {
    // 1️⃣ Find the source file
    const sourceFile = await File.findById(currentFileId);
    if (!sourceFile) {
      return res.status(404).json({ message: 'Source file not found.' });
    }

    const sourceCategory = sourceFile.category;
    const sourcePrice = sourceFile.price || 0;

    // 2️⃣ Aggregate related documents
    const relatedDocs = await File.aggregate([
      {
        $match: {
          _id: { $ne: sourceFile._id },
          category: { $ne: null },
          price: { $ne: null },
        },
      },
      {
        $addFields: {
          relevanceScore: {
            $add: [
              {
                $cond: {
                  if: { $eq: ["$category", sourceCategory] },
                  then: 40,
                  else: 0,
                },
              },
              {
                $multiply: [
                  30,
                  {
                    $subtract: [
                      1,
                      {
                        $min: [
                          1,
                          {
                            $divide: [
                              { $abs: { $subtract: ["$price", sourcePrice] } },
                              { $max: [sourcePrice, 1] },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            ],
          },
        },
      },
      { $sort: { relevanceScore: -1, downloadCount: -1 } },
      { $limit: 20 },
      {
        $project: {
          _id: 1,
          filename: 1,
          filedescription: 1,
          category: 1,
          price: 1,
          slug: 1,
          user: 1,
          filetype: 1,
          imageType: 1, // ✅ Include existing imageType
          relevanceScore: 1,
        },
      },
    ]);

    // 3️⃣ Add preview URLs (file.imageType already exists)
    const filesWithPreview = await Promise.all(
      relatedDocs.map(async (file) => ({
        ...file,
        previewUrl: await getValidFileUrl(file), // uses imageType if needed
      }))
    );

    // 4️⃣ Send response
    res.json(filesWithPreview);

  } catch (error) {
    console.error('Error fetching related documents:', error);
    res.status(500).json({ message: 'Internal server error while fetching related documents.' });
  }
});
;




// The Most Advanced Suggestions Route
app.get('/suggestions', async (req, res) => {
  const q = req.query.q?.toLowerCase().trim();
  if (!q || q.length < 2) return res.json([]);

  try {
    // Build regex for partial/fuzzy matching
    const regex = new RegExp(q.split(' ').join('.*'), 'i');

    // Build query
    const query = [
      { filename: regex },
      { filedescription: regex },
      { user: regex }
    ];

    // Only add price filter if q is a number
    const priceNum = Number(q);
    if (!isNaN(priceNum)) {
      query.push({ price: priceNum });
    }

    // Find matching documents
    let suggestions = await File.find({ $or: query })
      .limit(20)
      .lean();

    // Simple relevance scoring
    suggestions = suggestions.map(file => {
      let score = 0;
      if (file.filename.toLowerCase().includes(q)) score += 10;
      if (file.filedescription.toLowerCase().includes(q)) score += 5;
      if (file.user.toLowerCase().includes(q)) score += 3;
      if (!isNaN(priceNum) && file.price === priceNum) score += 7;
      return { ...file, score };
    });

    // Sort by score descending, then price ascending
    suggestions.sort((a, b) => b.score - a.score || a.price - b.price);

    // Take top 10
    suggestions = suggestions.slice(0, 10);

    // Enrich with preview URLs
    const enriched = await Promise.all(
      suggestions.map(async file => {
        const previewUrl = await getValidFileUrl(file);
        return { ...file, previewUrl };
      })
    );
 console.log("suggestions fetched")
    res.json(enriched);
  } catch (err) {
    console.error("Suggestion API Error:", err);
    res.status(500).json({ message: "Server error fetching suggestions." });
  }
});



// Checkout route
app.get("/checkout", authenticateJWT_user, requireAuth, async (req, res) => {
  try {
    const { fileId, couponCode } = req.query;

    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).send("File with id not found");
    }

    // Apply coupon if present
    let discountPercent = 0;
    if (couponCode) {
      const coupon = await Coupon.findOne({
        code: couponCode.toUpperCase(),
        file: fileId,
      });

      if (coupon) {
        if (coupon.expiry && coupon.expiry < new Date()) {
          // expired
          discountPercent = 0;
        } else {
          discountPercent = coupon.discountValue;
        }
      }
    }

    // Generate price breakdown
    const priceDetails = GenCheckOutPrice(file.price, { discountPercent });

    // Render checkout with all price info
    res.render("checkout", {
      razorpayKey: process.env.RAZORPAY_KEY_ID,
      file,
      priceDetails,
      couponCode: couponCode || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Coupon check API
app.get("/check/coupon", async (req, res) => {
  try {
    const { couponCode, fileId } = req.query;

    if (!couponCode || !fileId) {
      return res
        .status(400)
        .json({ error: "Coupon code and fileId are required" });
    }

    const coupon = await Coupon.findOne({
      code: couponCode.toUpperCase(),
      file: fileId,
    });

    if (!coupon) {
      return res.json({ valid: false, message: "Invalid coupon" });
    }

    if (coupon.expiry && coupon.expiry < new Date()) {
      return res.json({ valid: false, message: "Coupon expired" });
    }

    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    const priceDetails = GenCheckOutPrice(file.price, {
      discountPercent: coupon.discountValue,
    });

    res.json({ valid: true, priceDetails });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Price generator
function GenCheckOutPrice(price, options = {}) {
  const { discountPercent = 0, shippingFee = 0, rounding = "ceil" } = options;

  // Safe discount
  const safeDiscount = Math.min(Math.max(discountPercent, 0), 90);

  // Step 1: Apply coupon
  const discountedPrice = +(price * (1 - safeDiscount / 100)).toFixed(2);

  // Step 2: Tiered service fee
  let serviceFeeRate = 0.02;
  if (discountedPrice < 100) serviceFeeRate = 0.05;
  else if (discountedPrice > 500) serviceFeeRate = 0.015;
  const serviceFee = +(discountedPrice * serviceFeeRate).toFixed(2);

  // Step 3: Taxes
  const rawTax = serviceFee * 0.18;
  const luxuryTax = discountedPrice > 1000 ? discountedPrice * 0.05 : 0;

  const round = (num) => {
    if (rounding === "ceil") return Math.ceil(num * 100) / 100;
    if (rounding === "floor") return Math.floor(num * 100) / 100;
    return +num.toFixed(2);
  };

  const gstTax = round(rawTax);
  const luxuryTaxRounded = round(luxuryTax);

  // Step 4: Final total
  const total = +(
    discountedPrice +
    serviceFee +
    gstTax +
    luxuryTaxRounded +
    shippingFee
  ).toFixed(2);

  return {
    originalPrice: price,
    discountedPrice,
    discountPercent: safeDiscount,
    serviceFee,
    gstTax,
    luxuryTax: luxuryTaxRounded,
    shippingFee,
    total,
  };
}

/* Output example:
{
  originalPrice: 350,
  discountedPrice: 280,
  discountPercent: 20,
  serviceFee: 5.6,
  gstTax: 1.01,
  luxuryTax: 0,
  shippingFee: 15,
  total: 301.61
}
*/

app.get("/help/user/vidyari-guid",(req,res)=>{
  res.render("help.ejs");
})
app.get("/help/user/dashboard",(req,res)=>{
  res.render("dashboardhelp.ejs")
})
app.get(
  "/transactions",
  authenticateJWT_user,
  requireAuth,
  async (req, res) => {
    try {
      // Fetch data from MongoDB for a specific user, for example
      // The .lean() method is used for performance, as we only need plain JS objects
      const purchases = await Userpurchases.find({
        userId: req.user._id,
      }).lean();

      // Add mock productDetails for the example to work
      // In a real app, you would use Mongoose's .populate() method
      const processedPurchases = purchases.map((p) => {
        // Safely get the first 3 letters of productName, or use 'N/A' as a fallback
        const placeholderText = p.productName?.substring(0, 3) ?? "N/A";

        return {
          ...p,
          productDetails: {
            // This data would come from populating the 'productId'
            category: "Software",
            imageUrl: `https://placehold.co/120x120/6366f1/ffffff?text=${placeholderText}`,
          },
        };
      });
      let user = null;

      if (req.user) {
        const userId = req.user._id;
        // Fetch only the necessary fields
        user = await User.findById(userId).select(
          "profilePicUrl username email"
        );
        if (user) {
          console.log("User profile pic URL:", user.profilePicUrl);
        }
      }

      // Render the EJS template and pass the 'purchases' data to it
      res.render("perchasehistory", {
        purchases: processedPurchases,
        isLoggedin: !!req.user,
        profileUrl: user?.profilePicUrl || null,
        username: user?.username || null,
        useremail: user?.email || null,
         uId: user?._id || null,
      });
    } catch (error) {
      console.error("Error fetching purchase history:", error);
      res.status(500).send("Error loading page.");
    }
  }
);
// Helper to cleanly return MIME type
function getMimeType(extension) {
  switch (extension) {
    case ".pdf":
      return "application/pdf";
    case ".docx":
      return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    case ".pptx":
      return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    case ".zip":
      return "application/zip";
    case ".jpg":
      return "image/jpg";
    case ".png":
      return "image/png";
    default:
      return "application/octet-stream";
  }
}


app.use((req, res) => {
  res.status(404).render("404");
});
app.use((err, req, res, next) => {
  // 1. Log the error to your console for debugging
  console.error("==================== SERVER ERROR ====================");
  console.error(err.stack);
  console.error("======================================================");

  // 2. Send the 500 status code and render your new error page
  res.status(500).render("500");
});
// Error handling middleware
