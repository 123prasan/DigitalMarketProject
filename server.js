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
const http = require('http');
const NodeCache = require("node-cache");
// const logVisitorMiddleware = require("./middlewares/ipmiddleware");
const categories = require("./models/categories"); // Assuming categories.js exports a Mongoose model
const { createClient } = require("@supabase/supabase-js");
const Location = require("./models/userlocation"); // Assuming Location.js exports a Mongoose model
const chatRoutes = require("./routes/chat.js");
const File = require("./models/file");
const courseRoutes = require("./routes/courseroutes");
const progressRoutes = require("./routes/progressroutes");
const adminRoutes = require("./routes/adminRoutes");
const authenticateJWT_user = require("./routes/authentication/jwtAuth.js");
const User = require("./models/userData");
const UserDownloads = require("./models/userDownloads.js");
const Userpurchases = require("./models/userPerchase.js");
const requireAuth = require("./routes/authentication/reaquireAuth.js");
const Usernotifications = require("./models/userNotifications");
const CF_DOMAIN = "https://d3tonh6o5ach9f.cloudfront.net"; // e.g., https://d123abcd.cloudfront.net
const Usertransaction = require("./models/userTransactions.js");
const UserChats = require('./testings4.js'); // <-- IMPORT THE NEW ROUTER
const Coupon = require("./models/couponschema.js");
const WebSocket = require('ws');
const admin = require('firebase-admin');
const UserMessage = require('./models/UserMessage.js');
const userbal = require("./models/userBalance.js");
const pushNotificationroute = require('./pushNotification.js');
const serviceAccount = require('./serviceAccountKey.json');
const sendNotification = require("./test.js")
const Course = require("./models/course.js")
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const app = express();
app.use(cookieParser());

app.use("/", UserChats);
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
console.log("Mongo URI:", process.env.MONGODB_URI);


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
// apply JWT authentication to all admin API routes so req.user is populated
// and unauthorized calls respond with JSON instead of HTML
app.use("/api/admin", authenticateJWT, adminRoutes);
const apiRoutes = require('./routes/Adanalytics.js');

app.use('/api/creator', apiRoutes);
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
app.use(pushNotificationroute);
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

// Ensure DNS can resolve SRV records (some networks/VPNs block them)
require('dns').setServers(['1.1.1.1','8.8.8.8']);

// Connect to MongoDB with enhanced error handling
mongoose
  .connect(process.env.MONGODB_URI, {
    family:4,
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    retryWrites: true,
  })
  .then(() => {
    console.log("\n✅ MongoDB connected successfully!");
    console.log(`📊 Database: ${mongoose.connection.name}`);
    console.log(`🔗 Host: ${mongoose.connection.host}\n`);
  })
  .catch((err) => {
    console.error("\n❌ MongoDB connection error:");
    console.error(`Error Code: ${err.code}`);
    console.error(`Message: ${err.message}\n`);
    console.error("📋 TROUBLESHOOTING GUIDE:");
    console.error("1. Check MONGODB_URI in .env file");
    console.error("2. Verify MongoDB Atlas cluster is running (not paused)");
    console.error("3. Add your IP to Network Access in MongoDB Atlas");
    console.error("4. Check database user credentials");
    console.error("5. See MONGODB_TROUBLESHOOTING.txt for detailed steps\n");
    console.error("Full error:", err);
    // Don't exit - allow app to start but warn user
    console.warn("\n⚠️  Starting server WITHOUT database connection...\n");
  });

// Middlewares
require("./routes/bots/cleanUpAcc.js");
require("./routes/bots/cleanUpsub.js")
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

// Razorpay configuration
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Supabase client setup
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Middleware for JWT authentication
function authenticateJWT(req, res, next) {
  const token = req.cookies.jwt; // Get token from HTTP-only cookie
  const isApi = req.originalUrl && req.originalUrl.startsWith('/api/');

  if (!token) {
    if (isApi) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    // No token provided, redirect to login
    return res.render('login', { error: 'Access denied. Please log in.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // Token is invalid or expired, clear the cookie
      res.clearCookie('jwt');
      if (isApi) {
        return res.status(401).json({ message: 'Session expired or invalid. Please log in again.' });
      }
      return res.render('login', {
        error: 'Session expired or invalid. Please log in again.',
      });
    }
    // Token is valid, attach user payload to request
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
app.get("/files/impression/:id/:impression", authenticateJWT_user, requireAuth, async (req, res) => {
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
app.post("/create-order", authenticateJWT_user,requireAuth,async (req, res) => {
  // console.log("data",req.user)
  console.log("-----------------------------")
  try {
    const { fileId, filename, price } = req.body;

    if (!fileId || !filename || !price || isNaN(price)) {
      return res
        .status(400)
        .json({ error: "Missing or invalid fileId, filename, or price" });
    }
    const amountInPaisa = Math.round(price * 100); // Razorpay expects amount in smallest currency unit (paisa)
    
    // Generate receipt - must be 40 chars or less
    const receipt = `${fileId.toString().slice(-8)}_${Date.now().toString().slice(-6)}`;
    
    const orderOptions = {
      amount: amountInPaisa,
      currency: "INR",
      receipt: receipt,
      notes: {
        fileId: fileId,
        filename: filename,
        userId: req.user._id.toString(),
        userEmail: req.user.email
      }
    };

    const response = await razorpayInstance.orders.create(orderOptions);

    res.json({
      success: true,
      order_id: response.id,
      amount: amountInPaisa,
      currency: "INR",
      key: process.env.RAZORPAY_KEY_ID
    });
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
app.get("/terms&conditions", (req, res) => {
  res.render("terms&conditions");
});
app.get("/refundpolicy", (req, res) => {
  res.render("refundpolicy");
});
app.get("/payment-terms", (req, res) => {
  res.render("payment-terms");
});
app.get("/contact", (req, res) => {
  res.render("contact");
});
app.get("/disclaimer", (req, res) => {
  res.render("disclaimer");
});
app.get("/acceptable-use", (req, res) => {
  res.render("acceptable-use");
});
app.get("/intellectual-property", (req, res) => {
  res.render("intellectual-property");
});
app.get("/return-cancellation", (req, res) => {
  res.render("return-cancellation");
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
    console.log("incomplete payment details")
    return res.status(400).json({
      success: false,
      message: "Incomplete payment details",
    });
  }

  try {
    // Verify Razorpay signature
    const crypto = require('crypto');
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      console.log("Signature verification failed")
      return res.status(400).json({
        success: false,
        message: "Payment signature verification failed",
      });
    }

    // Fetch payment details from Razorpay
    let paymentDetails;
    try {
      paymentDetails = await razorpayInstance.payments.fetch(razorpay_payment_id);
      console.log(paymentDetails.status)
    } catch (err) {
      console.error("Razorpay fetch failed:", err);
      return res.status(502).json({
        success: false,
        message: "Payment gateway error",
      });
    }

    // Check if payment is successful
    if (paymentDetails.status !== 'captured') {
      console.log("Payment is not captured")
      return res.status(400).json({
        success: false,
        message: "Payment not completed",
      });
    }

    // Fetch file and Creator (User)
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ success: false, message: "File not found" });
    }
    
    // Fetch the creator to check Pro status
    const creator = await User.findById(file.userId);
    if (!creator) {
      return res.status(404).json({ success: false, message: "Creator not found" });
    }

    // --- VIDYARI PRO LOGIC STARTS HERE ---
    
    // 1. Determine base split based on Pro status (10% vs 30% fee)
    const platformFeePercentage = creator.isPro ? 0.10 : 0.30;
    let platformCut = totalprice * platformFeePercentage;
    let sellerShare = totalprice - platformCut;

    let subscriptionFeeDeducted = 0; // Track this for admin records if needed

    // 2. Handle "Pay via Wallet" Pending Fees
    if (creator.isPro && creator.pendingSubscriptionFee > 0) {
        if (sellerShare >= creator.pendingSubscriptionFee) {
            // Seller made enough to clear the whole debt
            subscriptionFeeDeducted = creator.pendingSubscriptionFee;
            sellerShare -= creator.pendingSubscriptionFee;
            platformCut += creator.pendingSubscriptionFee; // Admin keeps the sub fee
            creator.pendingSubscriptionFee = 0; // Debt cleared
        } else {
            // Seller didn't make enough, take all earnings toward debt
            subscriptionFeeDeducted = sellerShare;
            creator.pendingSubscriptionFee -= sellerShare;
            platformCut += sellerShare; // Admin takes what they made
            sellerShare = 0; // Seller gets 0 this time
        }
        
        // Save the creator's updated pending fee
        await creator.save(); 
    }
    // --- VIDYARI PRO LOGIC ENDS HERE ---


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
          totalAmount: sellerShare, // Now uses the dynamically calculated share
          ProductName: file.filename,
          purchaserId: req.user._id,
          transactionId: razorpay_payment_id,
          discount,
        },
        { upsert: true, new: true }
      ),

      // Seller balance update
      userbal.findOneAndUpdate(
        { UserId: file.userId },
        { $inc: { Balance: sellerShare } }, // Add calculated share to their balance
        { upsert: true, new: true }
      ),

      // Admin balance update
      Adminbal.findOneAndUpdate(
        {},
        { $inc: { totalAmount: platformCut, cutOffbal: sellerShare } }, // Now accurately tracks admin revenue
        { upsert: true, new: true }
      ),

      // Order record
      Order.findOneAndUpdate(
        { orderId: razorpay_order_id },
        {
          orderId: razorpay_order_id,
          transactionId: razorpay_payment_id,
          customer: paymentDetails.email || "Online Customer",
          payment: paymentDetails.method || "Online Payment",
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
      
      // Determine what to tell the creator
      let sellerMessage = `🤑 You Earned Amount of ₹ ${sellerShare.toFixed(2)}`;
      if (subscriptionFeeDeducted > 0) {
          sellerMessage += ` (₹${subscriptionFeeDeducted.toFixed(2)} automatically applied to your Pro Subscription fee).`;
      }

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
          body: sellerMessage, // Send the dynamic message regarding their earnings/debt
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


// Razorpay Webhook - No auth needed (public)
app.post("/webhook", (req, res) => {
  try {
    const crypto = require('crypto');
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    const signature = req.headers['x-razorpay-signature'];
    
    if (!signature) {
      return res.status(400).json({ error: 'Missing signature' });
    }

    // Verify webhook signature
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(JSON.stringify(req.body))
      .digest('base64');

    if (signature !== expectedSignature) {
      return res.status(400).json({ error: 'Invalid signature' });
    }

    const eventData = req.body;
    
    // Handle different webhook events
    if (eventData.event === 'payment.captured') {
      // Payment was captured/successful
      console.log('Payment captured:', eventData.payload.payment.entity);
      // You can add additional processing here if needed
    } else if (eventData.event === 'payment.failed') {
      // Payment failed
      console.log('Payment failed:', eventData.payload.payment.entity);
      // You can add additional processing here if needed
    }

    res.status(200).json({ status: 'ok' });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
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
app.get("/pricing",authenticateJWT_user,async(req,res)=>{
  let profileUrl = null;
 let user = null;
    if (req.user) {
      const cacheKey = `user_${req.user._id}`;
      const cachedUser = pageCache.get(cacheKey);

      if (cachedUser) {
        user = cachedUser;
        profileUrl = cachedUser.profilePicUrl;
      } else {
        // Fetch minimal data for rendering
        user = await User.findById(req.user._id).select("profilePicUrl username email").lean();
        if (user) {
          // Convert to CloudFront if S3-based
          if (user.profilePicUrl?.includes("s3.")) {
            try {
              const fileName = user.profilePicUrl.split("/").pop();
              user.profilePicUrl = `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
            } catch (err) {
              console.warn("⚠️ Profile URL conversion failed:", err.message);
            }
          }

          // Cache for future requests
          pageCache.set(cacheKey, user);
          profileUrl = user.profilePicUrl;
        }
      }
    }

    // 🧠 Step 3: Cache auto-refresh if popular (extend TTL when hit frequently)
    if (req.user) {
      const cacheKey = `user_${req.user._id}`;
      const ttl = pageCache.getTtl(cacheKey);
      if (ttl && ttl - Date.now() < 3 * 60 * 1000) {
        pageCache.ttl(cacheKey, 15 * 60); // extend 15 min if hot
      }
    }

  res.render("pricing",{
    isLoggedin: !!req.user,
      profileUrl,
      username: user?.username || null,
      useremail: user?.email || null,
      uId: user?._id?.toString() || null,
  })
})
app.get("/About",authenticateJWT_user,async(req,res)=>{
  let profileUrl = null;
 let user = null;
    if (req.user) {
      const cacheKey = `user_${req.user._id}`;
      const cachedUser = pageCache.get(cacheKey);

      if (cachedUser) {
        user = cachedUser;
        profileUrl = cachedUser.profilePicUrl;
      } else {
        // Fetch minimal data for rendering
        user = await User.findById(req.user._id).select("profilePicUrl username email").lean();
        if (user) {
          // Convert to CloudFront if S3-based
          if (user.profilePicUrl?.includes("s3.")) {
            try {
              const fileName = user.profilePicUrl.split("/").pop();
              user.profilePicUrl = `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
            } catch (err) {
              console.warn("⚠️ Profile URL conversion failed:", err.message);
            }
          }

          // Cache for future requests
          pageCache.set(cacheKey, user);
          profileUrl = user.profilePicUrl;
        }
      }
    }

    // 🧠 Step 3: Cache auto-refresh if popular (extend TTL when hit frequently)
    if (req.user) {
      const cacheKey = `user_${req.user._id}`;
      const ttl = pageCache.getTtl(cacheKey);
      if (ttl && ttl - Date.now() < 3 * 60 * 1000) {
        pageCache.ttl(cacheKey, 15 * 60); // extend 15 min if hot
      }
    }

  res.render("about",{
    isLoggedin: !!req.user,
      profileUrl,
      username: user?.username || null,
      useremail: user?.email || null,
      uId: user?._id?.toString() || null,
  })
})
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
      res.clearCookie("jwt", { domain: ".vidyari.com" });
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
    // specify domain to cover both vidyari.com and www.vidyari.com
    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      sameSite: "Lax",
      domain: ".vidyari.com",
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
  res.clearCookie("jwt", { domain: ".vidyari.com" }); // Clear the JWT cookie from the browser
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
            // Construct the S3 key (avoid double-prefixing if already present)
            const key = file.fileUrl && String(file.fileUrl).startsWith('main-files/')
              ? file.fileUrl
              : `main-files/${file.fileUrl}`; // adapt if your file structure is different

        // Generate pre-signed URL (valid for 5 minutes)
        const downloadUrl = s3.getSignedUrl("getObject", {
          Bucket: "vidyarimain2",
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

  const categories = await getcategories(); // Fetch categories
  const allAddresses = await fetchaddress(); // Fetch last 100 addresses
  
  // Fetch all users and their statistics
  const allUsers = await User.find({}).sort({ createdAt: -1 });
  const verifiedUsers = allUsers.filter(u => u.ISVERIFIED).length;
  const suspendedUsers = allUsers.filter(u => u.isSuspended).length;
  const bannedUsers = allUsers.filter(u => u.isBanned).length;
  
  res.render("admin", {
    // include the authenticated admin's username for display in the header
    username: req.user?.username || "Admin",
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
    // Users data
    allUsers,
    verifiedUsers,
    suspendedUsers,
    bannedUsers,
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
  const { fileId, filename, filedescription, price, couponCode } = req.body;
  
  try {
    const updatedFile = await File.findByIdAndUpdate(fileId, {
      filename,
      filedescription,
      price,
    }, { new: true });

    if (!updatedFile) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    // manage coupon association
    if (couponCode && couponCode.trim() !== '') {
      let coupon = await Coupon.findOne({ file: fileId });
      if (coupon) {
        coupon.code = couponCode.trim();
        await coupon.save();
      } else {
        // assign default owner for coupon as well
        const defaultUser = await User.findOne({ email: 'vidyari.inc@gmail.com' });
        const userIdForCoupon = defaultUser ? defaultUser._id : (req.user && req.user._id);
        await Coupon.create({
          userId: userIdForCoupon,
          file: fileId,
          code: couponCode.trim(),
          discountValue: 0,
        });
      }
    } else {
      // remove coupon if empty
      await Coupon.deleteOne({ file: fileId });
    }
    
    // Always return JSON for consistency
    res.json({ success: true, message: 'File updated successfully', file: updatedFile });
  } catch (error) {
    console.error('Edit file error:', error);
    res.status(500).json({ success: false, error: 'Could not update file' });
  }
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
    try {
      const { filename, filedescription, price, category } = req.body;
      const pdfFile = req.files["file"]?.[0];
      const imageFile = req.files["previewImage"]?.[0];
      if (!pdfFile || !imageFile)
        return res.status(400).send("PDF and image are required");

    // 1. Upload PDF to AWS S3 (vidyarimain2 bucket)
    const pdfS3Key = `main-files/${Date.now()}_${pdfFile.originalname}`;
    await s3.putObject({
      Bucket: 'vidyarimain2',
      Key: pdfS3Key,
      Body: pdfFile.buffer,
      ContentType: pdfFile.mimetype,
    }).promise();

    // 3. Save metadata in MongoDB, including file size
    // (We'll upload preview after, using the generated MongoDB _id)
    // determine owner (req.user may be admin, fallback to vidyari.inc user)
    let ownerUser = null;
    if (req.user && req.user._id) {
      ownerUser = await User.findById(req.user._id);
    }
    if (!ownerUser) {
      ownerUser = await User.findOne({ email: 'vidyari.inc@gmail.com' });
    }
    const ownerId = ownerUser ? ownerUser._id : null;
    const ownerName = ownerUser ? ownerUser.username : 'Admin';

    const newFile = await File.create({
      userId: ownerId,
      filename: filename || 'Untitled',
      filedescription,
      price: price || 0,
      category: category || 'Uncategorized',
      fileUrl: pdfS3Key,
      uploadedAt: new Date(),
      user: ownerName,
      fileSize: pdfFile.size,
      imageType: 'jpg',
    });

    // 2. Upload preview image to AWS S3 using the generated MongoDB _id
    const previewS3Key = `files-previews/images/${newFile._id}.jpg`;
    await s3.putObject({
      Bucket: 'vidyari3',
      Key: previewS3Key,
      Body: imageFile.buffer,
      ContentType: imageFile.mimetype,
    }).promise();
    //notification update
    const newMessage = new Message({
      message: `New file uploaded: ${filename} by ${req.user ? req.user.username : "Admin"}`,
    });
    await newMessage.save();

    res.redirect("/admin?fileUploaded=1");
    } catch (err) {
      console.error('File upload error:', err);
      res.status(500).send(`Upload failed: ${err.message}`);
    }
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

// import axios from "axios";

// Optional in-memory cache to avoid repeated checks
// const fileUrlCache = new Map();

/**
 * Get the valid image URL served via CloudFront (optimized for cost and speed)
 * @param {Object} file - File object from your DB
 * @param {string} CLOUDFRONT_DOMAIN - Your CloudFront domain (e.g. dxxxx.cloudfront.net)
 * @param {Array<string>} validTypes - Allowed file extensions
 */
// Global file preview cache (10 min TTL)
const previewfileUrlCache = new NodeCache({
  stdTTL: 600,
  checkperiod: 180,
  useClones: false,
});

// Reusable axios instance (connection pooling)
const previewhttp = axios.create({
  timeout: 1500,
  validateStatus: s => s < 500,
  decompress: true,
});

async function getValidFileUrl(
  file,
  CLOUDFRONT_DOMAIN = "d3epchi0htsp3c.cloudfront.net",
  validTypes = ["jpg", "jpeg", "png", "webp"]
) {

  try {
    const cacheKey = String(file._id);

    // ✅ Step 1: Return from memory cache instantly if available
    const cached = previewfileUrlCache.get(cacheKey);
    if (cached) return cached;

    const BASE_URL = `https://${CLOUDFRONT_DOMAIN}/files-previews/images`;

    // ✅ Step 2: Use known type directly if present
    if (file.imageType && validTypes.includes(file.imageType)) {
      const url = `${BASE_URL}/${file._id}.${file.imageType}`;
      previewfileUrlCache.set(cacheKey, url);
      return url;
    }

    // ✅ Step 3: Try all formats in parallel (fastest response wins)
    const urls = validTypes.map(ext => `${BASE_URL}/${file._id}.${ext}`);
    let foundUrl = null;

    await Promise.any(
      urls.map(async (url, i) => {
        try {
          const res = await previewhttp.head(url);
          if (res.status === 200 && !foundUrl) {
            foundUrl = url;
            file.imageType = validTypes[i];
          }
        } catch {
          /* ignore */
        }
      })
    ).catch(() => { }); // ignore Promise.any rejection

    // ✅ Step 4: If found, cache + async DB update (non-blocking)
    if (foundUrl) {
      previewfileUrlCache.set(cacheKey, foundUrl);
      process.nextTick(() => {
        File.updateOne(
          { _id: file._id },
          { $set: { imageType: file.imageType } }
        ).catch(() => { });
      });
      return foundUrl;
    }

    // ✅ Step 5: Fallback (CloudFront caches this anyway)
    const fallbackUrl = `${BASE_URL}/${file._id}.jpg`;
    previewfileUrlCache.set(cacheKey, fallbackUrl);
    return fallbackUrl;
  } catch (err) {
    console.error("getValidFileUrl error:", err.message);
    return `https://${CLOUDFRONT_DOMAIN}/files-previews/images/${file._id}.jpg`;
  }
}



// import NodeCache from "node-cache";
const userCache = new NodeCache({ stdTTL: 600, checkperiod: 120 }); // 10 min cache
// const CLOUDFRONT_AVATAR_URL = "https://previewfiles.vidyari.com/avatars";


// ======================================================
// ✅ Advanced Optimized File Details Route
// ======================================================
app.get("/file/:slug/:id", authenticateJWT_user, async (req, res) => {
  try {
    // 🧩 Validate Mongo ID format
    if (req.params.id.length !== 24) {
      return res.render("file-not-found");
    }

    // 📄 Fetch file
    const file = await File.findById(req.params.id);
    if (!file) {
      return res.status(404).render("404", { message: "File not found" });
    }

    // 🔄 Redirect to canonical slug
    if (file.slug !== req.params.slug) {
      return res.redirect(301, `/file/${file.slug}/${file._id}`);
    }

    // 👤 Seller info (cached)
    let sellerprofilepic = "/images/avatar.jpg";
    let ISVERIFIED = false;

    if (file.userId) {
      const sellerCacheKey = `seller_${file.userId}`;
      let seller = userCache.get(sellerCacheKey);

      if (!seller) {
        seller = await User.findById(file.userId).select("profilePicUrl ISVERIFIED").lean();
        if (seller) userCache.set(sellerCacheKey, seller);
      }

      if (seller?.profilePicUrl) {
        // Convert S3 → CloudFront
        if (seller.profilePicUrl.includes("s3.")) {
          const fileName = seller.profilePicUrl.split("/").pop();
          sellerprofilepic = `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
        } else {
          sellerprofilepic = seller.profilePicUrl;
        }
      }

      ISVERIFIED = seller?.ISVERIFIED || false;
    }

    // 📄 Get file preview and download URLs
    const previewUrl = await getValidFileUrl(file);
    const pdfUrl = `d3epchi0htsp3c.cloudfront.net/${file.fileUrl}`;

    // 👥 Logged-in viewer info (cached)
    let user = null;
    let profileUrl = "/images/avatar.jpg";

    if (req.user) {
      const viewerCacheKey = `user_${req.user._id}`;
      user = userCache.get(viewerCacheKey);

      if (!user) {
        user = await User.findById(req.user._id)
          .select("profilePicUrl username email")
          .lean();

        if (user) userCache.set(viewerCacheKey, user);
      }

      // Convert S3 → CloudFront
      if (user?.profilePicUrl?.includes("s3.")) {
        const fileName = user.profilePicUrl.split("/").pop();
        profileUrl = `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
      } else if (user?.profilePicUrl) {
        profileUrl = user.profilePicUrl;
      }
    }

    // 🧠 Extend cache for active users
    const extendTTL = (key) => {
      const ttl = userCache.getTtl(key);
      if (ttl && ttl - Date.now() < 3 * 60 * 1000) {
        userCache.ttl(key, 15 * 60);
      }
    };
    if (req.user) extendTTL(`user_${req.user._id}`);
    if (file.userId) extendTTL(`seller_${file.userId}`);

    // Prepare price details for checkout display
    const priceDetails = GenCheckOutPrice(Number(file.price) || 0);

    // 🎨 Render final optimized view
    res.render("file-details", {
      file,
      sellerprofilepic,
      ISVERIFIED,
      cashfreeAppId: process.env.CASHFREE_APP_ID,
      previewUrl,
      pdfUrl,
      isLoggedin: !!req.user,
      profileUrl,
      username: user?.username || null,
      useremail: user?.email || null,
      uId: user?._id || null,
      priceDetails,
    });
  } catch (error) {
    console.error("⚠️ Error fetching file:", error);
    res.status(500).send("Server error");
  }
});



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

    // Construct S3 keys using DB values (fallback to request body if necessary)
    const mainKeyFromDb = file.fileUrl
      ? (String(file.fileUrl).startsWith('main-files/') ? file.fileUrl : `main-files/${file.fileUrl}`)
      : null;
    const mainKeyFromReq = fileUrl
      ? (String(fileUrl).startsWith('main-files/') ? fileUrl : `main-files/${fileUrl}`)
      : null;
    const mainFileKey = mainKeyFromDb || mainKeyFromReq;

    // Delete main file from vidyari-main if key available
    if (mainFileKey) {
      try {
        await s3.deleteObject({ Bucket: "vidyarimain2", Key: mainFileKey }).promise();
        console.log(`✅ Deleted main file from S3: ${mainFileKey}`);
      } catch (delErr) {
        console.error(`❌ Error deleting main file ${mainFileKey}:`, delErr.message || delErr);
      }
    } else {
      console.warn('⚠️ No main file key available for deletion');
    }

    // Delete preview image(s) from vidyari3
    // Try with stored imageType first, then fallback to common formats
    const imageFormats = ['jpg', 'jpeg', 'png', 'webp', 'gif'];
    const storedType = file.imageType ? file.imageType.toLowerCase().replace('.', '') : null;
    
    // Reorder to try stored type first
    const formatsToTry = storedType && imageFormats.includes(storedType)
      ? [storedType, ...imageFormats.filter(f => f !== storedType)]
      : imageFormats;

    let deletedPreview = false;
    for (const ext of formatsToTry) {
      const previewKey = `files-previews/images/${file._id}.${ext}`;
      try {
        const result = await s3.deleteObject({ Bucket: "vidyari3", Key: previewKey }).promise();
        console.log(`✅ Deleted preview image from S3: ${previewKey}`);
        deletedPreview = true;
        break; // Stop after first successful deletion
      } catch (delErr) {
        console.error(`⚠️ Could not delete ${previewKey}:`, delErr.message || delErr);
      }
    }

    if (!deletedPreview) {
      console.warn(`⚠️ Could not delete any preview image format for ${file._id}`);
    }

    // Delete MongoDB record
    await File.deleteOne({ _id: fileId });
    console.log(`✅ File record deleted from MongoDB: ${fileId}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ Delete error:', err);
    res.json({ success: false, message: "Server error" });
  }
});
//user-notifications

// ====================================================================
// 🔍 SEO ROUTES - Sitemap & Schema Generation
// ====================================================================

// Generate main XML sitemap
app.get("/sitemap.xml", async (req, res) => {
  try {
    const baseUrl = "https://vidyari.com";
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n';

    // Static pages with high priority
    const staticPages = [
      { url: "/", priority: "1.0", changefreq: "daily" },
      { url: "/courses", priority: "0.9", changefreq: "daily" },
      { url: "/pricing", priority: "0.8", changefreq: "weekly" },
      { url: "/About", priority: "0.7", changefreq: "monthly" },
      { url: "/contact", priority: "0.7", changefreq: "monthly" },
      { url: "/privacy-policy", priority: "0.5", changefreq: "yearly" },
      { url: "/terms-and-conditions", priority: "0.5", changefreq: "yearly" },
    ];

    staticPages.forEach((page) => {
      xml += `  <url>\n    <loc>${baseUrl}${page.url}</loc>\n    <changefreq>${page.changefreq}</changefreq>\n    <priority>${page.priority}</priority>\n  </url>\n`;
    });

    xml += "</urlset>";

    res.header("Content-Type", "application/xml");
    res.send(xml);
  } catch (err) {
    console.error("Sitemap error:", err);
    res.status(500).send("Error generating sitemap");
  }
});

// Generate files sitemap (top 5000 files)
app.get("/sitemap-files.xml", async (req, res) => {
  try {
    const baseUrl = "https://vidyari.com";
    const files = await File.find().select("slug _id uploadedAt downloadCount").limit(5000).sort({ downloadCount: -1 }).lean();

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    files.forEach((file) => {
      const priority = file.downloadCount > 100 ? "0.8" : file.downloadCount > 50 ? "0.7" : "0.6";
      const lastmod = file.uploadedAt ? new Date(file.uploadedAt).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];

      xml += `  <url>\n    <loc>${baseUrl}/file/${file.slug}/${file._id}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <priority>${priority}</priority>\n  </url>\n`;
    });

    xml += "</urlset>";

    res.header("Content-Type", "application/xml");
    res.send(xml);
  } catch (err) {
    console.error("Files sitemap error:", err);
    res.status(500).send("Error generating files sitemap");
  }
});

// Generate courses sitemap
app.get("/sitemap-courses.xml", async (req, res) => {
  try {
    const baseUrl = "https://vidyari.com";
    const courses = await Course.find().select("slug _id createdAt").limit(2000).sort({ createdAt: -1 }).lean();

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    courses.forEach((course) => {
      const lastmod = course.createdAt ? new Date(course.createdAt).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];
      xml += `  <url>\n    <loc>${baseUrl}/course/${course.slug}/${course._id}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <priority>0.7</priority>\n  </url>\n`;
    });

    xml += "</urlset>";

    res.header("Content-Type", "application/xml");
    res.send(xml);
  } catch (err) {
    console.error("Courses sitemap error:", err);
    res.status(500).send("Error generating courses sitemap");
  }
});

// Robots.txt route (also serve from public folder)
app.get("/robots.txt", (req, res) => {
  res.header("Content-Type", "text/plain");
  const robotsContent = `# Robots.txt for Vidyari - Peer Learning Platform
User-agent: *
Allow: /
Allow: /file/
Allow: /courses
Allow: /profile/
Allow: /pricing
Allow: /About
Allow: /contact
Allow: /privacy-policy
Allow: /terms-and-conditions
Allow: /refund-policy

Disallow: /admin
Disallow: /admin-login
Disallow: /api/
Disallow: /checkout
Disallow: /download
Disallow: /*?*sort=
Disallow: /*?*filter=

Crawl-delay: 1
User-agent: Googlebot
Crawl-delay: 0

Sitemap: https://vidyari.com/sitemap.xml
Sitemap: https://vidyari.com/sitemap-files.xml
Sitemap: https://vidyari.com/sitemap-courses.xml
`;
  res.send(robotsContent);
});

// JSON-LD for Organization (global schema)
app.get("/schema/organization.json", (req, res) => {
  const schema = {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Vidyari",
    "url": "https://vidyari.com",
    "logo": "https://vidyari.com/images/logo.png",
    "description": "Peer-to-peer learning platform for study materials, notes, and digital resources",
    "sameAs": ["https://twitter.com/vidyari", "https://www.facebook.com/vidyari"],
    "contactPoint": {
      "@type": "ContactPoint",
      "contactType": "Customer Support",
      "email": "support@vidyari.com"
    },
    "founder": {
      "@type": "Person",
      "name": "Vidyari Team"
    }
  };
  res.json(schema);
});

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

const { getSignedUrl } = require("@aws-sdk/cloudfront-signer");
// const fs = require("fs");
// const path = require("path");
// const NodeCache = require("node-cache");

// ⚙️ Config
const CLOUDFRONT_DOMAIN = "d2q25uqlym20sh.cloudfront.net";
const CLOUDFRONT_KEY_PAIR_ID = process.env.CLOUDFRONT_KEY_PAIR_ID;
const PRIVATE_KEY_PATH = path.join(__dirname, "private_keys", "cloudfront-private-key.pem");
const PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");

// ⚡ Advanced cache
const urlCache = new NodeCache({
  stdTTL: 600,          // 10 minutes
  checkperiod: 120,
  useClones: false,
  deleteOnExpire: true,
});

// 🚦 Download Rate Limiting: per-user per-second tracker
// Format: downloadRateLimiter[userId] = { count: number, resetTime: timestamp }
// Allow max 2 downloads per user per second to prevent CloudFront abuse
const downloadRateLimiter = {};
const DOWNLOAD_RATE_LIMIT = 2; // max downloads per user per second
const RATE_LIMIT_WINDOW = 1000; // 1 second in milliseconds

function checkDownloadRateLimit(userId) {
  const now = Date.now();
  const limiterKey = String(userId);

  // Initialize or reset if window has passed
  if (!downloadRateLimiter[limiterKey] || now >= downloadRateLimiter[limiterKey].resetTime) {
    downloadRateLimiter[limiterKey] = {
      count: 1,
      resetTime: now + RATE_LIMIT_WINDOW,
    };
    return { allowed: true, remaining: DOWNLOAD_RATE_LIMIT - 1 };
  }

  // Increment count within current window
  const current = downloadRateLimiter[limiterKey];
  if (current.count < DOWNLOAD_RATE_LIMIT) {
    current.count++;
    return {
      allowed: true,
      remaining: DOWNLOAD_RATE_LIMIT - current.count,
    };
  }

  // Rate limit exceeded
  const waitMs = current.resetTime - now;
  return {
    allowed: false,
    remaining: 0,
    retryAfter: Math.ceil(waitMs / 1000), // seconds until next window
  };
}

app.get("/download", authenticateJWT_user, requireAuth, async (req, res) => {
  try {
    const fileId = req.query.file_id;
    if (!fileId || fileId.length !== 24) return res.render("file-not-found");

    // 🚦 Check download rate limit (prevent CloudFront abuse)
    const rateLimitCheck = checkDownloadRateLimit(req.user._id);
    if (!rateLimitCheck.allowed) {
      console.warn(`⏱ Download rate limit hit for user ${req.user._id}. Retry after ${rateLimitCheck.retryAfter}s`);
      return res.status(429).json({
        success: false,
        message: `Too many download requests. Please try again in ${rateLimitCheck.retryAfter} second(s).`,
        retryAfter: rateLimitCheck.retryAfter,
      });
    }

    const file = await File.findById(fileId).lean();
    if (!file) return res.render("file-not-found");

    // 🛡️ Validate purchase
    if (file.price > 0) {
      const purchased = await Userpurchases.exists({
        userId: req.user._id,
        productId: fileId,
      });
      if (!purchased) return res.render("404");
    }

    // 🧩 Normalize & encode S3 key to avoid AccessDenied and duplicate prefixes
    const rawFileKey = String(file.fileUrl || '').trim();
    if (!rawFileKey) {
      console.error('Download error: missing file.fileUrl for', fileId);
      return res.render('file-not-found');
    }
    const normalizedKey = rawFileKey.startsWith('main-files/') ? rawFileKey : `main-files/${rawFileKey}`;
    const cleanFileName = decodeURIComponent(normalizedKey).replace(/\s+/g, ' ').trim();
    const encodedFileKey = encodeURIComponent(cleanFileName).replace(/%2F/g, "/");

    const cacheKey = `CF_URL_${encodedFileKey}`;
    let signedUrl = urlCache.get(cacheKey);

    // ⚡ Extend TTL for hot files
    if (signedUrl && urlCache.has(cacheKey)) {
      const ttlRemaining = urlCache.getTtl(cacheKey) - Date.now();
      if (ttlRemaining < 3 * 60 * 1000) {
        urlCache.ttl(cacheKey, 15 * 60);
        console.log(`⏱ Extended TTL for popular file: ${file.filename}`);
      }
    }

    // 🧠 Generate signed URL if not cached
    if (!signedUrl) {
      const unsignedUrl = `https://${CLOUDFRONT_DOMAIN}/${encodedFileKey}`;
      try {
        signedUrl = getSignedUrl({
          url: unsignedUrl,
          keyPairId: CLOUDFRONT_KEY_PAIR_ID,
          privateKey: PRIVATE_KEY,
          dateLessThan: new Date(Date.now() + 15 * 60 * 1000),
        });
        urlCache.set(cacheKey, signedUrl);
        console.log(`✅ Cached new signed URL for ${file.filename}`);
      } catch (signErr) {
        console.error("❌ CloudFront signing error:", signErr);
        return res.status(500).render("500");
      }
    }

    // 🧱 Background async DB updates
    Promise.allSettled([
      File.updateOne({ _id: fileId }, { $inc: { downloadCount: 1 } }),
      UserDownloads.updateOne(
        { userId: req.user._id, fileId },
        {
          $setOnInsert: {
            filename: file.filename,
            fileUrl: file.fileUrl,
            fileType: path.extname(file.fileUrl)?.toLowerCase() || ".pdf",
          },
          $inc: { downloadCount: 1 },
        },
        { upsert: true }
      ),
    ]).catch(err => console.error("DB update error:", err));

    // 🔔 Background notification
    (async () => {
      try {
        const imageUrl = await getValidFileUrl(file);
        await sendNotification({
          userId: req.user._id,
          title: `Download started: ${file.filename}`,
          body: "Your download has begun successfully!",
          image: imageUrl,
          target_link: "/downloads",
          notification_type: "Download",
        });
      } catch (err) {
        console.error("Notification error:", err.message);
      }
    })();

    // ⚡ Lightweight analytics logging
    process.nextTick(() => {
      console.log(`📊 Downloaded: ${file.filename} by ${req.user._id}`);
    });

    // 🛡️ Add rate limit headers to response
    res.set('X-RateLimit-Limit', String(DOWNLOAD_RATE_LIMIT));
    res.set('X-RateLimit-Remaining', String(rateLimitCheck.remaining));
    res.set('X-RateLimit-Reset', String(downloadRateLimiter[String(req.user._id)].resetTime));

    // ✅ Redirect to CloudFront (fastest edge delivery)
    return res.redirect(signedUrl);

  } catch (error) {
    console.error("💥 Error in /download route:", error);
    return res.status(500).render("500");
  }
});

const dotenv = require("dotenv");
const usernotifications = require("./models/userNotifications.js");
dotenv.config();

// const axios = require("axios");

// const axios = require('axios');

// const VALID_IMAGE_TYPES = ['jpg', 'jpeg', 'png', 'webp'];

// import axios from "axios";

// Optional in-memory cache to avoid repeated checks
// const fileUrlCache = new Map();

// /**
//  * Get the valid image URL served via CloudFront (optimized for cost and speed)
//  * @param {Object} file - File object from your DB
//  * @param {string} CLOUDFRONT_DOMAIN - Your CloudFront domain (e.g. dxxxx.cloudfront.net)
//  * @param {Array<string>} validTypes - Allowed file extensions
//  */
//  async function getValidFileUrl(
//   file,
//   CLOUDFRONT_DOMAIN = "previewfiles.vidyari.com", // 👈 replace with your CloudFront domain
//   validTypes = ["jpg", "jpeg", "png", "webp"]
// ) {
//   // 1️⃣ Check local cache first
//   if (fileUrlCache.has(file._id)) {
//     return fileUrlCache.get(file._id);
//   }

//   // Base URL (CloudFront domain instead of S3)
//   const BASE_URL = `https://${CLOUDFRONT_DOMAIN}/files-previews/images`;

//   // 2️⃣ If file.imageType is already known, use it directly
//   if (file.imageType) {
//     const url = `${BASE_URL}/${file._id}.${file.imageType}`;
//     fileUrlCache.set(file._id, url);
//     return url;
//   }

//   // 3️⃣ Check CloudFront cache for available types (minimal checks)
//   for (const ext of validTypes) {
//     const url = `${BASE_URL}/${file._id}.${ext}`;
//     try {
//       const res = await axios.head(url, {
//         timeout: 1500,
//         validateStatus: (s) => s < 500,
//       });
//       if (res.status === 200) {
//         // Found valid image — update DB & cache
//         file.imageType = ext;
//         await file.save().catch(() => {});
//         fileUrlCache.set(file._id, url);
//         return url;
//       }
//     } catch {
//       // Ignore 403/404 — CloudFront will respond quickly without hitting S3
//       continue;
//     }
//   }

//   // 4️⃣ Default fallback (cached by CloudFront too)
//   const fallbackUrl = `${BASE_URL}/${file._id}.jpg`;
//   fileUrlCache.set(file._id, fallbackUrl);
//   return fallbackUrl;
// }



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
// import NodeCache from "node-cache";
const pageCache = new NodeCache({ stdTTL: 600, checkperiod: 120 }); // Cache for 10 min

const CLOUDFRONT_AVATAR_URL = "d3epchi0htsp3c.cloudfront.net/avatars";

// ==========================================
// ⚡ Optimized & Cached Documents Route
// ==========================================
app.get("/documents", authenticateJWT_user, async (req, res) => {
  try {
    // 🧠 Step 1: Try cached categories
    let categories = pageCache.get("categories");
    if (!categories) {
      categories = await getcategories();
      pageCache.set("categories", categories);
    }

    // 🧠 Step 2: Try cached user profile (keyed by userId)
    let user = null;
    let profileUrl = null;

    if (req.user) {
      const cacheKey = `user_${req.user._id}`;
      const cachedUser = pageCache.get(cacheKey);

      if (cachedUser) {
        user = cachedUser;
        profileUrl = cachedUser.profilePicUrl;
      } else {
        // Fetch minimal data for rendering
        user = await User.findById(req.user._id).select("profilePicUrl username email").lean();
        if (user) {
          // Convert to CloudFront if S3-based
          if (user.profilePicUrl?.includes("s3.")) {
            try {
              const fileName = user.profilePicUrl.split("/").pop();
              user.profilePicUrl = `${CLOUDFRONT_AVATAR_URL}/${fileName}`;
            } catch (err) {
              console.warn("⚠️ Profile URL conversion failed:", err.message);
            }
          }

          // Cache for future requests
          pageCache.set(cacheKey, user);
          profileUrl = user.profilePicUrl;
        }
      }
    }

    // 🧠 Step 3: Cache auto-refresh if popular (extend TTL when hit frequently)
    if (req.user) {
      const cacheKey = `user_${req.user._id}`;
      const ttl = pageCache.getTtl(cacheKey);
      if (ttl && ttl - Date.now() < 3 * 60 * 1000) {
        pageCache.ttl(cacheKey, 15 * 60); // extend 15 min if hot
      }
    }

    // ✅ Step 4: Render final page
    res.render("index", {
      categories,
      isLoggedin: !!req.user,
      profileUrl,
      username: user?.username || null,
      useremail: user?.email || null,
      uId: user?._id?.toString() || null,
    });
  } catch (err) {
    console.error("❌ Error loading /documents:", err);
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

//course routes

// app.get('/courses', async (req, res) => {

//     try {
//         if (req.query.search !== undefined) {

//             // --- API SEARCH (Returns JSON) ---
//             console.log(`Search query received: "${req.query.search}"`);
//             const searchQuery = req.query.search;

//             const query = {
//                 published: true, // Only search published courses
//                 $or: [
//                     { title: { $regex: searchQuery, $options: 'i' } },
//                     { description: { $regex: searchQuery, $options: 'i' } },
//                     { tags: { $regex: searchQuery, $options: 'i' } }
//                 ]
//             };

//             const filteredCourses = await Course.find(query)
//                 // vvv UPDATED THIS LINE vvv
//                 .populate('userId', 'fullName profilePicUrl username') 
//                 .sort({ createdAt: -1 });

//             res.json(filteredCourses);

//         } else {

//             // --- INITIAL PAGE LOAD (Renders EJS) ---
//             console.log('Initial page load. Fetching from DB and rendering EJS.');

//             // vvv UPDATED THIS LINE vvv
//             const allCourses = await Course.find({}) 
//                 // vvv AND UPDATED THIS LINE vvv
//                 .populate('userId', 'fullName profilePicUrl username')
//                 .sort({ createdAt: -1 });

//             // vvv UPDATED THIS LINE vvv
//             res.render('courses', { courses: allCourses }); // Changed 'courses' to 'index'
//         }
//     } catch (error) {
//         console.error('Error fetching courses:', error);
//         res.status(500).send('SERVER_ERROR. Check console.');
//     }
// });



app.get('/products/related', async (req, res) => {
  const { fileId } = req.query;
  const MIN_RESULTS = 5;  // We want at least this many results
  const MAX_RESULTS = 20; // We'll fetch up to this many

  if (!fileId) {
    return res.status(400).json({ message: 'Missing fileId parameter.' });
  }

  if (!mongoose.Types.ObjectId.isValid(fileId)) {
    return res.status(400).json({ message: 'Invalid fileId format.' });
  }

  try {
    // --- 1️⃣ Find the source file ---
    // Use .lean() for a fast, read-only object
    const sourceFile = await File.findById(fileId).lean();
    if (!sourceFile) {
      return res.status(404).json({ message: 'Source file not found.' });
    }

    // Define source properties for scoring
    const sourceCategory = sourceFile.category;
    const sourcePrice = sourceFile.price || 0;
    const sourceUser = sourceFile.user;
    // Use both filename and description for a richer text search
    const searchTerms = `${sourceFile.filename} ${sourceFile.filedescription || ''}`;

    // Helper function for the weighted scoring logic
    const getScoringPipeline = (isTextSearch) => [
      {
        $addFields: {
          // A. TEXT SCORE (Weight: 50%) - ONLY for text search
          textScore: isTextSearch ? { $meta: "textScore" } : 0,

          // B. CATEGORY MATCH (Weight: 20%)
          categoryMatch: {
            $cond: { if: { $eq: ["$category", sourceCategory] }, then: 1, else: 0 }
          },

          // C. SAME USER (Weight: 10%)
          userMatch: {
            $cond: { if: { $eq: ["$user", sourceUser] }, then: 1, else: 0 }
          },

          // D. PRICE PROXIMITY (Weight: 15%) - Scaled 0 to 1
          priceProximity: {
            $subtract: [
              1,
              {
                $min: [
                  1,
                  {
                    $divide: [
                      { $abs: { $subtract: ["$price", sourcePrice] } },
                      { $max: [sourcePrice, 10] } // Use 10 as a buffer to prevent tiny price diffs from scoring 0
                    ]
                  }
                ]
              }
            ]
          },

          // E. POPULARITY (Weight: 5%) - Use log10 to normalize
          normalizedPopularity: {
            $log10: { $add: ["$downloadCount", 1] } // +1 to avoid log(0)
          }
        }
      },
      {
        // Combine all factors into a final score
        $addFields: {
          relevanceScore: {
            $add: [
              { $multiply: ["$textScore", 50] }, // High weight for text
              { $multiply: ["$categoryMatch", 20] },
              { $multiply: ["$priceProximity", 15] },
              { $multiply: ["$userMatch", 10] },
              { $multiply: ["$normalizedPopularity", 5] }
            ]
          }
        }
      }
    ];

    // --- 2️⃣ PRIMARY QUERY (Intelligent Text Search) ---
    const textSearchPipeline = [
      {
        $match: {
          _id: { $ne: sourceFile._id },
          $text: { $search: searchTerms } // The "intelligent" part
        }
      },
      ...getScoringPipeline(true), // Use scoring logic with textScore
      { $sort: { relevanceScore: -1 } },
      { $limit: MAX_RESULTS },
    ];

    let relatedDocs = await File.aggregate(textSearchPipeline);

    // --- 3️⃣ FALLBACK QUERY (If text search is weak) ---
    // If we found few results, fill the list with category-based matches
    if (relatedDocs.length < MIN_RESULTS) {
      const remainingLimit = MAX_RESULTS - relatedDocs.length;

      // Get IDs of docs we already found, so we don't duplicate
      const excludedIds = relatedDocs.map(doc => doc._id);
      excludedIds.push(sourceFile._id);

      const fallbackPipeline = [
        {
          $match: {
            _id: { $nin: excludedIds }, // Exclude self and already-found docs
            category: sourceCategory, // Broad match on category
            price: { $ne: null }
          }
        },
        ...getScoringPipeline(false), // Use scoring logic *without* textScore
        { $sort: { relevanceScore: -1 } }, // Will sort by Price, User, Popularity
        { $limit: remainingLimit }
      ];

      const fallbackDocs = await File.aggregate(fallbackPipeline);
      // Combine the "smart" results with the "fallback" results
      relatedDocs = [...relatedDocs, ...fallbackDocs];
    }

    // --- 4️⃣ Add preview URLs (file.imageType already exists) ---
    // This part is the same, but we need to project all necessary fields

    // We must manually add the $project stage *after* aggregation
    // because .aggregate() doesn't support .lean() chaining
    const finalDocs = await File.find({
      _id: { $in: relatedDocs.map(d => d._id) }
    }).lean();

    // Create a map to re-apply the relevanceScore
    const scoreMap = new Map(relatedDocs.map(doc => [doc._id.toString(), doc.relevanceScore]));

    const filesWithData = finalDocs.map(file => ({
      ...file,
      relevanceScore: scoreMap.get(file._id.toString())
    }));

    // Sort again, as .find() doesn't guarantee order
    filesWithData.sort((a, b) => b.relevanceScore - a.relevanceScore);

    const filesWithPreview = await Promise.all(
      filesWithData.map(async (file) => ({
        ...file,
        previewUrl: await getValidFileUrl(file),
      }))
    );

    // --- 5️⃣ Send response ---
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
        const previewUrl = "./images/File_Demo.svg";
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
      cashfreeAppId: process.env.CASHFREE_APP_ID,
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
app.get("/vidyariPro",authenticateJWT_user,requireAuth, async (req,res)=>{
    try {
        // Fetch the latest user data to ensure 'isPro' and 'pendingSubscriptionFee' are accurate
        const user = await User.findById(req.user._id);

        res.render('subscription', {
            user: user,
            pageTitle: 'Upgrade to Vidyari Pro'
        });
    } catch (err) {
        console.error("Error loading subscription page:", err);
        res.status(500).send('Internal Server Error');
    }

})
// app.post('/upgrade-to-pro',authenticateJWT_user, requireAuth,async (req, res) => {
//   try {
//     const userId = req.user._id; // Assuming you have user auth middleware

//     await User.findByIdAndUpdate(userId, {
//       isPro: true,
//       pendingSubscriptionFee: 499, // Set the initial debt
//       proBillingCycleStart: new Date()
//     });

//     res.status(200).json({ 
//       success: true, 
//       message: "Welcome to Vidyari Pro! ₹499 will be deducted from your next sales." 
//     });
//   } catch (error) {
//     res.status(500).json({ error: "Upgrade failed" });
//   }
// });
app.post('/subscription/pay-now', authenticateJWT_user, requireAuth,async (req, res) => {
    try {
        const amount = 499 * 100; // Razorpay works in paise (499 INR = 49900 paise)
        
        const options = {
            amount: amount,
            currency: "INR",
            receipt: `rec_pro_${req.user._id}_${Date.now().toString().slice(-6)}`,
        };

        const order = await razorpayInstance.orders.create(options);

        // Send this data to your EJS to trigger the Razorpay Modal
        res.json({
            success: true,
            order_id: order.id,
            amount: order.amount,
            key_id: process.env.RAZORPAY_KEY_ID,
            user: {
                name: req.user.fullName,
                email: req.user.email,
                contact: req.user.ph
            }
        });
    } catch (error) {
        console.error("Razorpay Order Error:", error);
        res.status(500).json({ success: false, message: "Could not create order" });
    }
});
/**
 * @route   POST /subscription/pay-later
 * @desc    Instant upgrade to Pro, fee deducted from future sales
 */
app.post('/subscription/pay-later', authenticateJWT_user, async (req, res) => {
    try {
        const userId = req.user._id;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // 1. Prevent double subscription
        if (user.isPro) {
            return res.status(400).json({ 
                success: false, 
                message: "You are already a Vidyari Pro member!" 
            });
        }

        // 2. Set Pro status and the "Wallet Debt"
        user.isPro = true;
        user.pendingSubscriptionFee = 499; // This will be checked in /verify-payment
        user.proBillingCycleStart = new Date();
        
        // 3. Set expiration for 30 days from now
        let expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 30);
        user.proBillingCycleEnd = expiryDate;

        // 4. Update role to seller if they were just a buyer
        if (user.role === "Buyer") {
            user.role = "seller";
        }

        await user.save();

        // 5. Send a system notification to the user
        // Assuming your Usernotifications model is available
        /* await Usernotifications.create({
            userId: userId,
            type: "system",
            message: "Welcome to Vidyari Pro! You now keep 90% of your sales. The ₹499 subscription fee will be deducted from your next earnings.",
        });
        */

        // 6. Return success (Frontend will redirect to dashboard)
        return res.json({ 
            success: true, 
            message: "Welcome to Pro! Your earnings share is now 90%." 
        });

    } catch (err) {
        console.error("Error in /pay-later:", err);
        return res.status(500).json({ 
            success: false, 
            message: "Internal server error. Please try again later." 
        });
    }
});
app.post('/subscription/verify-payment',authenticateJWT_user, requireAuth,async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        // Verify Signature
        const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
        hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
        const generated_signature = hmac.digest('hex');

        if (generated_signature === razorpay_signature) {
            // PAYMENT SUCCESSFUL - Update User to Pro
            let expiry = new Date();
            expiry.setDate(expiry.getDate() + 30);

            await User.findByIdAndUpdate(req.user._id, {
                isPro: true,
                pendingSubscriptionFee: 0, 
                proBillingCycleStart: new Date(),
                proBillingCycleEnd: expiry
            });

            res.json({ success: true, message: "Subscription activated!" });
        } else {
            res.status(400).json({ success: false, message: "Invalid signature, payment failed" });
        }
    } catch (error) {
        console.error("Verification Error:", error);
        res.status(500).json({ success: false });
    }
});

/**
 * @route   POST /subscription/cancel
 * @desc    Cancel Vidyari Pro and return to Standard tier
 */
app.post("/subscription/cancel", authenticateJWT_user, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);

        if (!user.isPro) {
            return res.status(400).json({ success: false, message: "No active subscription found." });
        }

        // Revert to Basic
        user.isPro = false;
        user.pendingSubscriptionFee = 0; // Clear any remaining debt
        user.proBillingCycleStart = null;
        user.proBillingCycleEnd = null;

        await user.save();

        // Create a notification for the user
        await Usernotifications.create({
            userId: req.user._id,
            type: "system",
            message: "Your Vidyari Pro subscription has been cancelled. You are now on the Standard (70/30) plan.",
        });

        return res.json({ 
            success: true, 
            message: "Subscription cancelled successfully. You are now a Standard Creator." 
        });
    } catch (err) {
        console.error("Cancellation Error:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
});
app.get("/analytics",(req,res)=>{
    res.render("analytics")
})
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



app.get("/help/user/vidyari-guid", (req, res) => {
  res.render("help.ejs");
})
app.get("/help/user/dashboard", (req, res) => {
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