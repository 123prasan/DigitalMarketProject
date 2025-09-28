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
// const logVisitorMiddleware = require("./middlewares/ipmiddleware");
const categories = require("./models/categories"); // Assuming categories.js exports a Mongoose model
const { createClient } = require("@supabase/supabase-js");
const Location = require("./models/userlocation"); // Assuming Location.js exports a Mongoose model
const chatRoutes = require("./routes/chat.js");
const File = require("./models/file");
const courseRoutes = require("./routes/courseroutes");
const progressRoutes = require("./routes/progressroutes");
const authenticateJWT_user = require("./routes/authentication/jwtAuth.js");
const User = require("./models/userData.js");
const UserDownloads = require("./models/userDownloads.js");
const Userpurchases = require("./models/userPerchase.js");
const requireAuth = require("./routes/authentication/reaquireAuth.js");
const Usernotifications = require("./models/userNotifications");
const CF_DOMAIN = "https://d3tonh6o5ach9f.cloudfront.net"; // e.g., https://d123abcd.cloudfront.net
const Usertransaction = require("./models/userTransactions.js");
const app = express();

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
app.use(fileroute);
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
app.use(cookieParser()); // Use cookie-parser middleware

// Set views and static folder
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/chat", chatRoutes);
// Define Mongoose schema and model for Files
// In your file model (e.g., models/File.js)

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
app.get("/:id/:impression", async (req, res) => {
  if (req.params.impression == "like") {
    const file = await File.findById(req.params.id);
    if (file) {
      file.likes += 1;
      await file.save();
      // console.log(file.likes);
      res.json({ likes: file.likes });
    } else {
      res.status(404).json({ error: "File not found" });
    }
  }
  if (req.params.impression == "dislike") {
    const file = await File.findById(req.params.id);
    if (file && file.likes > 0) {
      file.likes -= 1;
      await file.save();
      // console.log(file.likes);
      res.json({ likes: file.likes });
    } else {
      res.status(404).json({ error: "File not found" });
    }
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
    filename,
  } = req.body;

  // Validate required payment fields
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({
      success: false,
      message: "Incomplete payment details",
    });
  }

  // Verify Razorpay signature
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
    // Fetch payment details from Razorpay
    const paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);

    // Fetch file details
    const file = await File.findById(fileId);
    if (!file) {
      return res
        .status(404)
        .json({ success: false, message: "File not found" });
    }
    const price = totalprice * 0.3;
    const totalPriceaftercut = totalprice - price;
    const updatetransaction = new Usertransaction({
      userId: file.userId,
      ProductId: file._id,
      totalAmount: totalPriceaftercut,
      ProductName: file.filename,
      purchaserId: req.user._id,
      transactionId: razorpay_payment_id,
    });
    await updatetransaction.save();
    await Adminbal.findOneAndUpdate(
      {}, // condition (empty if you only have one Admin balance doc)
      {
        $inc: {
          totalAmount: price, // add price to existing totalAmount
          cutOffbal: totalPriceaftercut, // add totalPriceAfterCut to existing cutOffbal
        },
      },
      { upsert: true, new: true } // create if not exists, return updated doc
    );

    // Save order details
    const orderData = {
      orderId: razorpay_order_id,
      transactionId: razorpay_payment_id,
      customer:
        paymentDetails.email || paymentDetails.contact || "Online Customer",
      payment: paymentDetails.method,
      total: totalprice,
      productId: file._id,
      productName: file.filename,
      items: [{ name: file.filename, quantity: 1, price: file.price }],
      status: "Successfull",
      dateTime: new Date(),
    };
    const order = new Order(orderData);
    await order.save();

    // Save user purchase
    const userPurchase = new Userpurchases({
      userId: req.user._id,
      productId: file._id,
      price: file.price,
      totalPrice: totalprice,
      productName: file.filename,
    });
    await userPurchase.save();

    // Add file to user's downloads (ignore duplicates)
    if (fileId) {
      await UserDownloads.findOneAndUpdate(
        { userId: req.user._id, fileId: file._id },
        {
          userId: req.user._id,
          fileId: file._id,
          filename: file.filename,
          fileUrl: file.fileUrl,
          fileType: file.fileType || "pdf",
        },
        { upsert: true, setDefaultsOnInsert: true }
      );

      // Send notification
      const userNotification = new Usernotifications({
        userId: req.user._id,
        type: "purchase",
        message: `Your purchase of the file <strong>${file.filename}</strong> has been successful.`,
        targetId: file._id,
      });
      await userNotification.save();
    }

    // Generate temporary token for direct file access
    const token = jwt.sign(
      {
        fileId: fileId,
        orderId: order.orderId,
        transactionId: order.transactionId,
      },
      process.env.JWT_SECRET_FILE_PURCHASE,
      { expiresIn: "2m" } // expires in 2 minutes
    );

    // Return download URL
    return res.json({
      success: true,
      downloadUrl: `/viewfile/${file.slug}/${file._id}?token=${token}`,
    });
  } catch (err) {
    console.error("Error in /verify-payment:", err);
    return res
      .status(500)
      .json({ success: false, message: "Payment verification failed" });
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
      message: `New file uploaded: ${filename} by ${
        req.user ? req.user.username : "Admin"
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

    // Get seller profile picture
    let sellerprofilepic = "/images/avatar.jpg"; // default
    if (file.userId) {
      const findUser = await User.findById(file.userId);
      if (findUser?.profilePicUrl) {
        sellerprofilepic = findUser.profilePicUrl;
      }
    }

    // Redirect if slug is incorrect
    if (file.slug !== req.params.slug) {
      return res.redirect(301, `/file/${file.slug}/${file._id}`);
    }

    // Build URLs (CloudFront)
const ext = file.imageType ?file.imageType:"jpg";
const previewUrl = `${CF_DOMAIN}/files-previews/images/${file._id}.${ext}`;    const pdfUrl = `${CF_DOMAIN}/${file.fileUrl}`;

    console.log("Preview URL:", previewUrl);

    // Logged in user
    let user = null;
    if (req.user) {
      user = await User.findById(req.user._id).select("profilePicUrl username email");
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
    });
  } catch (error) {
    console.error("Error fetching file:", error);
    res.status(500).send("Server error");
  }
});
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
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
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
    if (!fileId || fileId.length !== 24) return res.render("file-not-found");

    const file = await File.findById(fileId);
    if (!file) return res.render("file-not-found");

    // Purchase check
    if (file.price > 0) {
      const purchase = await Userpurchases.findOne({
        userId: req.user._id,
        productId: fileId,
      });
      if (!purchase) return res.render("404");
    }

    const fileKey = `main-files/${file.fileUrl}`;
    const extension = path.extname(file.fileUrl).toLowerCase();
    const baseName = path.basename(file.filename, path.extname(file.filename));
    const finalFilename = `${baseName}${extension}`;

    // Log download
    const existing = await UserDownloads.findOne({
      userId: req.user._id,
      fileId: file._id,
    });
    if (!existing) {
      await new UserDownloads({
        filename: file.filename,
        userId: req.user._id,
        fileId: file._id,
        fileUrl: file.fileUrl,
        fileType: extension,
      }).save();
      console.log("Download saved");
    }

    // Get S3 object stream
    const s3Stream = s3
      .getObject({
        Bucket: "vidyarimain",
        Key: fileKey,
      })
      .createReadStream();

    // Set headers for direct download
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${finalFilename}"`
    );
    res.setHeader(
      "Content-Type",
      mime.lookup(extension) || "application/octet-stream"
    );

    // Pipe S3 stream directly to response
    s3Stream.pipe(res).on("error", (err) => {
      console.error("S3 stream error:", err);
      res.status(500).render("500");
    });
  } catch (error) {
    console.error("Error in /download route:", error);
    res.status(500).render("500");
  }
});

const dotenv = require("dotenv");
const usernotifications = require("./models/userNotifications.js");
dotenv.config();

app.get("/documents", authenticateJWT_user, async (req, res) => {
  try {
    const files = await File.find();
    const categories = await getcategories();

    const filesWithPreviews = files.map((file) => {
      const previewUrl = `${CF_DOMAIN}/files-previews/images/${file._id}.${files.imageType || "jpg"}`;
      
      const pdfUrl = `${CF_DOMAIN}/${file.fileUrl}`;

      return {
        ...file.toObject(),
        previewUrl,
        pdfUrl,
      };
    });
    
    let user = null;
    if (req.user) {
      user = await User.findById(req.user._id).select(
        "profilePicUrl username email"
      );
    }

    res.render("index", {
      files: filesWithPreviews,
      categories,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
    });
  } catch (err) {
    console.error("DB fetch error:", err);
    res.status(500).send("Failed to load files");
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
