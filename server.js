const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const Order = require('./models/Order');
// const pdfPoppler = require("pdf-poppler"); // Commented out in original, remains commented
const fs = require("fs");
const Message = require("./models/message");
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require("dotenv").config();
// const useLocalStorage = process.env.USE_LOCAL_STORAGE === 'true';
const mongoose = require("mongoose");
const dayjs = require('dayjs');
const bcrypt = require('bcrypt');
const mime = require('mime-types');
const axios = require('axios');
// const logVisitorMiddleware = require("./middlewares/ipmiddleware");
const categories = require('./models/categories'); // Assuming categories.js exports a Mongoose model
const { createClient } = require('@supabase/supabase-js');
const Location = require('./models/userlocation'); // Assuming Location.js exports a Mongoose model


const app = express();
app.use(express.json());
const cors = require('cors');
app.use(cors());

function getcategories() {
    return categories.find({}).then(cats => cats.map(cat => cat.name));
    
}


// const fetch = require("node-fetch");

app.post("/save-location", async (req, res) => {
  let ip=req.body.ip;
  
  // Handle localhost IPs for development
   const check= await Location.findOne({ ip: ip });
    
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
       
    console.log("Location saved:", savedLocation);
        } catch (err) {
            console.error("Location error:", err);
           
        }
        
    }else{
        console.log("Location already exists for this IP:", ip);
        
    }

//    const ipadd=await axios.get('https://api64.ipify.org?format=json');
//    console.log("IP Address:", ipadd);
  
});

// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
app.use(cookieParser()); // Use cookie-parser middleware

// Set views and static folder
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));

// Define Mongoose schema and model for Files
const fileSchema = new mongoose.Schema({
    filedescription: String,
    user: String,
    filename: String,
    fileUrl: String,
    storedFilename: String,
    price: Number,
    uploadedAt: { type: Date, default: Date.now },
    category: { type: String, required: true },
    fileSize: Number,
    downloadCount: { type: Number, default: 0 } // <-- Add this line
});

const File = mongoose.model('doccollection', fileSchema);

// Razorpay instance from env variables
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_SECRET,
});

// Supabase client setup
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Middleware for JWT authentication
function authenticateJWT(req, res, next) {
    const token = req.cookies.jwt; // Get token from HTTP-only cookie

    if (!token) {
        // No token provided, redirect to login
        return res.render('login', { error: 'Access denied. Please log in.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            // Token is invalid or expired, clear the cookie and redirect
            res.clearCookie('jwt');
            return res.render('login', { error: 'Session expired or invalid. Please log in again.' });
        }
        // Token is valid, attach user payload to request (e.g., req.user.isAdmin, req.user.username)
        req.user = user;
        next();
    });
}

// Admin User configuration (from .env)
const ADMIN_USER = {
    username: process.env.ADMIN_USERNAME,
    passwordHash: process.env.ADMIN_PASSWORD_HASH
};

// --- Routes ---

// Razorpay Order Creation - No auth needed (public)
app.post("/create-order", async (req, res) => {
    try {
        const { fileId, filename, price } = req.body;

        if (!fileId || !filename || !price || isNaN(price)) {
            return res.status(400).json({ error: "Missing or invalid fileId, filename, or price" });
        }
        const amountInPaise = Math.round(price * 100);
        const options = {
            amount: amountInPaise,
            currency: "INR",
            receipt: `receipt_${fileId}`,
        };
        const order = await razorpay.orders.create(options);
        res.json(order);
    } catch (error) {
        console.error("Order creation failed:", error);
        res.status(500).json({ error: "Failed to create order" });
    }
});

// Razorpay Payment Verification - No auth needed (public)
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
        let paymentDetails;
        try {
            paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);
        } catch (err) {
            return res.status(500).json({ success: false, message: "Failed to fetch payment details" });
        }

        const file = await File.findById(fileId);
        if (!file) {
            return res.status(404).json({ success: false, message: "File not found" });
        }

        const orderData = {
            orderId: razorpay_order_id,
            transactionId: razorpay_payment_id,
            customer: paymentDetails.email || paymentDetails.contact || "Online Customer",
            payment: paymentDetails.method,
            total: file.price,
            items: [{ name: file.filename, quantity: 1, price: file.price }],
            status: "Successfull",
            dateTime: new Date()
        };
        const order = new Order(orderData);
        await order.save();

        res.json({
            success: true,
            order: {
                orderId: order.orderId,
                dateTime: order.dateTime,
                customer: order.customer,
                transactionId: order.transactionId,
                payment: order.payment,
                total: order.total,
                items: order.items,
                status: order.status
            }
        });
    } else {
        res.status(400).json({ success: false, message: "Invalid signature" });
    }
});

// Home Page - Render files
app.get("/", async (req, res) => {
    try {
        const files = await File.find();
        const categories = await getcategories(); // Fetch categories from MongoDB
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
        res.render('index', { files: filesWithPreviews,categories });
    } catch (err) {
        console.error("DB fetch error:", err);
        res.status(500).send("Failed to load files");
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
app.post("/download-pdf", async (req, res) => {
    const { fileId, paymentId } = req.body;

    if (!fileId) return res.status(400).send("Missing fileId");

    const file = await File.findById(fileId);
    if (!file) return res.status(404).send("File not found");

    // Increment download count here
    await File.updateOne({ _id: file._id }, { $inc: { downloadCount: 1 } });

    const { data, error } = await supabase
        .storage
        .from('files')
        .createSignedUrl(file.fileUrl.replace(/^\/+/, ''), 30);

    if (error || !data?.signedUrl) return res.status(404).send("File not found in storage");

    try {
        const fileResponse = await axios.get(data.signedUrl, { responseType: 'stream' });
        const contentType = fileResponse.headers['content-type'];
        let extension = mime.extension(contentType) || 'pdf';
        let baseName = file.filename ? file.filename.split('.')[0] : 'file';
        const safeFilename = encodeURIComponent(`${baseName}.${extension}`);

        res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
        res.setHeader('Content-Type', contentType || 'application/octet-stream');

        fileResponse.data.on('error', (err) => {
            console.error('Stream error:', err);
            res.status(500).send('Error streaming file');
        });

        fileResponse.data.pipe(res);

    } catch (err) {
        console.error('Axios download error:', err);
        res.status(500).send('Failed to download file');
    }
});

// --- Admin Authentication & Routes ---

// Login Page (GET)
app.get('/login', (req, res) => {
    // If a valid JWT cookie exists, redirect to admin immediately
    if (req.cookies.jwt) {
        try {
            jwt.verify(req.cookies.jwt, process.env.JWT_SECRET);
            return res.redirect('/admin');
        } catch (error) {
            // Token is invalid, clear it and proceed to login page to show error
            res.clearCookie('jwt');
        }
    }
    res.render('login', { error: null });
});

// Handle Login (POST) - No auth check needed here, this is auth itself
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (
        username === ADMIN_USER.username &&
        ADMIN_USER.passwordHash &&
        await bcrypt.compare(password, ADMIN_USER.passwordHash)
    ) {
        // Generate JWT token with 24h expiry
        const token = jwt.sign({ isAdmin: true, username: ADMIN_USER.username }, process.env.JWT_SECRET, { expiresIn: '24h' });

        // Set the token as an HTTP-only cookie with 24h maxAge
        res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
            sameSite: 'Lax'
        });

        // Redirect to admin page upon successful login
        res.redirect('/admin');
    } else {
        // Render login page with error for invalid credentials
        res.render('login', { error: 'Invalid username or password.' });
    }
});

// Logout Route - Clears the JWT cookie
app.get('/logout', (req, res) => {
    res.clearCookie('jwt'); // Clear the JWT cookie from the browser
    res.redirect('/login'); // Redirect to login page
});

// Admin Dashboard (Protected by JWT)
// const dayjs = require('dayjs');
const quarterOfYear = require('dayjs/plugin/quarterOfYear'); // Import the plugin
dayjs.extend(quarterOfYear); // Extend dayjs with the plugin
async function  fetchaddress(){
  const allAddresses=await Location.find({}).sort({ createdAt: -1 });
  return allAddresses; // Fetch last 100 addresses
}
 // Fetch last 100 addresses

app.get("/admin", authenticateJWT, async (req, res) => {
    const now = dayjs();
    const startCurrent = now.subtract(6, 'day').startOf('day').toDate();
    const endCurrent = now.endOf('day').toDate();
    const startPrev = now.subtract(13, 'day').startOf('day').toDate();
    const endPrev = now.subtract(7, 'day').endOf('day').toDate();

    const ordersCurrent = await Order.find({ dateTime: { $gte: startCurrent, $lte: endCurrent } });
    const totalOrders = ordersCurrent.length;
    const failedOrders = ordersCurrent.filter(o => o.status.toLowerCase().includes("unsuccessfull")).length;
    const successfulOrders = ordersCurrent.filter(o => o.status.toLowerCase().includes("successfull")).length;

    const ordersPrev = await Order.find({ dateTime: { $gte: startPrev, $lte: endPrev } });
    const totalOrdersPrev = ordersPrev.length;
    const failedOrdersPrev = ordersPrev.filter(o => o.status.toLowerCase().includes("unsuccessfull")).length;
    const successfulOrdersPrev = ordersPrev.filter(o => o.status.toLowerCase().includes("successfull")).length;

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

    // --- NEW DATA FETCHING FOR CHARTS ---

    // 1. Data for "Orders & Revenue Trends" Chart (Dashboard) - Last 12 months
    const monthlyData = await Order.aggregate([
        {
            $match: {
                // Filter for orders within the last 12 months
                dateTime: { $gte: dayjs().subtract(11, 'month').startOf('month').toDate(), $lte: dayjs().endOf('month').toDate() },
                // Only count successful orders for revenue
                status: { $in: ["Successfull"] }
            }
        },
        {
            $group: {
                _id: {
                    year: { $year: "$dateTime" },
                    month: { $month: "$dateTime" }
                },
                totalOrders: { $sum: 1 },
                totalRevenue: { $sum: "$total" }
            }
        },
        {
            $sort: { "_id.year": 1, "_id.month": 1 }
        }
    ]);

    const monthlyLabels = [];
    const monthlyTotalOrdersData = [];
    const monthlyTotalRevenueData = [];

    // Populate data for the last 12 months, filling with 0 if no orders exist for a month
    let currentMonth = dayjs().subtract(11, 'month').startOf('month');
    for (let i = 0; i < 12; i++) {
        const monthName = currentMonth.format('MMM YYYY'); // e.g., "Jan 2024"
        monthlyLabels.push(monthName);

        const foundMonthData = monthlyData.find(item =>
            item._id.year === currentMonth.year() && item._id.month === (currentMonth.month() + 1)
        );

        monthlyTotalOrdersData.push(foundMonthData ? foundMonthData.totalOrders : 0);
        monthlyTotalRevenueData.push(foundMonthData ? foundMonthData.totalRevenue : 0);

        currentMonth = currentMonth.add(1, 'month');
    }

    // 2. Data for "Revenue Trends Over Time" Chart (Analytics section) - Last 4 weeks
    const weeklyRevenueDataPoints = [];
    const weeklyRevenueLabels = [];

    for (let i = 3; i >= 0; i--) { // Loop from 3 weeks ago down to current week
        const weekStart = dayjs().subtract(i, 'week').startOf('week').toDate();
        const weekEnd = dayjs().subtract(i, 'week').endOf('week').toDate();

        const revenueForWeek = await Order.aggregate([
            { $match: { dateTime: { $gte: weekStart, $lte: weekEnd }, status: { $in: ['Successfull'] } } },
            { $group: { _id: null, total: { $sum: "$total" } } }
        ]);

        weeklyRevenueDataPoints.push(parseFloat(((revenueForWeek[0] && revenueForWeek[0].total) || 0).toFixed(2)));
        weeklyRevenueLabels.push(dayjs(weekStart).format('MMM D')); // e.g., "Jun 3"
    }

    // 3. Data for "Order Status Distribution" Chart (Analytics section)
    const successfulOrdersCount = await Order.countDocuments({ status: "Successfull" });
    const unsuccessfulOrdersCount = await Order.countDocuments({ status: "unsuccessfull" });
    const pendingOrdersCount = await Order.countDocuments({ status: "Pending" });

    const orderStatusCounts = {
        successful: successfulOrdersCount,
        unsuccessful: unsuccessfulOrdersCount,
        pending: pendingOrdersCount
    };

    // 4. Data for "Average Order Value" Chart (Analytics section) - Last 4 quarters
    const aovDataPoints = [];
    const aovLabels = [];

    for (let i = 3; i >= 0; i--) { // Loop from 3 quarters ago down to current quarter
        const quarterStart = dayjs().subtract(i, 'quarter').startOf('quarter').toDate();
        const quarterEnd = dayjs().subtract(i, 'quarter').endOf('quarter').toDate();

        const aovForQuarter = await Order.aggregate([
            { $match: { dateTime: { $gte: quarterStart, $lte: quarterEnd }, status: { $in: ['Successfull'] } } },
            {
                $group: {
                    _id: null,
                    totalRevenue: { $sum: "$total" },
                    totalOrders: { $sum: 1 }
                }
            }
        ]);

        const aov = (aovForQuarter[0] && aovForQuarter[0].totalOrders > 0) ?
                    (aovForQuarter[0].totalRevenue / aovForQuarter[0].totalOrders) : 0;

        aovDataPoints.push(parseFloat(aov.toFixed(2)));
        aovLabels.push(dayjs(quarterStart).format('Q [Q] YYYY')); // e.g., "2 Q 2024"
    }

   const categories = await getcategories(); // Fetch c
   const allAddresses= await fetchaddress(); // Fetch last 100 addresses
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
        allAddresses
    });
});

function getCSSVariables() {
    // Create a dummy element, attach to the DOM, get styles, and remove
    const dummy = document.createElement('div');
    dummy.style.display = 'none';
    document.body.appendChild(dummy);
    const computedStyle = window.getComputedStyle(dummy);

    const colors = {
        primary: computedStyle.getPropertyValue('--primary').trim(),
        primaryLight: computedStyle.getPropertyValue('--primary-light').trim(),
        success: computedStyle.getPropertyValue('--success').trim(),
        badgeSuccessBg: computedStyle.getPropertyValue('--badge-success-bg').trim(),
        danger: computedStyle.getPropertyValue('--danger').trim(),
        textDark: computedStyle.getPropertyValue('--text-dark').trim(),
        textLight: computedStyle.getPropertyValue('--text-light').trim(),
        border: computedStyle.getPropertyValue('--border').trim(),
        background: computedStyle.getPropertyValue('--background').trim()
    };

    document.body.removeChild(dummy); // Clean up
    return colors;
}


// Edit File Details (Protected by JWT)
app.post('/edit-file', authenticateJWT, async (req, res) => {
    const { fileId, filename, filedescription, price } = req.body;
    await File.findByIdAndUpdate(fileId, {
        filename,
        filedescription,
        price
    });
    res.redirect('/admin?fileUpdated=1');
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
app.post('/upload-file', upload.fields([
    { name: 'file', maxCount: 1 },
    { name: 'previewImage', maxCount: 1 }
]), authenticateJWT, async (req, res) => {
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

    // 2. Save metadata in MongoDB, including file size
    const newFile = await File.create({
        filename,
        filedescription,
        price,
        category,
        fileUrl: pdfData.path,
        uploadedAt: new Date(),
        user: req.user ? req.user.username : 'Admin',
        fileSize: pdfFile.size // <-- Add this line
    });
  //notification update
  const newMessage = new Message({ message: `New file uploaded: ${filename} by ${req.user ? req.user.username : 'Admin'}` });
  await newMessage.save();
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
    // ...rest of your code...
});


// Delete Order - NOW PROTECTED BY JWT
app.post('/delete-order', authenticateJWT, async (req, res) => {
    const { orderId } = req.body;
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

// Notifications API
app.get('/notifications', async (req, res) => {
    const query = {};
    if (req.query.unseen) query.seen = false;
    const notifications = await Message.find().sort({ DateTime: -1 });
    res.json({ notifications });
});

// File Details Page
app.get('/file/:id', async (req, res) => {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).send('File not found');

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

// Delete File - NOW PROTECTED BY JWT
app.post('/delete-file', authenticateJWT, async (req, res) => {
    const { fileId, fileUrl } = req.body;
    console.log({ fileId, fileUrl });
    try {
        // Find the file document to get the preview image path
        const file = await File.findById(fileId);
        if (!file) return res.json({ success: false, message: 'File not found' });

        // Prepare paths to delete: main file and preview image
        const pathsToDelete = [fileUrl];
        // If you store the preview image as `previews/<fileId>.jpg`
        pathsToDelete.push(`previews/${file._id}.jpg`);
        
        // Remove both files from Supabase Storage
        const { error: supabaseError } = await supabase
            .storage
            .from('files')
            .remove(pathsToDelete);

        if (supabaseError) return res.json({ success: false, message: 'Supabase delete failed' });

        // Delete the file record from MongoDB
        await File.deleteOne({ _id: fileId });

        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, message: 'Server error' });
    }
});

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
app.get('/viewfile/:id', async (req, res) => {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).send('File not found');

    // Increment download count
    await File.updateOne({ _id: file._id }, { $inc: { downloadCount: 1 } });

    const { data, error } = await supabase
        .storage
        .from('files')
        .createSignedUrl(file.fileUrl, 30); // 30 seconds

    if (error || !data?.signedUrl) return res.status(404).send('File not found in storage');

    const fileResponse = await axios.get(data.signedUrl, { responseType: 'stream' });

    // ...existing code for filename and headers...
    let extension = '';
    if (file.filename && file.filename.includes('.')) {
        extension = file.filename.split('.').pop();
    } else if (file.fileUrl && file.fileUrl.includes('.')) {
        extension = file.fileUrl.split('.').pop();
    }

    let baseName = file.filename ? file.filename.split('.')[0] : 'file';
    const safeFilename = extension
        ? `${baseName}.${extension}`
        : file.filename || 'file.pdf';

    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    res.setHeader('Content-Type', fileResponse.headers['content-type'] || 'application/octet-stream');
    fileResponse.data.pipe(res);
});
app.use((req, res) => {
    res.status(404).render('404');
});
// Error handling middleware