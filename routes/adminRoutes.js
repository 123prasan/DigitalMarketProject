const express = require('express');
const router = express.Router();
const Order = require('../models/Order');
const File = require('../models/file');
const Location = require('../models/userlocation');
const User = require('../models/userData');
const Usertransaction = require('../models/userTransactions');
const UserPurchase = require('../models/userPerchase');
const UserDownload = require('../models/userDownloads');
const Account = require('../models/Account');
const Coupon = require('../models/couponschema.js');
const dayjs = require('dayjs');
const AWS = require('aws-sdk');
const { EmailService } = require('../test');
const path = require('path');
const fs = require('fs');
const { getSignedUrl: getCloudfrontSignedUrl } = require('@aws-sdk/cloudfront-signer');

// CloudFront config (optional - set via env)
const CLOUDFRONT_DOMAIN = process.env.CLOUDFRONT_DOMAIN || 'd2q25uqlym20sh.cloudfront.net';
const CLOUDFRONT_KEY_PAIR_ID = process.env.CLOUDFRONT_KEY_PAIR_ID || process.env.CLOUDFRONT_KEYPAIR_ID;
let CLOUDFRONT_PRIVATE_KEY = null;
try {
  const privateKeyPath = path.join(__dirname, '..', 'private_keys', 'cloudfront-private-key.pem');
  if (fs.existsSync(privateKeyPath)) {
    CLOUDFRONT_PRIVATE_KEY = fs.readFileSync(privateKeyPath, 'utf8');
  }
} catch (e) {
  console.warn('CloudFront private key not loaded:', e.message || e);
}

// Configure S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'ap-south-1',
});

// Middleware to check if user is authenticated admin
const authenticateAdmin = require('./authentication/reaquireAuth');

// Initialize email service for real Nodemailer sending
const emailService = new EmailService();

// ============================================
// DASHBOARD STATS API ROUTES
// ============================================

/**
 * GET /api/admin/stats
 * Returns overall dashboard statistics (orders, revenue, customers)
 */
router.get('/stats', authenticateAdmin, async (req, res) => {
  try {
    const now = dayjs();
    const startCurrent = now.subtract(6, 'day').startOf('day').toDate();
    const endCurrent = now.endOf('day').toDate();
    const startPrev = now.subtract(13, 'day').startOf('day').toDate();
    const endPrev = now.subtract(7, 'day').endOf('day').toDate();

    // Current period orders
    const ordersCurrent = await Order.find({
      dateTime: { $gte: startCurrent, $lte: endCurrent },
    });
    
    const ordersPrev = await Order.find({
      dateTime: { $gte: startPrev, $lte: endPrev },
    });

    // Calculate metrics for the current 7‑day window
    const totalOrders = ordersCurrent.length;
    const failedOrders = ordersCurrent.filter((o) =>
      o.status.toLowerCase().includes('unsuccessfull')
    ).length;
    const successfulOrders = ordersCurrent.filter((o) =>
      o.status.toLowerCase().includes('successfull')
    ).length;

    // Also compute all-time totals so the dashboard can show lifetime numbers
    const totalOrdersAll = await Order.countDocuments({});
    const failedOrdersAll = await Order.countDocuments({ status: /unsuccessfull/i });
    const successfulOrdersAll = await Order.countDocuments({ status: /successfull/i });

    // Calculate trends for weekly comparison
    const calcTrend = (current, prev) => {
      if (prev === 0) return current === 0 ? 0 : 100;
      return (((current - prev) / prev) * 100).toFixed(1);
    };

    // Revenue
    const amountData = await Order.aggregate([
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$total' },
        },
      },
    ]);
    const totalAmount = (amountData[0] && amountData[0].totalAmount) || 0;

    // Customers
    const allAddresses = await Location.find({}).sort({ createdAt: -1 });
    const uniqueCustomers = allAddresses.length;

    res.json({
      success: true,
      stats: {
        // lifetime figures
        totalOrders: totalOrdersAll,
        failedOrders: failedOrdersAll,
        successfulOrders: successfulOrdersAll,
        // weekly figures (used for trends/charts)
        weeklyTotalOrders: totalOrders,
        weeklyFailedOrders: failedOrders,
        weeklySuccessfulOrders: successfulOrders,
        totalOrdersTrend: calcTrend(totalOrders, ordersPrev.length),
        failedOrdersTrend: calcTrend(failedOrders, 
          ordersPrev.filter(o => o.status.toLowerCase().includes('unsuccessfull')).length),
        successfulOrdersTrend: calcTrend(successfulOrders,
          ordersPrev.filter(o => o.status.toLowerCase().includes('successfull')).length),
        totalAmount,
        uniqueCustomers,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/orders
 * Returns paginated orders list with optional filters
 */
router.get('/orders', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = 'all', search = '' } = req.query;
    const skip = (page - 1) * limit;

    let query = {};

    // Filter by status
    if (status !== 'all') {
      if (status === 'unsuccessful') {
        query.status = { $regex: /unsuccessfull/i };
      } else if (status === 'successful') {
        query.status = { $regex: /successfull/i };
      }
    }

    // Search filter
    if (search) {
      query.$or = [
        { orderId: { $regex: search, $options: 'i' } },
        { transactionId: { $regex: search, $options: 'i' } },
        { customer: { $regex: search, $options: 'i' } },
      ];
    }

    const total = await Order.countDocuments(query);
    const orders = await Order.find(query)
      .sort({ dateTime: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.json({
      success: true,
      orders,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/files
 * Returns paginated files list
 */
router.get('/files', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.filename = { $regex: search, $options: 'i' };
    }

    const total = await File.countDocuments(query);
    const files = await File.find(query)
      .sort({ uploadedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    // Debug logging
    console.log(`📁 Files API - Total: ${total}, Page: ${page}, Limit: ${parseInt(limit)}, Returned: ${files.length}`);

    // attach coupon code if available
    const filesWithCoupon = await Promise.all(
      files.map(async (f) => {
        const coupon = await Coupon.findOne({ file: f._id });
        const obj = f.toObject();
        obj.couponCode = coupon ? coupon.code : '';
        return obj;
      })
    );

    res.json({
      success: true,
      files: filesWithCoupon,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/customers
 * Returns list of all customers/addresses
 */
router.get('/customers', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.$or = [
        { full_address: { $regex: search, $options: 'i' } },
        { city: { $regex: search, $options: 'i' } },
        { country: { $regex: search, $options: 'i' } },
      ];
    }

    const total = await Location.countDocuments(query);
    const customers = await Location.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.json({
      success: true,
      customers,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/transactions
 * Returns paginated transactions list
 */
router.get('/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = 'all' } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (status !== 'all') {
      query.status = status;
    }

    const total = await Usertransaction.countDocuments(query);
    const transactions = await Usertransaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.json({
      success: true,
      transactions,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/chart-data
 * Returns data for charts (monthly trends, etc.)
 */
router.get('/chart-data', authenticateAdmin, async (req, res) => {
  try {
    // Monthly data for last 12 months
    const monthlyData = await Order.aggregate([
      {
        $match: {
          dateTime: {
            $gte: dayjs().subtract(11, 'month').startOf('month').toDate(),
            $lte: dayjs().endOf('month').toDate(),
          },
          status: { $in: ['Successfull'] },
        },
      },
      {
        $group: {
          _id: {
            year: { $year: '$dateTime' },
            month: { $month: '$dateTime' },
          },
          totalOrders: { $sum: 1 },
          totalRevenue: { $sum: '$total' },
        },
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1 },
      },
    ]);

    // Status distribution
    const statusData = await Order.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
        },
      },
    ]);

    res.json({
      success: true,
      monthlyData,
      statusData,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/orders/:orderId
 * Retrieve a single order's details (used by admin UI)
 */
router.get('/orders/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }
    res.json({ success: true, order });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * DELETE /api/admin/orders/:orderId
 * Delete an order
 */
router.delete('/orders/:orderId', authenticateAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const result = await Order.findByIdAndDelete(orderId);
    
    if (!result) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    res.json({ success: true, message: 'Order deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * DELETE /api/admin/files/:id
 * Delete a file
 */
// delete a single file
router.delete('/files/:fileId', authenticateAdmin, async (req, res) => {
  try {
    const { fileId } = req.params;
    const result = await File.findByIdAndDelete(fileId);
    // also remove any coupon linked
    await Coupon.deleteMany({ file: fileId });
    
    if (!result) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    res.json({ success: true, message: 'File deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// bulk delete files
router.delete('/files', authenticateAdmin, async (req, res) => {
  try {
    const { fileIds } = req.body;
    if (!Array.isArray(fileIds)) {
      return res.status(400).json({ success: false, message: 'fileIds array required' });
    }
    const result = await File.deleteMany({ _id: { $in: fileIds } });
    await Coupon.deleteMany({ file: { $in: fileIds } });
    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/download-file
 * Download a file from S3 by fileId
 */
router.get('/download-file', authenticateAdmin, async (req, res) => {
  try {
    const { fileId, filename } = req.query;
    
    // Get file from MongoDB to get the S3 key
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    // fileUrl contains the S3 key for the main file - normalize to avoid double-prefix
    let s3Key = String(file.fileUrl || '').trim();
    if (!s3Key) return res.status(404).json({ success: false, message: 'File has no S3 key' });
    if (!s3Key.startsWith('main-files/')) s3Key = `main-files/${s3Key}`;

    // Determine proper download filename with extension
    const ext = path.extname(s3Key) || '';
    const rawName = String(filename || '').trim();
    const hasExt = rawName && path.extname(rawName);
    const safeBase = rawName
      ? rawName.replace(/[^a-zA-Z0-9 _.-]/g, '_')
      : `file_${file._id}`;
    const finalFilename = hasExt ? safeBase : `${safeBase}${ext}`;

    // Try CloudFront signed URL first (if private key + key pair id available)
    let signedUrl;
    try {
      if (CLOUDFRONT_PRIVATE_KEY && CLOUDFRONT_KEY_PAIR_ID) {
        // Include response-content-disposition as query param so S3 will set Content-Disposition
        const disposition = `attachment; filename="${finalFilename}"`;
        const unsignedUrl = `https://${CLOUDFRONT_DOMAIN}/${encodeURIComponent(s3Key).replace(/%2F/g, '/')}` + `?response-content-disposition=${encodeURIComponent(disposition)}`;

        signedUrl = getCloudfrontSignedUrl({
          url: unsignedUrl,
          keyPairId: CLOUDFRONT_KEY_PAIR_ID,
          privateKey: CLOUDFRONT_PRIVATE_KEY,
          dateLessThan: new Date(Date.now() + 15 * 60 * 1000),
        });
        console.log(`Using CloudFront signed URL for ${s3Key}`);
        return res.redirect(signedUrl);
      }
    } catch (cfErr) {
      console.error('CloudFront signing failed, falling back to S3 signed URL:', cfErr);
    }

    // Fallback: S3 signed URL with Content-Disposition
    signedUrl = s3.getSignedUrl('getObject', {
      Bucket: 'vidyarimain2',
      Key: s3Key,
      Expires: 15 * 60, // 15 minutes
      ResponseContentDisposition: `attachment; filename="${finalFilename}"`,
    });

    // Redirect to the signed URL for download
    res.redirect(signedUrl);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// USER MANAGEMENT API ROUTES
// ============================================

/**
 * GET /api/admin/users
 * Returns all users with comprehensive data
 */
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    const allUsers = await User.find({}).sort({ createdAt: -1 });
    
    // Count different user statuses
    const verifiedUsers = allUsers.filter(u => u.ISVERIFIED).length;
    const suspendedUsers = allUsers.filter(u => u.isSuspended).length;
    const bannedUsers = allUsers.filter(u => u.isBanned).length;

    res.json({
      success: true,
      allUsers,
      verifiedUsers,
      suspendedUsers,
      bannedUsers,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/admin/users/:userId
 * Returns specific user details with account info, purchases, and downloads
 */
router.get('/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId)
      .populate('followers', 'username profilePicUrl')
      .populate('following', 'username profilePicUrl');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get account balance
    const account = await Account.findOne({ userId });
    
    // Get user purchases
    const purchases = await UserPurchase.find({ userId });
    
    // Get user downloads
    const downloads = await UserDownload.find({ userId });

    res.json({
      success: true,
      user,
      account,
      purchases,
      downloads,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * PATCH /api/admin/users/:userId/suspend
 * Toggle suspend status of a user
 */
router.patch('/users/:userId/suspend', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { isSuspended } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { isSuspended },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      message: `User ${isSuspended ? 'suspended' : 'unsuspended'} successfully`,
      user,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * PATCH /api/admin/users/:userId/ban
 * Toggle ban status of a user
 */
router.patch('/users/:userId/ban', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { isBanned } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { isBanned },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      message: `User ${isBanned ? 'banned' : 'unbanned'} successfully`,
      user,
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * DELETE /api/admin/users/:userId
 * Delete a user and all associated data
 */
router.delete('/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    // Delete user and all related data
    await Promise.all([
      User.findByIdAndDelete(userId),
      Account.deleteMany({ userId }),
      UserPurchase.deleteMany({ userId }),
      UserDownload.deleteMany({ userId }),
      Usertransaction.deleteMany({ userId }),
      File.deleteMany({ user: userId }),
    ]);

    res.json({
      success: true,
      message: 'User and all associated data deleted successfully',
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// SELLERS API ROUTE (added 2026-03-03)
// ============================================

/**
 * GET /api/admin/sellers
 * Returns list of sellers with counts and revenue placeholders
 */
router.get('/sellers', authenticateAdmin, async (req, res) => {
  try {
    // find users marked as seller (case-insensitive)
    const sellers = await User.find({ role: { $regex: /^seller$/i } }).lean();

    const sellersData = await Promise.all(
      sellers.map(async (s) => {
        const productCount = await File.countDocuments({ user: s._id });
        // revenue calculation requires more detailed order model; placeholder 0 for now
        const revenue = 0;
        return {
          _id: s._id,
          username: s.username,
          email: s.email,
          name: s.name || s.username,
          productCount,
          revenue,
          rating: s.rating || 0,
          status: s.isBanned ? 'Banned' : s.isSuspended ? 'Suspended' : 'Active',
        };
      })
    );

    res.json({ success: true, sellers: sellersData });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// EMAIL & NOTIFICATIONS API ROUTES
// ============================================

/**
 * GET /api/admin/email-templates
 * Returns list of available email templates from emails/templates folder
 */
router.get('/email-templates', authenticateAdmin, async (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');
    
    const templatesPath = path.join(__dirname, '../emails/templates');
    const templates = {};
    
    // Read all template categories (auth, marketing, seller, system, transaction)
    const categories = fs.readdirSync(templatesPath);
    
    for (const category of categories) {
      const categoryPath = path.join(templatesPath, category);
      if (fs.statSync(categoryPath).isDirectory()) {
        templates[category] = [];
        
        const files = fs.readdirSync(categoryPath);
        for (const file of files) {
          if (file.endsWith('.html') || file.endsWith('.js')) {
            const filePath = path.join(categoryPath, file);
            const content = fs.readFileSync(filePath, 'utf8');
            templates[category].push({
              name: file.replace('.html', '').replace('.js', ''),
              category,
              content: content,
              size: content.length
            });
          }
        }
      }
    }
    
    res.json({
      success: true,
      templates: templates
    });
  } catch (error) {
    console.error('Error loading templates:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/admin/send-email
 * Send bulk or individual emails with template support
 * Body: { subject, content, recipients: [{email, username}, ...] }
 * Uses real Nodemailer SMTP for actual email delivery
 */
router.post('/send-email', authenticateAdmin, async (req, res) => {
  try {
    const { subject, content, recipients } = req.body;

    if (!subject || !content || !recipients || recipients.length === 0) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.warn('⚠️ Email credentials not configured in .env');
      return res.status(400).json({ 
        success: false, 
        message: 'Email service not configured. Please set EMAIL_USER and EMAIL_PASS in .env' 
      });
    }

    console.log(`📧 Sending real emails to ${recipients.length} recipients via Nodemailer...`);

    // Send emails using real EmailService with content as-is from frontend
    // Frontend sends either HTML or plain text - emailService will handle it
    const emailResults = await emailService.sendEmailBulk(recipients, subject, content);

    console.log(`✅ Successfully sent ${emailResults.sent} email(s)`);

    res.json({
      success: true,
      message: `Email successfully sent to ${emailResults.sent} recipient(s)`,
      sent: emailResults.sent,
      failed: emailResults.failed,
      results: emailResults.results
    });

  } catch (error) {
    console.error('❌ Email sending error:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send email: ' + error.message,
      error: error.message 
    });
  }
});

module.exports = router;
