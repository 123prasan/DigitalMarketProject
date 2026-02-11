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
const dayjs = require('dayjs');

// Middleware to check if user is authenticated admin
const authenticateAdmin = require('./authentication/reaquireAuth');

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

    // Calculate metrics
    const totalOrders = ordersCurrent.length;
    const failedOrders = ordersCurrent.filter((o) =>
      o.status.toLowerCase().includes('unsuccessfull')
    ).length;
    const successfulOrders = ordersCurrent.filter((o) =>
      o.status.toLowerCase().includes('successfull')
    ).length;

    // Calculate trends
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
        totalOrders,
        totalOrdersTrend: calcTrend(totalOrders, ordersPrev.length),
        failedOrders,
        failedOrdersTrend: calcTrend(failedOrders, 
          ordersPrev.filter(o => o.status.toLowerCase().includes('unsuccessfull')).length),
        successfulOrders,
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

    res.json({
      success: true,
      files,
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
 * DELETE /api/admin/orders/:id
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
router.delete('/files/:fileId', authenticateAdmin, async (req, res) => {
  try {
    const { fileId } = req.params;
    const result = await File.findByIdAndDelete(fileId);
    
    if (!result) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    res.json({ success: true, message: 'File deleted successfully' });
  } catch (error) {
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

module.exports = router;
