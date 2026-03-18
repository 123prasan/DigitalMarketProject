const express = require("express");
const router = express.Router();

// Models
const InstructorEarnings = require("../models/InstructorEarnings");
const InstructorPayout = require("../models/InstructorPayout");
const CoursePayment = require("../models/CoursePayment");
const User = require("../models/userData");

// Middleware
const authenticateJWT = require("./authentication/jwtAuth");
const requireAuth = require("./authentication/reaquireAuth");

// ====================== INSTRUCTOR EARNINGS ROUTES ======================

/**
 * GET /api/instructor/earnings
 * Get earnings history for authenticated instructor
 * Auth: Required
 * Query: { page, limit, status, sortBy, fromDate, toDate }
 */
router.get("/earnings", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const instructorId = req.user._id;
    const { page = 1, limit = 10, status, sortBy = "createdAt", fromDate, toDate } = req.query;

    // Build filter
    const filter = { instructorId: instructorId };
    if (status) {
      filter.status = status;
    }
    if (fromDate || toDate) {
      filter.createdAt = {};
      if (fromDate) {
        filter.createdAt.$gte = new Date(fromDate);
      }
      if (toDate) {
        filter.createdAt.$lte = new Date(toDate);
      }
    }

    // Build sort
    const sortOptions = {};
    switch (sortBy) {
      case "amount":
        sortOptions.netEarnings = -1;
        break;
      case "date":
        sortOptions.createdAt = -1;
        break;
      default:
        sortOptions.createdAt = -1;
    }

    // Execute query
    const skip = (page - 1) * limit;
    const earnings = await InstructorEarnings.find(filter)
      .populate("paymentId", "studentId createdAt")
      .populate("courseId", "title price")
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await InstructorEarnings.countDocuments(filter);

    // Calculate summary statistics
    const summary = await InstructorEarnings.aggregate([
      { $match: filter },
      {
        $group: {
          _id: "$status",
          totalAmount: { $sum: "$netEarnings" },
          count: { $sum: 1 },
        },
      },
    ]);

    const summaryMap = {};
    summary.forEach((item) => {
      summaryMap[item._id] = {
        total: item.totalAmount,
        count: item.count,
      };
    });

    res.json({
      earnings: earnings,
      summary: summaryMap,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching earnings:", error);
    res.status(500).json({ error: "Failed to fetch earnings" });
  }
});

/**
 * GET /api/instructor/balance
 * Get total available balance for instructor
 * Auth: Required
 */
router.get("/balance", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const instructorId = req.user._id;

    // Get balance by status
    const balance = await InstructorEarnings.aggregate([
      {
        $match: {
          instructorId: instructorId,
        },
      },
      {
        $group: {
          _id: "$status",
          total: { $sum: "$netEarnings" },
        },
      },
    ]);

    const balanceMap = {};
    let totalAvailable = 0;

    balance.forEach((item) => {
      balanceMap[item._id] = item.total;
      if (item._id === "AVAILABLE" || item._id === "PENDING") {
        totalAvailable += item.total;
      }
    });

    // Get pending payouts
    const pendingPayouts = await InstructorPayout.aggregate([
      {
        $match: {
          instructorId: instructorId,
          status: { $in: ["PENDING", "APPROVED", "PROCESSING"] },
        },
      },
      {
        $group: {
          _id: null,
          total: { $sum: "$totalAmount" },
        },
      },
    ]);

    const pendingPayoutAmount = pendingPayouts.length > 0 ? pendingPayouts[0].total : 0;

    res.json({
      balanceByStatus: balanceMap,
      totalAvailable: balanceMap["AVAILABLE"] || 0,
      totalPending: balanceMap["PENDING"] || 0,
      totalPaid: balanceMap["PAID"] || 0,
      pendingPayoutProcessing: pendingPayoutAmount,
      netAvailable: (balanceMap["AVAILABLE"] || 0) - pendingPayoutAmount,
    });
  } catch (error) {
    console.error("Error fetching balance:", error);
    res.status(500).json({ error: "Failed to fetch balance" });
  }
});

/**
 * GET /api/instructor/earnings/:earningId
 * Get detailed information about specific earning
 * Auth: Required
 */
router.get("/earnings/:earningId", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const { earningId } = req.params;
    const instructorId = req.user._id;

    const earning = await InstructorEarnings.findOne({
      _id: earningId,
      instructorId: instructorId,
    })
      .populate("paymentId")
      .populate("courseId", "title price")
      .populate("payoutId");

    if (!earning) {
      return res.status(404).json({ error: "Earning not found" });
    }

    res.json(earning);
  } catch (error) {
    console.error("Error fetching earning:", error);
    res.status(500).json({ error: "Failed to fetch earning" });
  }
});

// ====================== PAYOUT REQUEST ROUTES ======================

/**
 * POST /api/instructor/request-payout
 * Request payout for available earnings
 * Auth: Required
 * Body: { amount?, paymentMethodId?, notes? }
 */
router.post("/request-payout", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const instructorId = req.user._id;
    const { amount, paymentMethodId, notes } = req.body;

    // Get available balance
    const availableEarnings = await InstructorEarnings.find({
      instructorId: instructorId,
      status: "AVAILABLE",
    });

    const totalAvailable = availableEarnings.reduce((sum, e) => sum + e.netEarnings, 0);

    // Determine payout amount
    const payoutAmount = amount || totalAvailable;

    // Validate
    if (payoutAmount <= 0) {
      return res.status(400).json({ error: "Payout amount must be greater than 0" });
    }

    if (payoutAmount > totalAvailable) {
      return res.status(400).json({
        error: "Payout amount exceeds available balance",
        available: totalAvailable,
      });
    }

    // Check minimum threshold
    const minimumThreshold = 500; // Rs 500 minimum
    if (payoutAmount < minimumThreshold) {
      return res.status(400).json({
        error: `Minimum payout amount is Rs ${minimumThreshold}`,
        available: totalAvailable,
      });
    }

    // Create payout request
    const earningsToInclude = [];
    let accumulatedAmount = 0;

    for (const earning of availableEarnings) {
      if (accumulatedAmount >= payoutAmount) {
        break;
      }

      earningsToInclude.push(earning._id);
      accumulatedAmount += earning.netEarnings;
    }

    // Create InstructorPayout document
    const payout = new InstructorPayout({
      instructorId: instructorId,
      totalAmount: payoutAmount,
      earningsIncluded: earningsToInclude,
      earningsCount: earningsToInclude.length,
      paymentMethodId: paymentMethodId,
      status: "PENDING",
      notes: notes,
    });

    await payout.save();

    // Update earnings status to PROCESSING
    await InstructorEarnings.updateMany(
      { _id: { $in: earningsToInclude } },
      { status: "PROCESSING", payoutId: payout._id }
    );

    res.json({
      success: true,
      payoutId: payout.payoutId,
      _id: payout._id,
      amount: payoutAmount,
      earningsCount: earningsToInclude.length,
      status: payout.status,
      requestedAt: payout.requestedAt,
    });
  } catch (error) {
    console.error("Error requesting payout:", error);
    res.status(500).json({ error: "Failed to request payout" });
  }
});

/**
 * GET /api/instructor/payouts
 * Get payout history for instructor
 * Auth: Required
 * Query: { page, limit, status }
 */
router.get("/payouts", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const instructorId = req.user._id;
    const { page = 1, limit = 10, status } = req.query;

    const filter = { instructorId: instructorId };
    if (status) {
      filter.status = status;
    }

    const skip = (page - 1) * limit;

    const payouts = await InstructorPayout.find(filter)
      .populate("paymentMethodId")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await InstructorPayout.countDocuments(filter);

    res.json({
      payouts: payouts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching payouts:", error);
    res.status(500).json({ error: "Failed to fetch payouts" });
  }
});

/**
 * GET /api/instructor/payouts/:payoutId
 * Get detailed payout information
 * Auth: Required
 */
router.get("/payouts/:payoutId", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const { payoutId } = req.params;
    const instructorId = req.user._id;

    const payout = await InstructorPayout.findOne({
      _id: payoutId,
      instructorId: instructorId,
    }).populate("earningsIncluded paymentMethodId approvedBy");

    if (!payout) {
      return res.status(404).json({ error: "Payout not found" });
    }

    // Get detailed earnings info
    const earningsDetails = await InstructorEarnings.find({
      _id: { $in: payout.earningsIncluded },
    }).populate("courseId", "title price");

    res.json({
      payout: payout,
      earningsDetails: earningsDetails,
    });
  } catch (error) {
    console.error("Error fetching payout:", error);
    res.status(500).json({ error: "Failed to fetch payout" });
  }
});

/**
 * POST /api/instructor/payouts/:payoutId/cancel
 * Cancel pending payout request
 * Auth: Required
 */
router.post("/payouts/:payoutId/cancel", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const { payoutId } = req.params;
    const instructorId = req.user._id;

    const payout = await InstructorPayout.findOne({
      _id: payoutId,
      instructorId: instructorId,
    });

    if (!payout) {
      return res.status(404).json({ error: "Payout not found" });
    }

    // Can only cancel pending payouts
    if (payout.status !== "PENDING" && payout.status !== "APPROVED") {
      return res.status(400).json({
        error: `Cannot cancel payout with status: ${payout.status}`,
      });
    }

    // Update payout status
    payout.status = "CANCELLED";
    await payout.save();

    // Revert earnings status back to AVAILABLE
    await InstructorEarnings.updateMany(
      { _id: { $in: payout.earningsIncluded } },
      { status: "AVAILABLE", $unset: { payoutId: "" } }
    );

    res.json({
      success: true,
      message: "Payout cancelled successfully",
      payoutId: payout._id,
    });
  } catch (error) {
    console.error("Error cancelling payout:", error);
    res.status(500).json({ error: "Failed to cancel payout" });
  }
});

module.exports = router;
