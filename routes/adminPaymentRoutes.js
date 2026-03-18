const express = require("express");
const router = express.Router();

// Models
const CoursePayment = require("../models/CoursePayment");
const InstructorEarnings = require("../models/InstructorEarnings");
const InstructorPayout = require("../models/InstructorPayout");
const Course = require("../models/course");
const User = require("../models/userData");

// Middleware
const authenticateJWT = require("./authentication/jwtAuth");
const requireAuth = require("./authentication/reaquireAuth");

// Helper: Check if user is admin
async function isAdmin(userId) {
  const user = await User.findById(userId);
  return user && user.role === "admin";
}

// Middleware: Verify admin access
async function requireAdmin(req, res, next) {
  if (!(await isAdmin(req.user._id))) {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// ====================== PAYMENT ANALYTICS ======================

/**
 * GET /api/admin/payments/analytics
 * Get payment statistics and analytics
 * Auth: Required (Admin only)
 * Query: { fromDate, toDate }
 */
router.get("/payments/analytics", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { fromDate, toDate } = req.query;

    // Build date filter
    const dateFilter = {};
    if (fromDate) {
      dateFilter.$gte = new Date(fromDate);
    }
    if (toDate) {
      dateFilter.$lte = new Date(toDate);
    }

    const match = dateFilter && Object.keys(dateFilter).length > 0 
      ? { createdAt: dateFilter }
      : {};

    // Payment statistics
    const paymentStats = await CoursePayment.aggregate([
      { $match: match },
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
          totalAmount: { $sum: "$amount" },
          totalFees: { $sum: "$platformFee" },
          totalTax: { $sum: "$taxAmount" },
          averageAmount: { $avg: "$amount" },
        },
      },
    ]);

    // Total revenue
    const revenue = await CoursePayment.aggregate([
      { $match: { status: "COMPLETED", ...match } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: "$platformFee" },
          totalStudents: { $sum: 1 },
          totalAmount: { $sum: "$amount" },
          totalInstructorPay: { $sum: "$instructorEarnings" },
        },
      },
    ]);

    // Daily revenue
    const dailyRevenue = await CoursePayment.aggregate([
      { $match: { status: "COMPLETED", ...match } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 },
          amount: { $sum: "$amount" },
          fee: { $sum: "$platformFee" },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    // Payment method distribution
    const paymentMethods = await CoursePayment.aggregate([
      { $match: { status: "COMPLETED", ...match } },
      {
        $group: {
          _id: "$paymentMethod",
          count: { $sum: 1 },
          amount: { $sum: "$amount" },
        },
      },
    ]);

    const statsMap = {};
    paymentStats.forEach((stat) => {
      statsMap[stat._id] = {
        count: stat.count,
        totalAmount: stat.totalAmount,
        totalFees: stat.totalFees,
        totalTax: stat.totalTax,
        averageAmount: stat.averageAmount,
      };
    });

    res.json({
      summary: {
        totalRevenue: revenue[0]?.totalRevenue || 0,
        totalStudents: revenue[0]?.totalStudents || 0,
        totalAmount: revenue[0]?.totalAmount || 0,
        totalInstructorPay: revenue[0]?.totalInstructorPay || 0,
      },
      byStatus: statsMap,
      dailyRevenue: dailyRevenue,
      paymentMethods: paymentMethods,
      generatedAt: new Date(),
    });
  } catch (error) {
    console.error("Analytics error:", error);
    res.status(500).json({ error: "Failed to fetch analytics" });
  }
});

/**
 * GET /api/admin/payments/list
 * Get list of all payments with filters
 * Auth: Required (Admin only)
 * Query: { page, limit, status, courseId, instructorId, studentId }
 */
router.get("/payments/list", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, courseId, instructorId, studentId } = req.query;

    const filter = {};
    if (status) filter.status = status;
    if (courseId) filter.courseId = courseId;
    if (instructorId) filter.instructorId = instructorId;
    if (studentId) filter.studentId = studentId;

    const skip = (page - 1) * limit;

    const payments = await CoursePayment.find(filter)
      .populate("courseId", "title price")
      .populate("instructorId", "name email")
      .populate("studentId", "email username")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await CoursePayment.countDocuments(filter);

    res.json({
      payments: payments,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Payment list error:", error);
    res.status(500).json({ error: "Failed to fetch payments" });
  }
});

// ====================== PAYOUT MANAGEMENT ======================

/**
 * GET /api/admin/payouts/pending
 * Get all pending payouts awaiting approval
 * Auth: Required (Admin only)
 */
router.get("/payouts/pending", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const payouts = await InstructorPayout.find({
      status: "PENDING",
    })
      .populate("instructorId", "name email")
      .sort({ requestedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await InstructorPayout.countDocuments({
      status: "PENDING",
    });

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
    console.error("Pending payouts error:", error);
    res.status(500).json({ error: "Failed to fetch pending payouts" });
  }
});

/**
 * POST /api/admin/payouts/:payoutId/approve
 * Approve a pending payout
 * Auth: Required (Admin only)
 * Body: { remarks? }
 */
router.post("/payouts/:payoutId/approve", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { payoutId } = req.params;
    const { remarks } = req.body;
    const adminId = req.user._id;

    const payout = await InstructorPayout.findById(payoutId);

    if (!payout) {
      return res.status(404).json({ error: "Payout not found" });
    }

    if (payout.status !== "PENDING") {
      return res.status(400).json({
        error: `Cannot approve payout with status: ${payout.status}`,
      });
    }

    // Update payout
    payout.status = "APPROVED";
    payout.approvedBy = adminId;
    payout.approvedAt = new Date();
    payout.remarks = remarks;
    await payout.save();

    res.json({
      success: true,
      message: "Payout approved successfully",
      payoutId: payout._id,
      status: payout.status,
    });
  } catch (error) {
    console.error("Payout approval error:", error);
    res.status(500).json({ error: "Failed to approve payout" });
  }
});

/**
 * POST /api/admin/payouts/:payoutId/reject
 * Reject a pending payout
 * Auth: Required (Admin only)
 * Body: { reason: string }
 */
router.post("/payouts/:payoutId/reject", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { payoutId } = req.params;
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({ error: "Reason is required for rejection" });
    }

    const payout = await InstructorPayout.findById(payoutId);

    if (!payout) {
      return res.status(404).json({ error: "Payout not found" });
    }

    if (payout.status !== "PENDING") {
      return res.status(400).json({
        error: `Cannot reject payout with status: ${payout.status}`,
      });
    }

    // Revert earnings status
    await InstructorEarnings.updateMany(
      { _id: { $in: payout.earningsIncluded } },
      { status: "AVAILABLE", $unset: { payoutId: "" } }
    );

    // Update payout
    payout.status = "CANCELLED";
    payout.failureReason = reason;
    payout.failedAt = new Date();
    await payout.save();

    res.json({
      success: true,
      message: "Payout rejected and cancelled",
      payoutId: payout._id,
    });
  } catch (error) {
    console.error("Payout rejection error:", error);
    res.status(500).json({ error: "Failed to reject payout" });
  }
});

/**
 * GET /api/admin/payouts/processing
 * Get all payouts being processed or completed
 * Auth: Required (Admin only)
 * Query: { status, page, limit }
 */
router.get("/payouts/processing", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { status = "PROCESSING", page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const filter = { status: { $in: ["APPROVED", "PROCESSING", "COMPLETED", "FAILED"] } };
    if (status) {
      filter.status = status;
    }

    const payouts = await InstructorPayout.find(filter)
      .populate("instructorId", "name email")
      .sort({ processedAt: -1 })
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
    console.error("Processing payouts error:", error);
    res.status(500).json({ error: "Failed to fetch processing payouts" });
  }
});

/**
 * POST /api/admin/payouts/:payoutId/process
 * Manually trigger payout processing (normally done by cron)
 * Auth: Required (Admin only)
 * Body: { gatewayPayoutId?, status }
 */
router.post("/payouts/:payoutId/process", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { payoutId } = req.params;
    const { gatewayPayoutId, status } = req.body;

    if (!status || !["PROCESSING", "COMPLETED", "FAILED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status provided" });
    }

    const payout = await InstructorPayout.findById(payoutId);

    if (!payout) {
      return res.status(404).json({ error: "Payout not found" });
    }

    if (payout.status !== "APPROVED") {
      return res.status(400).json({
        error: `Payout must be APPROVED before processing (current: ${payout.status})`,
      });
    }

    // Update payout
    payout.status = status;
    payout.processedAt = new Date();
    payout.gatewayPayoutId = gatewayPayoutId;

    if (status === "COMPLETED") {
      payout.completedAt = new Date();

      // Update all included earnings to PAID
      await InstructorEarnings.updateMany(
        { _id: { $in: payout.earningsIncluded } },
        { status: "PAID", paidAt: new Date() }
      );
    } else if (status === "FAILED") {
      payout.failureReason = "Manual failure mark by admin";
      payout.failedAt = new Date();
    }

    await payout.save();

    res.json({
      success: true,
      message: `Payout marked as ${status}`,
      payoutId: payout._id,
      status: payout.status,
    });
  } catch (error) {
    console.error("Payout processing error:", error);
    res.status(500).json({ error: "Failed to process payout" });
  }
});

/**
 * GET /api/admin/payouts/:payoutId
 * Get detailed payout information
 * Auth: Required (Admin only)
 */
router.get("/payouts/:payoutId", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { payoutId } = req.params;

    const payout = await InstructorPayout.findById(payoutId)
      .populate("instructorId", "name email")
      .populate("approvedBy", "name email")
      .populate("earningsIncluded");

    if (!payout) {
      return res.status(404).json({ error: "Payout not found" });
    }

    // Get earnings details with course info
    const earningsDetails = await InstructorEarnings.find({
      _id: { $in: payout.earningsIncluded },
    }).populate("courseId", "title price");

    res.json({
      payout: payout,
      earningsDetails: earningsDetails,
    });
  } catch (error) {
    console.error("Payout detail error:", error);
    res.status(500).json({ error: "Failed to fetch payout details" });
  }
});

// ====================== REFUND MANAGEMENT ======================

/**
 * POST /api/admin/payments/:paymentId/refund
 * Initiate refund for a payment
 * Auth: Required (Admin only)
 * Body: { reason: string, percentage?: 100 }
 */
router.post("/payments/:paymentId/refund", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { paymentId } = req.params;
    const { reason, percentage = 100 } = req.body;

    if (!reason) {
      return res.status(400).json({ error: "Reason is required for refund" });
    }

    const coursePayment = await CoursePayment.findById(paymentId);

    if (!coursePayment) {
      return res.status(404).json({ error: "Payment not found" });
    }

    if (coursePayment.status !== "COMPLETED") {
      return res.status(400).json({
        error: "Can only refund completed payments",
      });
    }

    // Calculate refund amount
    const refundAmount = Math.round((coursePayment.amount * percentage) / 100);

    // Update payment
    coursePayment.status = "REFUNDED";
    coursePayment.refundedAt = new Date();
    coursePayment.refundReason = reason;
    coursePayment.refundAmount = refundAmount;
    coursePayment.refundPercentage = percentage;
    await coursePayment.save();

    // Remove student from course enrollment
    const course = await Course.findById(coursePayment.courseId);
    if (course) {
      course.enrolledStudents = course.enrolledStudents.filter(
        (id) => id.toString() !== coursePayment.studentId.toString()
      );
      course.enrollCount = Math.max(0, (course.enrollCount || 1) - 1);
      await course.save();
    }

    // Update instructor earnings if applicable
    const earning = await InstructorEarnings.findOne({
      paymentId: paymentId,
    });
    if (earning) {
      // Calculate refund from instructor
      const instructorRefundAmount = Math.round((earning.netEarnings * percentage) / 100);
      
      if (earning.status === "AVAILABLE") {
        // Has not been paid yet - deduct from earnings
        earning.status = "REFUNDED";
        earning.refundAmount = instructorRefundAmount;
        earning.refundReason = reason;
      } else if (earning.status === "PAID") {
        // Already paid - need to reverse it (TODO: create reversal record)
        earning.status = "REFUND_PENDING";
        earning.refundRequest = {
          amount: instructorRefundAmount,
          reason: reason,
          requestedAt: new Date(),
        };
      }
      await earning.save();
    }

    res.json({
      success: true,
      message: "Refund processed successfully",
      paymentId: coursePayment._id,
      refundAmount: refundAmount,
      refundPercentage: percentage,
    });
  } catch (error) {
    console.error("Refund error:", error);
    res.status(500).json({ error: "Failed to process refund" });
  }
});

/**
 * GET /api/admin/refunds/list
 * Get all refunds
 * Auth: Required (Admin only)
 * Query: { page, limit, status }
 */
router.get("/refunds/list", authenticateJWT, requireAuth, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = "REFUNDED" } = req.query;
    const skip = (page - 1) * limit;

    const refunds = await CoursePayment.find({
      status: status,
      refundedAt: { $exists: true },
    })
      .populate("courseId", "title price")
      .populate("studentId", "email username")
      .populate("instructorId", "name email")
      .sort({ refundedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await CoursePayment.countDocuments({
      status: status,
      refundedAt: { $exists: true },
    });

    res.json({
      refunds: refunds,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Refund list error:", error);
    res.status(500).json({ error: "Failed to fetch refunds" });
  }
});

module.exports = router;
