const express = require("express");
const router = express.Router();
const Razorpay = require("razorpay");
const crypto = require("crypto");

// Models
const Course = require("../models/course");
const CoursePayment = require("../models/CoursePayment");
const InstructorEarnings = require("../models/InstructorEarnings");
const InstructorPayout = require("../models/InstructorPayout");
const User = require("../models/userData");
const UserPurchase = require("../models/userPerchase");
const UserTransaction = require("../models/userTransactions");
const UserBal = require("../models/userBalance");
const Order = require("../models/Order");

// Middleware
const authenticateJWT = require("./authentication/jwtAuth");
const requireAuth = require("./authentication/reaquireAuth");

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ====================== PAYMENT ROUTES ======================

/**
 * POST /api/payments/initiate-payment
 * Initiate payment for course enrollment
 * Body: { courseId }
 * Auth: Required
 */
router.post("/initiate-payment", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const { courseId } = req.body;
    const studentId = req.user._id;

    // Validate input
    if (!courseId) {
      return res.status(400).json({ error: "courseId is required" });
    }

    // Fetch course
    const course = await Course.findById(courseId).populate("userId", "email name");
    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    // Check if user already enrolled
    const enrollmentCheck = await Course.findOne({
      _id: courseId,
      enrolledStudents: studentId,
    });
    if (enrollmentCheck) {
      return res.status(400).json({ error: "You are already enrolled in this course" });
    }

    // Validate course price
    const price = course.price || 0;
    if (price <= 0) {
      return res.status(400).json({ error: "Course is not available for purchase" });
    }

    // Calculate amount (in paise for Razorpay)
    const amount = Math.round(price * 100); // Convert to paise

    // Create Razorpay order
    const orderOptions = {
      amount: amount,
      currency: "INR",
      receipt: `ORD${Date.now().toString().slice(-14)}`,  // Max 40 chars: "ORD" + last 14 of timestamp
      payment_capture: 1,
      notes: {
        courseId: courseId.toString(),
        studentId: studentId.toString(),
        courseName: course.title,
        coursePrice: price,
      },
    };

    const razorpayOrder = await razorpay.orders.create(orderOptions);

    // Create CoursePayment record
    const coursePayment = new CoursePayment({
      courseId: courseId,
      instructorId: course.userId._id,
      studentId: studentId,
      amount: price,
      finalAmount: price,
      orderId: razorpayOrder.id,
      paymentGateway: "RAZORPAY",
      status: "INITIATED",
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

    await coursePayment.save();

    // Return order details to frontend
    res.json({
      success: true,
      orderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency,
      keyId: process.env.RAZORPAY_KEY_ID,
      studentName: req.user.name || req.user.email,
      studentEmail: req.user.email,
      courseName: course.title,
      courseId: courseId,
      paymentId: coursePayment._id,
    });
  } catch (error) {
    console.error("Payment initiation error:", error);
    res.status(500).json({ error: "Failed to initiate payment", details: error.message });
  }
});

/**
 * POST /api/payments/verify-payment
 * Verify payment signature and complete payment
 * Body: { orderId, paymentId: razorpayPaymentId, signature, paymentDocumentId }
 * Auth: Required
 */
router.post("/verify-payment", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const { orderId, paymentId: razorpayPaymentId, signature, paymentDocumentId } = req.body;
    const studentId = req.user._id;

    // Validate input
    if (!orderId || !razorpayPaymentId || !signature) {
      return res.status(400).json({ error: "Missing payment details" });
    }

    // Fetch CoursePayment record
    const coursePayment = await CoursePayment.findOne({
      orderId: orderId,
      studentId: studentId,
    }).populate("courseId instructorId");

    if (!coursePayment) {
      return res.status(404).json({ error: "Payment record not found" });
    }

    // Verify signature
    const body = orderId + "|" + razorpayPaymentId;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest("hex");

    if (expectedSignature !== signature) {
      // Signature verification failed
      await coursePayment.markAsFailed("Signature verification failed", "INVALID_SIGNATURE");
      return res.status(400).json({ error: "Payment verification failed" });
    }

    // Mark signature as verified
    coursePayment.signatureVerified = true;

    // Update payment status
    coursePayment.status = "PROCESSING";
    coursePayment.paymentId = razorpayPaymentId;
    await coursePayment.save();

    // Fetch course details
    const course = await Course.findById(coursePayment.courseId);

    // Fetch instructor to check Pro status
    const instructor = await User.findById(coursePayment.instructorId);

    // Calculate platform fee and instructor earnings based on Pro status
    let platformFeePercentage = 0.30; // Default: 30% to platform
    if (instructor && instructor.isPro) {
      platformFeePercentage = 0.10; // Pro: 10% to platform
    }

    const platformFee = coursePayment.finalAmount * platformFeePercentage;
    const instructorEarningsAmount = coursePayment.finalAmount - platformFee;

    // Update coursePayment with calculated values
    coursePayment.platformFeePercentage = platformFeePercentage * 100; // Store as percentage
    coursePayment.platformFee = platformFee;
    coursePayment.instructorEarnings = instructorEarningsAmount;
    await coursePayment.save();

    // Create enrollment record
    if (!course.enrolledStudents.includes(studentId)) {
      course.enrolledStudents.push(studentId);
      course.enrollCount = (course.enrollCount || 0) + 1;
      await course.save();
    }

    // Create InstructorEarnings record
    const instructorEarnings = new InstructorEarnings({
      paymentId: coursePayment._id,
      instructorId: coursePayment.instructorId,
      courseId: coursePayment.courseId,
      courseTitle: course.title,
      grossAmount: coursePayment.amount,
      platformFeeDeducted: coursePayment.platformFee,
      taxDeducted: coursePayment.taxAmount,
      netEarnings: coursePayment.instructorEarnings,
      status: "PENDING",
    });

    await instructorEarnings.save();

    // Create UserPurchase record (for student's purchase history)
    await UserPurchase.create({
      userId: studentId,
      productId: coursePayment.courseId,
      productName: course.title,
      price: coursePayment.amount,
      quantity: 1,
      totalPrice: coursePayment.finalAmount,
      productType: "Course",
      status: "completed",
      purchaseDate: new Date(),
      purchaseId: razorpayPaymentId,
    });

    // Create UserTransaction record (for instructor's earnings dashboard)
    await UserTransaction.create({
      ProductName: course.title,
      ProductId: coursePayment.courseId.toString(),
      userId: coursePayment.instructorId, // Seller/instructor
      purchaserId: studentId, // Buyer/student
      status: "Completed",
      totalAmount: coursePayment.instructorEarnings || coursePayment.amount,
      discount: 0,
      transactionId: razorpayPaymentId,
    });

    // Create Order record (for order history/dashboard)
    await Order.findOneAndUpdate(
      { orderId: orderId },
      {
        orderId: orderId,
        transactionId: razorpayPaymentId,
        customer: req.user.email || "Online Customer",
        payment: "RAZORPAY",
        total: coursePayment.finalAmount,
        productId: coursePayment.courseId.toString(),
        productName: course.title,
        items: [{ name: course.title, quantity: 1, price: coursePayment.amount }],
        status: "Successfull",
        dateTime: new Date(),
      },
      { upsert: true, new: true }
    );

    // Update instructor's balance
    await UserBal.findOneAndUpdate(
      { UserId: coursePayment.instructorId.toString() },
      { 
        $inc: { Balance: coursePayment.instructorEarnings || coursePayment.amount },
        prevBal: 0
      },
      { upsert: true, new: true }
    );

    // Mark payment as completed
    coursePayment.status = "COMPLETED";
    coursePayment.completedAt = new Date();
    await coursePayment.save();

    // TODO: Queue email notifications
    // - Send enrollment confirmation to student
    // - Send earnings notification to instructor
    // - Queue payout if instructor balance > threshold

    res.json({
      success: true,
      message: "Payment verified successfully",
      courseId: coursePayment.courseId,
      orderId: orderId,
      paymentId: razorpayPaymentId,
      redirect: "/my-courses"
    });
  } catch (error) {
    console.error("Payment verification error:", error);
    res.status(500).json({ error: "Payment verification failed", details: error.message });
  }
});

/**
 * POST /api/webhooks/razorpay
 * Razorpay webhook for payment events
 * No auth required - Razorpay sends this directly
 */
router.post("/webhooks/razorpay", async (req, res) => {
  try {
    const event = req.body;
    const signature = req.headers["x-razorpay-signature"];

    // Verify webhook signature
    const body = JSON.stringify(event);
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
      .update(body)
      .digest("hex");

    if (expectedSignature !== signature) {
      console.warn("Invalid webhook signature");
      return res.status(400).json({ error: "Invalid signature" });
    }

    // Handle different event types
    switch (event.event) {
      case "payment.authorized":
        await handlePaymentAuthorized(event.payload.payment.entity);
        break;
      case "payment.failed":
        await handlePaymentFailed(event.payload.payment.entity);
        break;
      case "order.paid":
        await handleOrderPaid(event.payload.order.entity);
        break;
      default:
        console.log("Unhandled event type:", event.event);
    }

    // Always respond with 200 to acknowledge receipt
    res.json({ success: true });
  } catch (error) {
    console.error("Webhook error:", error);
    // Still respond with 200 to prevent Razorpay retries
    res.status(200).json({ error: "Webhook processed" });
  }
});

/**
 * GET /api/payments/status/:orderId
 * Check payment status
 * Auth: Required
 */
router.get("/status/:orderId", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const { orderId } = req.params;
    const studentId = req.user._id;

    const coursePayment = await CoursePayment.findOne({
      orderId: orderId,
      studentId: studentId,
    }).populate("courseId");

    if (!coursePayment) {
      return res.status(404).json({ error: "Payment not found" });
    }

    res.json({
      status: coursePayment.status,
      amount: coursePayment.amount,
      finalAmount: coursePayment.finalAmount,
      courseId: coursePayment.courseId._id,
      courseName: coursePayment.courseId.title,
      createdAt: coursePayment.createdAt,
      completedAt: coursePayment.completedAt,
    });
  } catch (error) {
    console.error("Payment status error:", error);
    res.status(500).json({ error: "Failed to fetch payment status" });
  }
});

/**
 * GET /api/payments/history
 * Get payment history for current user
 * Auth: Required
 */
router.get("/history", authenticateJWT, requireAuth, async (req, res) => {
  try {
    const studentId = req.user._id;
    const { page = 1, limit = 10 } = req.query;

    const skip = (page - 1) * limit;

    const payments = await CoursePayment.find({
      studentId: studentId,
    })
      .populate("courseId", "title price thumbnailUrl")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await CoursePayment.countDocuments({
      studentId: studentId,
    });

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
    console.error("Payment history error:", error);
    res.status(500).json({ error: "Failed to fetch payment history" });
  }
});

// ====================== HELPER FUNCTIONS ======================

/**
 * Handle payment.authorized event from Razorpay
 */
async function handlePaymentAuthorized(paymentData) {
  try {
    const orderId = paymentData.order_id;
    const paymentId = paymentData.id;

    const coursePayment = await CoursePayment.findOne({
      orderId: orderId,
    });

    if (!coursePayment) {
      console.warn("CoursePayment not found for order:", orderId);
      return;
    }

    coursePayment.paymentId = paymentId;
    coursePayment.status = "PROCESSING";
    await coursePayment.save();

    console.log("Payment authorized:", paymentId);
  } catch (error) {
    console.error("Error handling payment authorized:", error);
  }
}

/**
 * Handle payment.failed event from Razorpay
 */
async function handlePaymentFailed(paymentData) {
  try {
    const orderId = paymentData.order_id;
    const reason = paymentData.description || "Payment failed";

    const coursePayment = await CoursePayment.findOne({
      orderId: orderId,
    });

    if (!coursePayment) {
      console.warn("CoursePayment not found for order:", orderId);
      return;
    }

    await coursePayment.markAsFailed(reason, paymentData.error_code || "UNKNOWN");
    console.log("Payment failed:", orderId, reason);
  } catch (error) {
    console.error("Error handling payment failed:", error);
  }
}

/**
 * Handle order.paid event from Razorpay
 */
async function handleOrderPaid(orderData) {
  try {
    const orderId = orderData.id;

    const coursePayment = await CoursePayment.findOne({
      orderId: orderId,
    }).populate("courseId instructorId studentId");

    if (!coursePayment) {
      console.warn("CoursePayment not found for order:", orderId);
      return;
    }

    // Mark as completed
    coursePayment.status = "COMPLETED";
    coursePayment.completedAt = new Date();
    await coursePayment.save();

    // Enroll student
    const course = coursePayment.courseId;
    if (!course.enrolledStudents.includes(coursePayment.studentId._id)) {
      course.enrolledStudents.push(coursePayment.studentId._id);
      course.enrollCount = (course.enrollCount || 0) + 1;
      await course.save();
    }

    // Create instructor earnings
    const instructorEarnings = new InstructorEarnings({
      paymentId: coursePayment._id,
      instructorId: coursePayment.instructorId._id,
      courseId: coursePayment.courseId._id,
      courseTitle: course.title,
      grossAmount: coursePayment.amount,
      platformFeeDeducted: coursePayment.platformFee,
      taxDeducted: coursePayment.taxAmount,
      netEarnings: coursePayment.instructorEarnings,
      status: "AVAILABLE",
    });

    await instructorEarnings.save();

    console.log("Order paid - enrollment completed:", orderId);
  } catch (error) {
    console.error("Error handling order paid:", error);
  }
}

module.exports = router;
