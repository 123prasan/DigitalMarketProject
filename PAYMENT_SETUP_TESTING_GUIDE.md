# Payment & Payout System - Setup and Testing Guide

## Quick Start

### 1. Environment Setup

Add these to your `.env` file:

```env
# Razorpay
RAZORPAY_KEY_ID=rzp_live_xxx          # Get from Razorpay dashboard
RAZORPAY_KEY_SECRET=xxx                # Get from Razorpay dashboard
RAZORPAY_WEBHOOK_SECRET=xxx            # Get from webhook setup

# Platform Configuration
PLATFORM_FEE_PERCENTAGE=10             # Platform takes 10%
PLATFORM_TAX_PERCENTAGE=5              # Tax is 5%
MINIMUM_PAYOUT_AMOUNT=500              # Minimum Rs 500 payout
```

### 2. Database Models Setup

All models are already created:
- ✅ [CoursePayment](./models/CoursePayment.js) - Tracks all payments
- ✅ [InstructorEarnings](./models/InstructorEarnings.js) - Tracks instructor income
- ✅ [InstructorPayout](./models/InstructorPayout.js) - Batch payout requests
- ✅ [Course](./models/course.js) - Updated with enrolledStudents[]

### 3. Routes Setup

All routes are already mounted in `server.js`:
- ✅ `/api/payments/*` - Payment initiation and verification
- ✅ `/api/instructor/*` - Instructor earnings and payout management
- ✅ `/api/admin/*` - Admin payment analytics and payout processing

### 4. Frontend Integration

Updated in `views/course-detail.ejs`:
- ✅ Razorpay script loaded
- ✅ `enrollNow()` function implements full payment flow
- ✅ `verifyPayment()` handles signature verification

---

## Testing Payment Flow

### Step 1: Test Razorpay Checkout

1. Go to any course detail page
2. Click "Enroll Now" button
3. Razorpay checkout modal should open

**Expected:**
- Modal shows course name and price
- Student email is pre-filled
- Can select payment method

### Step 2: Test Successful Payment

1. Use Razorpay test card: **4111 1111 1111 1111**
   - Expiry: Any future date (e.g., 12/25)
   - CVV: Any 3 digits (e.g., 123)

2. Complete payment in checkout

**Expected:**
- Payment completes
- Frontend shows "Enrollment successful!"
- Page reloads
- Student is added to course.enrolledStudents

3. Check database:
```javascript
// In MongoDB
db.coursepayments.findOne({ orderId: "order_xxx" })
// Status should be "COMPLETED"

db.instructorearnings.findOne({ paymentId: ObjectId("xxx") })
// Should have netEarnings calculated

db.courses.findOne({ _id: ObjectId("xxx") })
// Should have student in enrolledStudents array
```

### Step 3: Test Failed Payment

1. Use test card: **4000 0000 0000 0002** (Fails)
2. Try to complete payment
3. Should see error message
4. CoursePayment status should be "FAILED"

**Expected Database State:**
```javascript
db.coursepayments.findOne({ status: "FAILED" })
// retryCount: 1
// failureReason: Payment failed
```

---

## Testing Instructor Payout Flow

### Step 1: Instructor Checks Earnings

1. Login as instructor
2. Call API:
```bash
GET /api/instructor/earnings
Authorization: Bearer <JWT_TOKEN>
```

**Response:**
```json
{
  "earnings": [
    {
      "_id": "xxx",
      "courseId": { "title": "Python 101", "price": 999 },
      "grossAmount": 999,
      "platformFeeDeducted": 100,
      "taxDeducted": 50,
      "netEarnings": 849,
      "status": "AVAILABLE",
      "createdAt": "2024-01-15T10:30:00Z"
    }
  ],
  "summary": {
    "AVAILABLE": { "total": 849, "count": 1 }
  }
}
```

### Step 2: Instructor Requests Payout

```bash
POST /api/instructor/request-payout
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "amount": 849,
  "notes": "Monthly earnings"
}
```

**Response:**
```json
{
  "success": true,
  "payoutId": "PAYOUT_1705314600000_abc123",
  "_id": "xxx",
  "amount": 849,
  "earningsCount": 1,
  "status": "PENDING"
}
```

**Check Database:**
```javascript
db.instructorpayouts.findOne({ payoutId: "PAYOUT_xxx" })
// status: "PENDING"
// totalAmount: 849

db.instructorearnings.findOne({ _id: ObjectId("xxx") })
// status: "PROCESSING"
// payoutId: ObjectId("payout_id")
```

### Step 3: Admin Approves Payout

```bash
POST /api/admin/payouts/:payoutId/approve
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "remarks": "Verified and approved"
}
```

**Expected:**
- Payout status: PENDING → APPROVED
- approvedAt: Current timestamp
- approvedBy: Admin user ID

### Step 4: Admin Processes Payout

```bash
POST /api/admin/payouts/:payoutId/process
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json

{
  "status": "COMPLETED",
  "gatewayPayoutId": "payout_abc123"
}
```

**Expected:**
```javascript
db.instructorpayouts.findOne({ _id: ObjectId("xxx") })
// status: "COMPLETED"
// processedAt: Current timestamp
// completedAt: Current timestamp
// gatewayPayoutId: "payout_abc123"

db.instructorearnings.find({ payoutId: ObjectId("xxx") })
// All records status: "PAID"
// paidAt: Current timestamp
```

---

## Testing Admin Analytics

### Get Payment Analytics

```bash
GET /api/admin/payments/analytics?fromDate=2024-01-01&toDate=2024-01-31
Authorization: Bearer <ADMIN_JWT_TOKEN>
```

**Response:**
```json
{
  "summary": {
    "totalRevenue": 5000,
    "totalStudents": 5,
    "totalAmount": 49900,
    "totalInstructorPay": 44900
  },
  "byStatus": {
    "COMPLETED": {
      "count": 5,
      "totalAmount": 49900,
      "totalFees": 5000,
      "totalTax": 2500
    },
    "FAILED": { ... }
  },
  "dailyRevenue": [
    {
      "_id": "2024-01-15",
      "count": 2,
      "amount": 1998,
      "fee": 200
    }
  ]
}
```

### Get Payment List

```bash
GET /api/admin/payments/list?page=1&limit=20&status=COMPLETED
Authorization: Bearer <ADMIN_JWT_TOKEN>
```

---

## Testing Refund Processing

### Admin Initiates Refund

```bash
POST /api/admin/payments/:paymentId/refund
Authorization: Bearer <ADMIN_JWT_TOKEN>
Content-Type: application/json

{
  "reason": "Student requested refund",
  "percentage": 100
}
```

**Effects:**
1. CoursePayment status: COMPLETED → REFUNDED
2. Student removed from course.enrolledStudents
3. Course.enrollCount decremented
4. InstructorEarnings status: AVAILABLE → REFUNDED

**Check Database:**
```javascript
db.coursepayments.findOne({ _id: ObjectId("xxx") })
// status: "REFUNDED"
// refundedAt: Current timestamp
// refundReason: "Student requested refund"
// refundAmount: 999
// refundPercentage: 100

db.instructorearnings.findOne({ paymentId: ObjectId("xxx") })
// status: "REFUNDED"
// refundAmount: 849

db.courses.findOne({ _id: ObjectId("xxx") })
// enrolledStudents does not include student
// enrollCount decreased
```

---

## API Testing with cURL

### Test Payment Initiation

```bash
curl -X POST http://localhost:8080/api/payments/initiate-payment \
  -H "Content-Type: application/json" \
  -H "Cookie: jwt=<YOUR_JWT_TOKEN>" \
  -d '{
    "courseId": "abc123def456"
  }'
```

### Test Payment Verification

```bash
curl -X POST http://localhost:8080/api/payments/verify-payment \
  -H "Content-Type: application/json" \
  -H "Cookie: jwt=<YOUR_JWT_TOKEN>" \
  -d '{
    "orderId": "order_1234567890abc",
    "paymentId": "pay_1234567890abc",
    "signature": "signature_hash_here",
    "paymentDocumentId": "mongodb_id"
  }'
```

### Test Instructor Earnings

```bash
curl -X GET http://localhost:8080/api/instructor/earnings \
  -H "Cookie: jwt=<YOUR_JWT_TOKEN>"
```

### Test Request Payout

```bash
curl -X POST http://localhost:8080/api/instructor/request-payout \
  -H "Content-Type: application/json" \
  -H "Cookie: jwt=<YOUR_JWT_TOKEN>" \
  -d '{
    "amount": 1000,
    "notes": "Monthly withdrawal"
  }'
```

---

## Razorpay Webhook Setup

1. Go to [Razorpay Dashboard](https://dashboard.razorpay.com)
2. Settings → Webhooks
3. Add webhook URL:
   ```
   https://yourdomain.com/api/webhooks/razorpay
   ```
4. Select events:
   - ✅ payment.authorized
   - ✅ payment.failed
   - ✅ order.paid
5. Copy webhook secret to `.env` as `RAZORPAY_WEBHOOK_SECRET`

**Test Webhook:**
```bash
# Razorpay will send test events to your webhook URL
# Check server logs for webhook receipt
# Look for: "Webhook received: payment.authorized"
```

---

## Error Handling Testing

### Test Duplicate Payment Prevention

1. Complete payment
2. Try same course payment again
3. Should show: "You are already enrolled in this course"

### Test Rate Limiting

1. Attempt 5 failed payments in quick succession
2. 6th attempt should be blocked with: "Too many payment attempts"

### Test Invalid Signature

1. Complete payment
2. Manually modify returned signature
3. Should show: "Payment verification failed"

### Test Network Error Recovery

1. Start payment
2. Kill network connection during checkout
3. Retry payment
4. Should not create duplicate payment records

---

## Database Verification Queries

### Check All Payments
```javascript
db.coursepayments.find({}).pretty()
```

### Check Instructor Earnings
```javascript
db.instructorearnings.aggregate([
  { $match: { instructorId: ObjectId("instructor_id") } },
  { $group: { 
      _id: "$status",
      total: { $sum: "$netEarnings" },
      count: { $sum: 1 }
    }
  }
])
```

### Check Payout Status
```javascript
db.instructorpayouts.find({
  status: { $in: ["PENDING", "APPROVED", "PROCESSING"] }
}).pretty()
```

### Calculate Revenue
```javascript
db.coursepayments.aggregate([
  { $match: { status: "COMPLETED" } },
  { $group: {
      _id: null,
      totalRevenue: { $sum: "$platformFee" },
      totalStudents: { $sum: 1 },
      totalAmount: { $sum: "$amount" }
    }
  }
])
```

### Find Enrolled Students
```javascript
db.courses.findOne({ _id: ObjectId("course_id") })
  .enrolledStudents
```

---

## Production Checklist

- [ ] Razorpay account created and API keys obtained
- [ ] Environment variables configured (KEY_ID, KEY_SECRET, WEBHOOK_SECRET)
- [ ] Webhook URL registered in Razorpay dashboard
- [ ] Database models migrated with enrolledStudents field
- [ ] All routes mounted in server.js
- [ ] HTTPS enabled for payment endpoints
- [ ] Rate limiting implemented for payment endpoints
- [ ] Error logs configured for payment failures
- [ ] Email notifications configured (payment confirmation, payout approval)
- [ ] Cron job configured for automatic payout processing
- [ ] Admin dashboard created for payment monitoring
- [ ] Refund policy documented for users
- [ ] PCI compliance verification completed
- [ ] Payment page tested with real Razorpay keys
- [ ] Webhook signature verification working
- [ ] All payment states tested (success, failure, retry, refund)

---

## Troubleshooting

### Payment Stuck in INITIATED Status

**Cause:** Webhook not received or processing failed
**Solution:**
1. Check Razorpay dashboard for payment status
2. Verify webhook URL is accessible
3. Check server logs for webhook receipt
4. Manually process payment: `POST /api/admin/payouts/{id}/process`

### Instructor Can't See Earnings

**Cause:** Payment status not COMPLETED
**Solution:**
1. Check CoursePayment collection for status
2. Verify signature verification passed
3. Check webhook logs for failures
4. Run manual verification if needed

### Payout Fails to Process

**Cause:** Instructor bank account not verified
**Solution:**
1. Ask instructor to verify bank account in Razorpay
2. Use test mode to verify integration
3. Check Razorpay API response for specific error

### Student Can't Enroll Multiple Courses

**Cause:** Checking same courseId restriction
**Solution:**
1. Verify course IDs are different
2. Check Course.enrolledStudents array
3. Remove student and retry if data is corrupted

---

## Next Steps

1. **Email Integration**
   - Send payment confirmation to student
   - Send earnings notification to instructor
   - Send payout approval notification

2. **Dashboard Pages**
   - Instructor earnings dashboard
   - Admin payment analytics dashboard
   - Payment history for students

3. **Compliance**
   - Implement PCI DSS compliance
   - Add GDPR data handling
   - Create invoice generation

4. **Advanced Features**
   - Refund automation (7-day no-questions refund)
   - Recurring subscription courses
   - Affiliate commission tracking
   - Multi-currency support

