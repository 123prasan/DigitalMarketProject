# Payment and Payout System - Complete Documentation

## Architecture Overview

### Core Models

#### 1. **CoursePayment** (models/CoursePayment.js)
Tracks every payment transaction for course purchases.

**Key Fields:**
- `paymentId`: Razorpay payment ID
- `orderId`: Razorpay order ID
- `courseId`, `instructorId`, `studentId`: References
- `amount`: Original course price
- `finalAmount`: Amount after discounts
- `platformFee`: Platform commission (10% default)
- `taxAmount`: Tax (5% default)
- `instructorEarnings`: Net amount for instructor
- `status`: PENDING → INITIATED → PROCESSING → COMPLETED
- `signatureVerified`: Boolean for payment authentication
- `retryCount`, `maxRetries`: Retry logic for failed payments

**Key Methods:**
- `verifySignature()`: Validate Razorpay webhook signature
- `markAsCompleted()`: Update to COMPLETED status
- `markAsFailed()`: Update to FAILED with retry logic
- `canRetry()`: Check if payment can be retried

---

#### 2. **InstructorEarnings** (models/InstructorEarnings.js)
Tracks instructor income from each course sale.

**Key Fields:**
- `paymentId`: Reference to CoursePayment
- `instructorId`: Instructor who created course
- `courseId`: Sold course
- `grossAmount`: Total sale amount
- `platformFeeDeducted`: Platform commission deducted
- `taxDeducted`: Tax amount
- `netEarnings`: Amount instructor receives
- `status`: PENDING → AVAILABLE → PROCESSING → PAID
- `payoutId`: Links to InstructorPayout when included in batch

**Use Case:**
Created automatically when payment is verified. Tracks instructor's share of each sale.

---

#### 3. **InstructorPayout** (models/InstructorPayout.js)
Batch payout requests from instructors to withdraw earnings.

**Key Fields:**
- `payoutId`: Unique payout identifier
- `instructorId`: Instructor requesting payout
- `totalAmount`: Total amount in this payout
- `earningsIncluded[]`: Array of InstructorEarnings IDs
- `status`: PENDING → APPROVED → PROCESSING → COMPLETED
- `paymentGateway`: RAZORPAY, BANK_TRANSFER, UPI, STRIPE
- `gatewayPayoutId`: Payout ID from payment gateway
- `failureReason`, `failureCode`: Error tracking
- `retryCount`, `maxRetries`: Retry logic

**Key Methods:**
- `isEligibleForProcessing()`: Check if ready for payout
- `markAsCompleted()`: Complete with gateway payout ID
- `markAsFailed()`: Mark failed with reason and retry schedule

---

## API Routes

### Payment Routes (`/api/payments/`)

#### 1. Initiate Payment
```
POST /api/payments/initiate-payment
Auth: Required (JWT)
Body: { courseId: ObjectId }

Response:
{
  success: true,
  orderId: "order_xxx",          // Razorpay order ID
  amount: 99900,                 // In paise
  currency: "INR",
  keyId: "rzp_live_xxx",         // Client-side Razorpay key
  studentName: "John Doe",
  studentEmail: "john@example.com",
  courseName: "Python 101",
  courseId: "xxx",
  paymentId: "xxx"               // MongoDB CoursePayment ID
}

Process Flow:
1. Fetch course details + validate price
2. Check if student already enrolled
3. Create Razorpay order via API
4. Create CoursePayment record (INITIATED status)
5. Return order details for frontend checkout
```

#### 2. Verify Payment
```
POST /api/payments/verify-payment
Auth: Required (JWT)
Body: {
  orderId: "order_xxx",
  paymentId: "pay_xxx",          // Razorpay payment ID
  signature: "hash_xxx",         // Razorpay signature
  paymentDocumentId: "xxx"       // MongoDB CoursePayment ID
}

Response:
{
  success: true,
  message: "Payment verified successfully",
  courseId: "xxx",
  orderId: "order_xxx",
  paymentId: "pay_xxx"
}

Process Flow:
1. Fetch CoursePayment record
2. Verify Razorpay signature
3. Update CoursePayment status to PROCESSING
4. Add student to course.enrolledStudents
5. Create InstructorEarnings record
6. Mark CoursePayment as COMPLETED
7. Queue email notifications
8. Check if instructor payout threshold reached
```

#### 3. Get Payment Status
```
GET /api/payments/status/:orderId
Auth: Required (JWT)

Response:
{
  status: "COMPLETED",
  amount: 999,
  finalAmount: 999,
  courseId: "xxx",
  courseName: "Python 101",
  createdAt: "2024-01-15T10:30:00Z",
  completedAt: "2024-01-15T10:35:00Z"
}
```

#### 4. Get Payment History
```
GET /api/payments/history?page=1&limit=10
Auth: Required (JWT)

Response:
{
  payments: [
    {
      _id: "xxx",
      status: "COMPLETED",
      amount: 999,
      courseId: { title: "Python 101", price: 999 },
      createdAt: "2024-01-15T10:30:00Z"
    }
  ],
  pagination: {
    page: 1,
    limit: 10,
    total: 25,
    pages: 3
  }
}
```

#### 5. Razorpay Webhook
```
POST /api/webhooks/razorpay
Auth: None (Razorpay validates signature)

Headers: x-razorpay-signature

Handles Events:
- payment.authorized: Update CoursePayment status
- payment.failed: Mark as failed with retry logic
- order.paid: Complete enrollment and create earnings

Process Flow:
1. Verify Razorpay webhook signature
2. Handle event type (authorized/failed/paid)
3. Update database accordingly
4. Always respond with 200 OK to acknowledge
```

---

### Instructor Routes (`/api/instructor/`)

#### 1. Get Earnings Summary
```
GET /api/instructor/earnings?page=1&limit=10&status=AVAILABLE&sortBy=date&fromDate=2024-01-01&toDate=2024-01-31
Auth: Required (JWT)

Query Parameters:
- page: Pagination page (default: 1)
- limit: Results per page (default: 10)
- status: Filter by status (PENDING, AVAILABLE, PROCESSING, PAID)
- sortBy: Sort field (createdAt, amount)
- fromDate, toDate: Date range filter

Response:
{
  earnings: [
    {
      _id: "xxx",
      courseId: { title: "Python 101", price: 999 },
      grossAmount: 999,
      platformFeeDeducted: 100,
      taxDeducted: 50,
      netEarnings: 849,
      status: "AVAILABLE",
      createdAt: "2024-01-15T10:30:00Z"
    }
  ],
  summary: {
    "AVAILABLE": { total: 5000, count: 5 },
    "PAID": { total: 10000, count: 10 }
  },
  pagination: { page: 1, limit: 10, total: 25, pages: 3 }
}
```

#### 2. Get Account Balance
```
GET /api/instructor/balance
Auth: Required (JWT)

Response:
{
  balanceByStatus: {
    "AVAILABLE": 5000,
    "PENDING": 2000,
    "PAID": 50000
  },
  totalAvailable: 5000,       // Can request payout
  totalPending: 2000,          // Processing by platform
  totalPaid: 50000,            // Withdrawn
  pendingPayoutProcessing: 1000, // In active payout batch
  netAvailable: 4000           // Available - pending batches
}
```

#### 3. Get Specific Earning
```
GET /api/instructor/earnings/:earningId
Auth: Required (JWT)

Response:
{
  _id: "xxx",
  paymentId: { ... },          // Full CoursePayment details
  courseId: { title: "Python 101", price: 999 },
  grossAmount: 999,
  platformFeeDeducted: 100,
  taxDeducted: 50,
  netEarnings: 849,
  status: "AVAILABLE",
  payoutId: null,              // null if not included in payout
  createdAt: "2024-01-15T10:30:00Z",
  updatedAt: "2024-01-15T10:30:00Z"
}
```

#### 4. Request Payout
```
POST /api/instructor/request-payout
Auth: Required (JWT)
Body: {
  amount?: 5000,               // Optional: specific amount (default: all available)
  paymentMethodId?: "xxx",     // Optional: payment method ID
  notes?: "Monthly withdrawal" // Optional: notes
}

Validation:
- Minimum amount: Rs 500
- Cannot exceed available balance
- Minimum threshold check

Response:
{
  success: true,
  payoutId: "PAYOUT_1705314600000_abc123",
  _id: "xxx",
  amount: 5000,
  earningsCount: 5,
  status: "PENDING",
  requestedAt: "2024-01-15T10:30:00Z"
}

Process Flow:
1. Get all earnings with status AVAILABLE
2. Calculate total available
3. Validate amount (min 500, max available)
4. Select earnings to include (FIFO)
5. Create InstructorPayout record
6. Update selected earnings to PROCESSING status
7. Admin will APPROVE and process payout
```

#### 5. Get Payout History
```
GET /api/instructor/payouts?page=1&limit=10&status=COMPLETED
Auth: Required (JWT)

Query Parameters:
- page: Pagination page
- limit: Results per page
- status: Filter (PENDING, APPROVED, PROCESSING, COMPLETED, FAILED, CANCELLED)

Response:
{
  payouts: [
    {
      payoutId: "PAYOUT_1705314600000_abc123",
      totalAmount: 5000,
      status: "COMPLETED",
      requestedAt: "2024-01-15T10:30:00Z",
      completedAt: "2024-01-15T11:00:00Z",
      gatewayPayoutId: "payout_xxx",
      approvedBy: { ... }
    }
  ],
  pagination: { page: 1, limit: 10, total: 15, pages: 2 }
}
```

#### 6. Get Payout Details
```
GET /api/instructor/payouts/:payoutId
Auth: Required (JWT)

Response:
{
  payout: {
    payoutId: "PAYOUT_1705314600000_abc123",
    totalAmount: 5000,
    earningsCount: 5,
    status: "COMPLETED",
    requestedAt: "2024-01-15T10:30:00Z",
    approvedAt: "2024-01-15T10:45:00Z",
    processedAt: "2024-01-15T10:50:00Z",
    completedAt: "2024-01-15T11:00:00Z",
    gatewayPayoutId: "payout_xxx",
    failureReason: null,
    notes: "Monthly withdrawal"
  },
  earningsDetails: [
    {
      courseId: { title: "Python 101", price: 999 },
      grossAmount: 999,
      netEarnings: 849,
      courseTitle: "Python 101"
    }
  ]
}
```

#### 7. Cancel Payout Request
```
POST /api/instructor/payouts/:payoutId/cancel
Auth: Required (JWT)

Conditions:
- Can only cancel PENDING or APPROVED payouts
- Cannot cancel PROCESSING, COMPLETED, or FAILED

Response:
{
  success: true,
  message: "Payout cancelled successfully",
  payoutId: "xxx"
}

Process Flow:
1. Fetch payout record
2. Validate status is PENDING or APPROVED
3. Update payout status to CANCELLED
4. Revert all included earnings back to AVAILABLE
5. Return confirmation
```

---

## Payment Flow Diagram

```
Student Side:
1. Click "Enroll Now"
   ↓
2. Frontend calls /api/payments/initiate-payment
   ↓
3. Backend creates CoursePayment (INITIATED)
   ↓
4. Backend creates Razorpay order
   ↓
5. Returns orderId + amount to frontend
   ↓
6. Razorpay checkout opens
   ↓
7. Student completes payment
   ↓
8. Razorpay returns to frontend with signature
   ↓
9. Frontend calls /api/payments/verify-payment
   ↓
10. Backend verifies signature
    ↓
11. Updates CoursePayment to COMPLETED
    ↓
12. Adds student to course enrollment
    ↓
13. Creates InstructorEarnings record
    ↓
14. Student has course access ✅
```

---

## Payout Flow Diagram

```
Instructor Side - Withdrawal Request:
1. Instructor views earnings dashboard
   ↓
2. Views available balance
   ↓
3. Clicks "Request Payout"
   ↓
4. Selects amount (min Rs 500)
   ↓
5. Frontend calls /api/instructor/request-payout
   ↓
6. Backend creates InstructorPayout (PENDING)
   ↓
7. Updates selected earnings to PROCESSING
   ↓
8. Confirmation shown to instructor

Admin Side - Payout Processing:
1. Admin views pending payouts dashboard
   ↓
2. Reviews payout requests
   ↓
3. Approves payout (updates status: APPROVED)
   ↓
4. Cron job processes approved payouts
   ↓
5. Cron calls payment gateway (Razorpay payout API)
   ↓
6. Receives payout ID from gateway
   ↓
7. Updates InstructorPayout to PROCESSING
   ↓
8. Monitors payout status
   ↓
9. When confirmed by gateway: COMPLETED
   ↓
10. Updates all included earnings to PAID
    ↓
11. Instructor receives funds in bank account ✅
```

---

## Security Considerations

### Payment Security

1. **Signature Verification**
   - Always verify Razorpay signature before marking payment as complete
   - Use: `crypto.createHmac('sha256', secret).update(body).digest('hex')`
   - Compare with provided signature

2. **Amount Verification**
   - Never trust amount from frontend
   - Always fetch course details and validate price on backend
   - Check finalAmount matches received amount

3. **User Verification**
   - Always verify student ID from JWT token
   - Never accept studentId from request body
   - Prevent same user from purchasing multiple times

4. **Idempotency**
   - PaymentId is unique - handles duplicate webhook calls
   - Verify payment hasn't been processed before updating

### Payout Security

1. **IP Tracking**
   - Log IP address of payment initiation
   - Compare with payout IP for fraud detection

2. **Rate Limiting**
   - Limit payout requests per instructor per day
   - Limit payment attempts per course per user

3. **Minimum Thresholds**
   - Minimum payout of Rs 500 prevents micro-transactions
   - Reduces payment gateway fees on small transfers

4. **Audit Trail**
   - Log all payment and payout actions
   - Record admin approvals
   - Track failures and retries

---

## Error Handling

### Payment Failures

```javascript
// Automatic Retry Logic
if (payment.status === "FAILED") {
  if (payment.canRetry()) {
    // Increment retryCount
    // Schedule retry after delay
    // Send notification to student: "Payment failed, please try again"
  } else {
    // Max retries exceeded
    // Mark as CANCELLED
    // Send notification: "Payment failed after multiple attempts"
  }
}
```

### Webhook Failures

```javascript
// If webhook fails, Razorpay retries with exponential backoff
// Your webhook must:
// 1. Always respond with 200 OK
// 2. Handle duplicate events gracefully
// 3. Check if payment already processed before updating
// 4. Log all webhook calls for debugging
```

---

## Testing Checklist

### Payment Flow
- [ ] Student clicks Enroll Now
- [ ] Razorpay checkout opens
- [ ] Payment success redirects properly
- [ ] Payment failure shows error message
- [ ] CoursePayment record created
- [ ] InstructorEarnings record created
- [ ] Student added to course enrollment
- [ ] Webhook receives payment.authorized event

### Payout Flow
- [ ] Instructor can view earnings
- [ ] Balance calculation is correct
- [ ] Instructor can request payout
- [ ] Payout shown as PENDING
- [ ] Admin can approve payout
- [ ] Cron job processes payouts
- [ ] Instructor receives funds
- [ ] Earnings marked as PAID

### Error Scenarios
- [ ] Payment fails - retry logic works
- [ ] Duplicate webhook - handles gracefully
- [ ] Invalid signature - rejects payment
- [ ] Payout below minimum - shows error
- [ ] Insufficient balance - shows error
- [ ] Network error - proper error messages

---

## Configuration (Environment Variables)

```env
# Razorpay
RAZORPAY_KEY_ID=rzp_live_xxx
RAZORPAY_KEY_SECRET=xxx
RAZORPAY_WEBHOOK_SECRET=xxx

# Platform Configuration
PLATFORM_FEE_PERCENTAGE=10        # 10% platform commission
PLATFORM_TAX_PERCENTAGE=5          # 5% tax
MINIMUM_PAYOUT_AMOUNT=500          # Min Rs 500
PAYOUT_BATCH_LIMIT=100000          # Max per batch
PAYOUT_PROCESSING_DAY=5            # Day of month to process
```

---

## Future Enhancements

1. **Multiple Payment Gateways**
   - Stripe, PayPal, Apple Pay, Google Pay

2. **Refund Processing**
   - Auto-refund if course not started within 7 days
   - Manual refund by admin for support cases

3. **Subscription Courses**
   - Monthly recurring payments
   - Automatic enrollment renewal

4. **Affiliate System**
   - Referral commissions
   - Partner payouts

5. **Advanced Analytics**
   - Revenue dashboard for instructors
   - Course performance metrics
   - Student conversion tracking

6. **Automated Payouts**
   - Weekly/monthly automatic payouts above threshold
   - Bank account speed verification
   - Instant payouts for premium instructors

7. **Compliance**
   - PCI DSS compliance
   - GDPR data handling
   - Tax form generation
   - 1099 reporting for US instructors
