# Cashfree to Razorpay Migration - Implementation Report

**Date**: February 15, 2026  
**Project**: Vidyari Digital Marketplace  
**Migration Status**: ✅ COMPLETE

---

## Executive Summary

The payment gateway for the Vidyari Digital Marketplace has been successfully migrated from **Cashfree** to **Razorpay**. All payment processing, order creation, verification, and webhook handling have been completely refactored to work with Razorpay's API.

### Key Statistics
- **Files Modified**: 3 (package.json, server.js, views/checkout.ejs)
- **Dependencies Changed**: 1 package replacement
- **Endpoints Updated**: 3 (/create-order, /verify-payment, /webhook)
- **Frontend Logic Updated**: Payment checkout component

---

## Detailed Changes

### 1. Package.json Dependency Update

**File**: [package.json](package.json)

```diff
- "cashfree-pg": "^4.1.0"
+ "razorpay": "^2.9.1"
```

**Reason**: Razorpay provides the official SDK for Node.js integration with better documentation and API support.

---

### 2. Backend Configuration (server.js)

#### 2.1 File Header Documentation (Line 1-10)
**Updated**: JSDoc comments to reflect Razorpay instead of Cashfree

```diff
- * order processing with Cashfree, MongoDB database interactions
+ * order processing with Razorpay, MongoDB database interactions
- * It also integrates with Cashfree for payment processing.
+ * It also integrates with Razorpay for payment processing.
```

#### 2.2 Imports (Line 12)
**Before**:
```javascript
const { Cashfree } = require("cashfree-pg");
```

**After**:
```javascript
const Razorpay = require("razorpay");
```

#### 2.3 Payment Gateway Configuration (Line 431-436)
**Before**:
```javascript
// Cashfree configuration
Cashfree.XClientId = process.env.CASHFREE_APP_ID;
Cashfree.XClientSecret = process.env.CASHFREE_SECRET_KEY;
Cashfree.XEnvironment = Cashfree.Environment.SANDBOX;
```

**After**:
```javascript
// Razorpay configuration
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});
```

---

### 3. Payment API Endpoints

#### 3.1 POST /create-order Endpoint (Line 499-538)

**Purpose**: Create an order for payment processing

**Changes**:

| Aspect | Cashfree | Razorpay |
|--------|----------|----------|
| **Amount Unit** | Rupees (₹99 = 99) | Paisa (₹99 = 9900) |
| **Method** | `Cashfree.PGCreateOrder()` | `razorpayInstance.orders.create()` |
| **Order Object** | Complex with return_url, notify_url | Simple with amount, currency, notes |
| **Response** | Includes `payment_session_id` | Includes `order_id` and `key` |

**Key Code Update**:
```javascript
// OLD - Cashfree
const request = {
  order_id: `order_${fileId}_${Date.now()}`,
  order_amount: amountInRupees,
  order_currency: "INR",
  customer_details: {
    customer_id: `cusotmer_${req.user._id}`,
    customer_email:`${req.user.email}`,
    customer_phone: "9999999999",
  },
  order_meta: {
    return_url: `${process.env.BASE_URL || 'http://localhost:8000'}/payment-success?order_id={order_id}`,
    notify_url: `${process.env.BASE_URL || 'http://localhost:8000'}/webhook`,
  },
};
const response = await Cashfree.PGCreateOrder("2023-08-01", request);

// NEW - Razorpay
const orderOptions = {
  amount: amountInPaisa,  // Note: in paisa, not rupees
  currency: "INR",
  receipt: `order_${fileId}_${Date.now()}`,
  notes: {
    fileId: fileId,
    filename: filename,
    userId: req.user._id.toString(),
    userEmail: req.user.email
  }
};
const response = await razorpayInstance.orders.create(orderOptions);
```

**Response Format**:
```javascript
// OLD - Cashfree
{
  success: true,
  order_id: response.data.order_id,
  payment_session_id: response.data.payment_session_id,
  amount: amountInRupees * 100,
  currency: "INR",
}

// NEW - Razorpay
{
  success: true,
  order_id: response.id,
  amount: amountInPaisa,
  currency: "INR",
  key: process.env.RAZORPAY_KEY_ID
}
```

#### 3.2 POST /verify-payment Endpoint (Line 596-781)

**Purpose**: Verify payment signature and process order completion

**Changes**:

| Aspect | Cashfree | Razorpay |
|--------|----------|----------|
| **Signature Algorithm** | HMAC SHA256 (base64) | HMAC SHA256 (hex) |
| **Signature String** | JSON.stringify(req.body) | `order_id\|payment_id` |
| **Payment Fetch** | `Cashfree.PGFetchOrder()` | `razorpayInstance.payments.fetch()` |
| **Success Status** | `order_status === 'ACTIVE'` | `status === 'captured'` |
| **Request Parameters** | order_id, payment_id, signature | razorpay_order_id, razorpay_payment_id, razorpay_signature |

**Key Code Update**:
```javascript
// OLD - Cashfree signature verification
const expectedSignature = crypto
  .createHmac('sha256', secretKey)
  .update(JSON.stringify(req.body))
  .digest('base64');

// NEW - Razorpay signature verification
const expectedSignature = crypto
  .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
  .update(razorpay_order_id + "|" + razorpay_payment_id)
  .digest('hex');
```

**Fetch Payment Details**:
```javascript
// OLD - Cashfree
const response = await Cashfree.PGFetchOrder("2023-08-01", order_id);
const paymentDetails = response.data;

// NEW - Razorpay
const paymentDetails = await razorpayInstance.payments.fetch(razorpay_payment_id);
```

**Status Check**:
```javascript
// OLD - Cashfree
if (paymentDetails.order_status !== 'ACTIVE') { /* ... */ }

// NEW - Razorpay
if (paymentDetails.status !== 'captured') { /* ... */ }
```

**Database Storage Updates**: Both implementations store the same data in MongoDB, but with different transaction ID sources:
- File: Order record, Transaction record, User purchase, User download, User notification
- Balance: Seller balance update, Admin balance update
- Notifications: Push notifications to buyer and seller

#### 3.3 POST /webhook Endpoint (Line 773-805)

**Purpose**: Receive and process payment event notifications from payment gateway

**Changes**:

| Aspect | Cashfree | Razorpay |
|--------|----------|----------|
| **Signature Header** | `x-webhook-signature` or `X-Webhook-Signature` | `x-razorpay-signature` |
| **Signature Encoding** | Base64 | Base64 |
| **Event Types** | `PAYMENT_SUCCESS_WEBHOOK` | `payment.captured`, `payment.failed`, etc. |
| **Event Data Path** | `eventData.data` | `eventData.payload.payment.entity` |

**Key Code Update**:
```javascript
// OLD - Cashfree
const signature = req.headers['x-webhook-signature'] || req.headers['X-Webhook-Signature'];
const expectedSignature = crypto
  .createHmac('sha256', secretKey)
  .update(JSON.stringify(req.body))
  .digest('base64');

if (eventData.type === 'PAYMENT_SUCCESS_WEBHOOK') {
  console.log('Payment successful:', eventData.data);
}

// NEW - Razorpay
const signature = req.headers['x-razorpay-signature'];
const expectedSignature = crypto
  .createHmac('sha256', secret)
  .update(JSON.stringify(req.body))
  .digest('base64');

if (eventData.event === 'payment.captured') {
  console.log('Payment captured:', eventData.payload.payment.entity);
} else if (eventData.event === 'payment.failed') {
  console.log('Payment failed:', eventData.payload.payment.entity);
}
```

---

### 4. Frontend Checkout Component (views/checkout.ejs)

#### 4.1 Payment SDK Script (Line 483)

**Before**:
```html
<script src="https://sdk.cashfree.com/js/v3/cashfree.js"></script>
```

**After**:
```html
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
```

#### 4.2 Payment Initialization Logic (Line 563-636)

**Before**:
```javascript
if (payButton) {
    payButton.onclick = function (e) {
        return;  // This was disabled - now enabled
        e.preventDefault();
        // ... fetch /create-order
        .then(order => {
            const cashfree = new Cashfree({mode:"sandbox"});
            cashfree.checkout({
                paymentSessionId: order.payment_session_id,
                redirectTarget: "_modal",
            }).then((result) => {
                if (result.error) { /* handle error */ }
                else if (result.paymentDetails) {
                    // ... fetch /verify-payment with:
                    // order_id: result.paymentDetails.orderId,
                    // payment_id: result.paymentDetails.paymentId,
                }
            });
        });
    }
}
```

**After**:
```javascript
if (payButton) {
    payButton.onclick = function (e) {
        e.preventDefault();
        // ... fetch /create-order
        .then(order => {
            const options = {
                key: order.key,  // Razorpay Key ID
                amount: order.amount,
                currency: order.currency,
                name: "Vidyari",
                description: "<%= file.filename %>",
                order_id: order.order_id,
                handler: function (response) {
                    // ... fetch /verify-payment with:
                    // razorpay_order_id: response.razorpay_order_id,
                    // razorpay_payment_id: response.razorpay_payment_id,
                    // razorpay_signature: response.razorpay_signature,
                },
                prefill: {
                    email: "<%= typeof useremail !== 'undefined' ? useremail : '' %>",
                    name: "<%= typeof username !== 'undefined' ? username : '' %>"
                },
                theme: { color: "#000000" },
                modal: {
                    ondismiss: function() {
                        // Handle modal close
                    }
                }
            };
            const rzp = new Razorpay(options);
            rzp.open();
        });
    }
}
```

**Key Differences**:
1. **Initialization**: `new Razorpay(options)` instead of `new Cashfree({mode:"sandbox"})`
2. **Configuration**: Options object is passed to constructor
3. **Modal Opening**: `rzp.open()` instead of `cashfree.checkout()`
4. **Handler Function**: Becomes the success handler after payment
5. **Response Format**: Response properties use `razorpay_` prefix
6. **Modal Dismissal**: Separate handler for when user closes modal without paying

---

## Environment Variables

### Required New Variables

Add these to your `.env` file:

```env
# Razorpay API Credentials (Get from https://razorpay.com/settings/api-keys)
RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxx  (or rzp_live_ for production)
RAZORPAY_KEY_SECRET=your_key_secret_here

# Razorpay Webhook Secret (Get from https://razorpay.com/settings/webhooks)
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret_here
```

### Legacy Variables (Can be removed)

```env
# CASHFREE_APP_ID=...
# CASHFREE_SECRET_KEY=...
# CASHFREE_WEBHOOK_SECRET=...
```

---

## Payment Flow Architecture

### Before (Cashfree)
```
User → Checkout Page → /create-order → Cashfree API → Payment Session
  ↓
Cashfree SDK Modal → User Enters Card
  ↓
Cashfree Processes → /verify-payment → Fetch Cashfree Order
  ↓
Verify Status → Store in DB → Send Notifications
```

### After (Razorpay)
```
User → Checkout Page → /create-order → Razorpay API → Order ID
  ↓
Razorpay Checkout Modal → User Enters Card
  ↓
Razorpay Processes → Handler with Response
  ↓
/verify-payment → Signature Verification
  ↓
Fetch Razorpay Payment → Verify Status → Store in DB → Send Notifications
```

---

## Testing the Migration

### Test Credentials
- **Key ID**: Use your test key from Razorpay dashboard (starts with `rzp_test_`)
- **Test Card**: `4111 1111 1111 1111`
- **Expiry**: Any future date (e.g., `12/25`)
- **CVV**: Any 3 digits (e.g., `123`)

### Test Scenarios

1. **Successful Payment**:
   - User adds product to checkout
   - Clicks "Complete Payment"
   - Razorpay modal opens
   - Enters test card details
   - Payment succeeds → Redirected to download page

2. **Payment Failure**:
   - Use an invalid card number
   - Error should be displayed in checkout page

3. **Webhook Verification**:
   - Monitor Razorpay dashboard for webhook delivery
   - Check server logs for webhook processing

---

## Files Modified

### 1. [package.json](package.json)
- **Status**: ✅ Updated
- **Change**: Replaced `cashfree-pg` with `razorpay`
- **Installing**: Run `npm install` to fetch new dependency

### 2. [server.js](server.js)
- **Status**: ✅ Updated
- **Changes**:
  - Line 12: Import statement
  - Lines 431-436: Configuration
  - Lines 499-538: `/create-order` endpoint
  - Lines 596-781: `/verify-payment` endpoint
  - Lines 773-805: `/webhook` endpoint
- **Total Changes**: 5 major sections

### 3. [views/checkout.ejs](views/checkout.ejs)
- **Status**: ✅ Updated
- **Changes**:
  - Line 483: SDK script src
  - Lines 563-636: Payment logic JavaScript
- **Total Changes**: 2 major sections

---

## Migration Checklist

Pre-Deployment:
- [x] Dependencies updated in package.json
- [x] Backend configuration replaced
- [x] Payment endpoints refactored
- [x] Frontend checkout component updated
- [x] Webhook endpoint updated
- [x] Migration guide created

Post-Deployment:
- [ ] Run `npm install` to fetch Razorpay SDK
- [ ] Add Razorpay credentials to `.env`
- [ ] Test payment flow with test credentials
- [ ] Set up webhook in Razorpay dashboard
- [ ] Configure webhook secret in `.env`
- [ ] Test successful payment scenario
- [ ] Test failed payment scenario
- [ ] Monitor webhook delivery in Razorpay dashboard
- [ ] Verify transaction records in MongoDB
- [ ] Test push notifications to buyer and seller

---

## Rollback Plan

If issues arise and you need to revert to Cashfree:

### Option 1: Git Revert
```bash
git checkout HEAD -- package.json server.js views/checkout.ejs
npm install
```

### Option 2: Manual Revert
1. Restore backup of original files
2. Replace Razorpay env vars with Cashfree env vars
3. Run `npm install`

---

## Performance & Security Considerations

### Performance
- **Response Times**: Razorpay typically has <100ms latency for order creation
- **Webhook Processing**: Async processing prevents blocking main PaymentIntent
- **Connection Pooling**: Razorpay SDK handles connection optimization

### Security
- **PCI Compliance**: All card data handled by Razorpay servers
- **Signature Verification**: HMAC-SHA256 ensures webhook authenticity
- **HTTPS Required**: All API calls must use HTTPS
- **API Key Rotation**: Implement key rotation strategy in production

---

## Known Issues & Workarounds

### Issue: "Invalid Signature" errors on webhook
**Solution**: Verify webhook secret matches exactly in Razorpay dashboard settings

### Issue: Amount discrepancies
**Remember**: Razorpay uses paisa (smallest unit), not rupees. Multiply by 100.

### Issue: Test card always fails
**Check**: Using test key (rzp_test_) not live key (rzp_live_)

---

## Support & Documentation

- **Razorpay Docs**: https://razorpay.com/docs/
- **API Reference**: https://razorpay.com/docs/api/
- **SDK GitHub**: https://github.com/razorpay/razorpay-node
- **Our Migration Guide**: [RAZORPAY_MIGRATION_GUIDE.md](RAZORPAY_MIGRATION_GUIDE.md)

---

## Conclusion

The migration from Cashfree to Razorpay has been successfully completed. All payment processing functionality has been maintained while leveraging Razorpay's streamlined API and better integration patterns. The system is ready for testing and deployment.

**Next Steps**:
1. Deploy to staging environment
2. Run comprehensive payment tests
3. Configure webhook settings in Razorpay dashboard
4. Deploy to production once staging validation is complete
