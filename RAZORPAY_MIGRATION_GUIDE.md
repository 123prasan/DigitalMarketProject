# Cashfree to Razorpay Migration Guide

## Overview
This project has been successfully migrated from **Cashfree** payment gateway to **Razorpay** payment gateway. All payment processing, order creation, verification, and webhook handling have been updated.

## Migration Summary

### Changes Made

#### 1. **Package Dependencies** (`package.json`)
- **Removed**: `cashfree-pg: ^4.1.0`
- **Added**: `razorpay: ^2.9.1`

#### 2. **Backend Configuration** (`server.js`)
- **Removed Cashfree initialization**:
  ```javascript
  const { Cashfree } = require("cashfree-pg");
  Cashfree.XClientId = process.env.CASHFREE_APP_ID;
  Cashfree.XClientSecret = process.env.CASHFREE_SECRET_KEY;
  Cashfree.XEnvironment = Cashfree.Environment.SANDBOX;
  ```

- **Added Razorpay initialization**:
  ```javascript
  const Razorpay = require("razorpay");
  const razorpayInstance = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
  ```

#### 3. **Updated Endpoints**

##### `/create-order` (POST)
- **Changed**: Order creation method
- **Old**: Used `Cashfree.PGCreateOrder()` with payment session ID
- **New**: Uses `razorpayInstance.orders.create()` with simpler order object
- **Response**: Now includes `key_id` in addition to order details

##### `/verify-payment` (POST)
- **Changed**: Payment verification and signature validation
- **Old**: Fetched order status via `Cashfree.PGFetchOrder()`
- **New**: Verifies HMAC SHA256 signature and fetches payment via `razorpayInstance.payments.fetch()`
- **Status Check**: Changed from `order_status !== 'ACTIVE'` to `status !== 'captured'`
- **Expected Fields**: Changed from Cashfree format to Razorpay format

##### `/webhook` (POST)
- **Changed**: Webhook event handling and signature verification
- **Old**: Used `x-webhook-signature` header and base64 encoding
- **New**: Uses `x-razorpay-signature` header with base64 encoding
- **Events**:
  - `PAYMENT_SUCCESS_WEBHOOK` → `payment.captured`
  - Added support for `payment.failed` event

#### 4. **Frontend Updates** (`views/checkout.ejs`)
- **Changed**: Payment SDK
- **Old**: Cashfree SDK script from `https://sdk.cashfree.com/js/v3/cashfree.js`
- **New**: Razorpay SDK script from `https://checkout.razorpay.com/v1/checkout.js`

- **Changed**: Payment checkout method
- **Old**: Used `new Cashfree({mode:"sandbox"}).checkout()`
- **New**: Uses `new Razorpay(options).open()`

- **Updated**: Handler function receives different response object
- **Old**: `result.paymentDetails.orderId` and `result.paymentDetails.paymentId`
- **New**: `response.razorpay_order_id` and `response.razorpay_payment_id`

## Environment Variables Required

### Add these to your `.env` file:

```env
# Razorpay Configuration
RAZORPAY_KEY_ID=your_razorpay_key_id_here
RAZORPAY_KEY_SECRET=your_razorpay_key_secret_here
RAZORPAY_WEBHOOK_SECRET=your_razorpay_webhook_secret_here

# Optional (remove old Cashfree variables if not needed)
# CASHFREE_APP_ID=...
# CASHFREE_SECRET_KEY=...
# CASHFREE_WEBHOOK_SECRET=...
```

### How to Get Razorpay Credentials:

1. **Create/Login to Razorpay Account**: https://razorpay.com
2. **Go to Settings → API Keys**:
   - Copy your **Key ID** and **Key Secret**
   - These will serve as `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET`

3. **Setup Webhook**:
   - Go to Settings → Webhooks
   - Add webhook endpoint: `https://yourdomain.com/webhook`
   - Select events: `payment.authorized`, `payment.failed`, `payment.captured`
   - Copy the **Webhook Secret** for `RAZORPAY_WEBHOOK_SECRET`

## Installation Steps

### 1. Install Dependencies
```bash
npm install
```

### 2. Update Environment Variables
Edit your `.env` file and add the Razorpay credentials above.

### 3. Test the Integration

#### Testing in Sandbox Mode:
Razorpay SDK automatically works in test mode with test credentials.

**Test Card Details**:
- Card Number: `4111 1111 1111 1111`
- Expiry: Any future date (e.g., `12/25`)
- CVV: Any 3 digits (e.g., `123`)
- Name: Any name

#### Payment Flow:
1. User clicks "Complete Payment" on checkout page
2. Razorpay checkout modal opens
3. User enters test card details
4. Payment is processed
5. Frontend sends verification request to `/verify-payment`
6. Backend verifies signature and stores transaction
7. User is redirected to download

## Key Differences Between Cashfree and Razorpay

| Feature | Cashfree | Razorpay |
|---------|----------|----------|
| **SDK Endpoint** | `https://sdk.cashfree.com/js/v3/cashfree.js` | `https://checkout.razorpay.com/v1/checkout.js` |
| **Amount Unit** | Rupees (e.g., 99 for ₹99) | Paisa (e.g., 9900 for ₹99) |
| **Order Creation** | `Cashfree.PGCreateOrder()` | `razorpayInstance.orders.create()` |
| **Payment Status** | `order_status === 'ACTIVE'` | `status === 'captured'` |
| **Signature Header** | `x-webhook-signature` | `x-razorpay-signature` |
| **Webhook Events** | `PAYMENT_SUCCESS_WEBHOOK` | `payment.captured`, `payment.failed` |
| **Checkout Modal** | Modal with session ID | Modal with order ID |
| **Payment Details** | Via `paymentDetails` object | Via response object with razorpay_ prefix |

## Code Changes Location

- **Backend**: [server.js](server.js)
  - Lines 12: Import statement
  - Lines 432-436: Configuration
  - Lines 499-538: `/create-order` endpoint
  - Lines 596-781: `/verify-payment` endpoint
  - Lines 773-805: `/webhook` endpoint

- **Frontend**: [views/checkout.ejs](views/checkout.ejs)
  - Line 483: SDK script
  - Lines 563-636: Payment logic JavaScript

## Migration Checklist

- [x] Updated `package.json` dependencies
- [x] Updated server.js imports
- [x] Updated Razorpay configuration
- [x] Updated `/create-order` endpoint
- [x] Updated `/verify-payment` endpoint
- [x] Updated `/webhook` endpoint
- [x] Updated checkout.ejs SDK
- [x] Updated payment flow logic
- [ ] Added Razorpay credentials to `.env`
- [ ] Tested payment flow with test credentials
- [ ] Deployed to production

## Rollback Instructions

If you need to revert to Cashfree:

1. **Restore from Git**:
   ```bash
   git checkout HEAD -- package.json server.js views/checkout.ejs
   ```

2. **Reinstall Dependencies**:
   ```bash
   npm install
   ```

3. **Restore Environment Variables**:
   - Add back `CASHFREE_APP_ID`, `CASHFREE_SECRET_KEY`, `CASHFREE_WEBHOOK_SECRET`

## Troubleshooting

### Issue: "Invalid signature"
- **Check**: Webhook secret is correct in `RAZORPAY_WEBHOOK_SECRET`
- **Check**: Webhook URL is accessible from the internet
- **Check**: Request body is not modified before signature verification

### Issue: "Payment not captured"
- **Check**: User completed payment in test modal
- **Check**: Payment status is `captured` (not `authorized` or `failed`)
- **Check**: Signature verification passed

### Issue: Order creation fails
- **Check**: `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` are correct
- **Check**: Amount is in paisa (multiply by 100)
- **Check**: Currency is set to "INR"

## Support Resources

- **Razorpay Documentation**: https://razorpay.com/docs
- **Razorpay API Reference**: https://razorpay.com/docs/api/orders/
- **Razorpay Support**: https://razorpay.com/support

## Notes

- Razorpay charges **2% + GST** on all transactions by default
- Webhook delivery is automatic; monitor webhook logs in Razorpay dashboard
- All payment records are stored in MongoDB with the new Razorpay transaction IDs
- The migration maintains backward compatibility with existing order and transaction records
