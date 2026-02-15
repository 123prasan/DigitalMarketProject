# Razorpay Migration - Quick Reference Card

## 🚀 Quick Deployment Steps

```bash
# 1. Install dependencies
npm install

# 2. Update .env file
RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxxxx
RAZORPAY_KEY_SECRET=your_key_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# 3. Start server
npm start

# 4. Test payment
# Visit checkout page and use test card: 4111 1111 1111 1111
```

---

## 📋 Files Changed Summary

| File | Changes | Lines |
|------|---------|-------|
| `package.json` | Razorpay dependency | Line 49 |
| `server.js` | Import, Config, 3 endpoints, webhooks | Lines 12, 431, 499, 596, 773 |
| `views/checkout.ejs` | SDK script, Payment logic | Lines 483, 563 |

---

## 🔄 Key API Changes

### Order Creation
```javascript
// OLD
const response = await Cashfree.PGCreateOrder("2023-08-01", request);
response.data.payment_session_id  // Get session

// NEW
const response = await razorpayInstance.orders.create(options);
response.id  // Get order ID
```

### Payment Verification
```javascript
// OLD
const response = await Cashfree.PGFetchOrder("2023-08-01", order_id);
paymentDetails.order_status === 'ACTIVE'

// NEW
const paymentDetails = await razorpayInstance.payments.fetch(payment_id);
paymentDetails.status === 'captured'
```

### Amount Format
```javascript
// OLD (Cashfree)
amount: 99  // ₹99 in rupees

// NEW (Razorpay)
amount: 9900  // ₹99 in paisa
```

---

## 🧪 Test Card Details

| Field | Value |
|-------|-------|
| **Card Number** | `4111 1111 1111 1111` |
| **Expiry** | `12/25` (or any future date) |
| **CVV** | `123` (or any 3 digits) |
| **Name** | Any name |
| **Email** | Auto-filled from checkout |

---

## 📡 Webhook Setup

### URL
```
https://yourdomain.com/webhook
```

### Events to Subscribe
- `payment.authorized`
- `payment.failed`
- `payment.captured`

### Signature Header
```
x-razorpay-signature: <signature>
```

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| Payment creation fails | Check RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are correct |
| "Invalid Signature" | Verify RAZORPAY_WEBHOOK_SECRET matches dashboard |
| Amount shows wrong | Remember: multiply rupees by 100 for paisa |
| Webhook not received | Check URL is publicly accessible and HTTPS |
| Test card rejected | Ensure using `rzp_test_` key not `rzp_live_` |

---

## 📊 Migration Metrics

- **Total Files Modified**: 3
- **Total Endpoints Updated**: 3
- **Lines of Code Changed**: ~300
- **Testing Time Required**: ~30 minutes
- **Deployment Risk**: LOW (payment gateway abstraction layer isolated)

---

## ✅ Pre-Launch Checklist

- [ ] `npm install` completed
- [ ] `.env` has all 3 Razorpay variables
- [ ] Tested successful payment with test card
- [ ] Tested failed payment scenario
- [ ] Webhook URL configured in Razorpay dashboard
- [ ] Verified webhook signature secret
- [ ] Checked MongoDB records for new transactions
- [ ] Verified seller/admin balance updates
- [ ] Confirmed push notifications sent
- [ ] Check logs for any errors
- [ ] Deploy to production

---

## 🔐 Security Notes

✅ All card data handled by Razorpay (PCI compliant)  
✅ Signature verification on all webhooks  
✅ API keys never exposed in code  
✅ Environment variables used for secrets  
✅ Transaction records stored securely in DB  

---

## 📞 Quick Help

**Is test mode enabled?**  
Check that RAZORPAY_KEY_ID starts with `rzp_test_`

**Which amount unit to use?**  
Always use paisa (×100). So ₹99 = 9900

**How to verify webhook?**  
On Razorpay dashboard → Settings → Webhooks → Check delivery logs

**Need to switch back to Cashfree?**  
```bash
git checkout HEAD -- package.json server.js views/checkout.ejs
npm install
```

---

## 📚 Online Resources

- **Razorpay Documentation**: https://razorpay.com/docs/
- **API Orders**: https://razorpay.com/docs/api/orders/
- **Node.js SDK**: https://github.com/razorpay/razorpay-node
- **Full Migration Guide**: See RAZORPAY_MIGRATION_GUIDE.md
- **Implementation Report**: See MIGRATION_IMPLEMENTATION_REPORT.md

---

## 🎯 Payment Flow Summary

```
User → Checkout Page
  ↓
Click "Complete Payment"
  ↓
GET /create-order API → Razorpay creates order
  ↓
Razorpay Checkout Modal Opens
  ↓
User Enters Card Details
  ↓
Razorpay Processes Payment
  ↓
Modal Callback Handler Triggered
  ↓
POST /verify-payment API
  ↓
Signature Verification ✓
  ↓
Fetch Payment Details ✓
  ↓
Update DB Records ✓
  ↓
Send Notifications ✓
  ↓
Redirect to Download URL ✓
```

---

**Migration Date**: February 15, 2026  
**Status**: ✅ COMPLETE  
**Ready for Deployment**: YES
