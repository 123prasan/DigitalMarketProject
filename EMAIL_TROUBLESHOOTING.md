# Email Sending & Image Issues - Troubleshooting Guide

## Issues Fixed ✅

### 1. **Profile Images Not Showing in Emails** 
**Problem:** Images in emails (like profile pictures or logos) were not displaying because they used relative paths.

**Root Cause:**
- Email template used `src="public/images/mainlogo.png"` (relative path)
- Email clients cannot resolve relative paths
- Needs absolute URLs with full domain or CDN

**Files Fixed:**
- `emails/templates/auth/welcomeEmail.html` - Changed from `src="public/images/mainlogo.png"` to `src="https://d3epchi0htsp3c.cloudfront.net/mainlogo.png"`

**Solution Implemented:**
- Added automatic URL fixing function `fixRelativeUrls()` in `test.js`
- Converts all relative image paths to absolute CloudFront URLs
- Applied to all bulk email sending

---

### 2. **Emails Not Sending from Admin Dashboard**
**Problem:** Admin email campaigns were not being sent or failing silently.

**Root Causes:**
1. **Missing Email Credentials** - `EMAIL_USER` and `EMAIL_PASS` environment variables not configured
2. **Improved Error Handling** - Now provides clear feedback on what's wrong
3. **Improper API Call** - Using relative path instead of API_BASE constant

**Files Updated:**
- `routes/adminRoutes.js` - Enhanced error messages and logging
- `views/admin/admin.ejs` - Now uses `${API_BASE}/send-email` for consistency

**Solution Implemented:**
- Better error handling with clear messages
- Returns debug info showing which credentials are missing
- Logs which email account is being used
- Shows count of failed/successful emails

---

## Configuration Requirements ⚙️

### Required Environment Variables
Add these to your `.env` file:

```env
# Email Service Credentials
EMAIL_SERVICE=gmail  # or your email service
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password  # NOT your regular password, use Gmail App Password

# Alternatively use these if EMAIL_USER/PASS not set:
ADMIN_EMAIL=your-email@gmail.com
ADMIN_PASSWORD=your-app-password

# Optional but recommended:
BASE_URL=https://your-domain.com  # For email unsubscribe links
CF_DOMAIN_PROFILES_COURSES=https://your-cloudfront-domain.cloudfront.net
COMPANY_NAME=Your Company Name
SUPPORT_EMAIL=support@your-domain.com
```

### Gmail App Password Setup
For Gmail SMTP, you need an **App Password**, not your regular password:

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable 2-Step Verification (if not already enabled)
3. Create an App Password
4. Use this in `EMAIL_PASS`

---

## Troubleshooting Steps 🔧

### Problem: "Email service not configured" Error

**Cause:** `EMAIL_USER` or `EMAIL_PASS` not set in `.env`

**Solution:**
```bash
# Check if .env exists
ls -la .env

# Add/update these lines in .env:
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Restart your server
```

### Problem: Emails Have Broken Images

**Cause:** Images using relative paths that email clients can't resolve

**Status:** ✅ FIXED - Automatic URL conversion is now in place

The system now automatically converts:
- `src="public/images/logo.png"` → `src="https://cloudfront.net/logo.png"`
- `src="/images/avatar.jpg"` → `src="https://cloudfront.net/avatar.jpg"`

### Problem: Some Emails Failed to Send

**What to Check:**
1. Check server logs for detailed error messages
2. Look for SMTP authentication errors
3. Verify recipient email addresses are valid
4. Check email rate limits (some providers throttle bulk sends)

**From Admin Dashboard:**
- The response now shows which emails failed
- Check the browser console for error details
- Server logs show clear failure reasons

### Problem: Emails Going to Spam

**Common Reasons:**
- No reply-to header
- Missing proper HTML formatting
- Unverified sender address in SES/email provider

**Status:** ✅ FIXED - System includes:
- Reply-To header pointing to support email
- Proper HTML template wrapping
- X-Mailer and Priority headers

---

## How Email System Works 📬

### Email Flow Architecture

```
Admin Dashboard (admin.ejs)
    ↓ POST /api/admin/send-email
    ↓ (recipients, subject, content)
Backend Routes (adminRoutes.js)
    ↓ Validates credentials
    ↓ EmailService.sendEmailBulk()
Test.js (EmailService)
    ↓ fixRelativeUrls() - Converts relative URLs to absolute
    ↓ sendEmail() - Sends via Nodemailer SMTP
Gmail/SMTP Server
    ↓
Recipient Email Inbox
```

### Key Functions

**`fixRelativeUrls(htmlContent)`** - In `test.js`
- Automatically converts relative image paths to absolute URLs
- Uses CloudFront domain for images
- Ensures emails display properly

**`sendEmailBulk(recipients, subject, htmlContent)`** - In `test.js`
- Sends to multiple recipients
- Replaces {username} and {email} placeholders
- Wraps in professional HTML template
- Handles errors gracefully

**`/api/admin/send-email`** - POST endpoint in `adminRoutes.js`
- Validates input
- Checks email credentials
- Calls EmailService
- Returns success/failure count

---

## Testing Email Sending 🧪

### Test 1: Check Backend Configuration
```bash
# Check if EMAIL_USER and EMAIL_PASS are set
grep "EMAIL_USER" .env
grep "EMAIL_PASS" .env

# Check test email sending (if available)
node test.js
```

### Test 2: Send Test Email via Admin Dashboard
1. Go to Admin Panel → Campaigns
2. Fill in subject and content
3. Select "Individual Email"
4. Enter a test email address
5. Click "Send Campaign"
6. Check response message for success/failure

### Test 3: Check Server Logs
Look for messages like:
- ✅ "Email sent to user@example.com"
- ❌ "Error sending email: ECONNREFUSED"
- ⚠️ "Email credentials not configured"

---

## Image URLs in Emails 🖼️

### Supported Image URL Formats

**❌ WON'T WORK (Relative Paths):**
```html
<!-- Email clients can't resolve these -->
<img src="/images/logo.png">
<img src="public/images/avatar.jpg">
<img src="./images/banner.png">
```

**✅ WORKS (Absolute URLs):**
```html
<!-- Full domain URLs work in emails -->
<img src="https://mycdn.cloudfront.net/logo.png">
<img src="https://d3epchi0htsp3c.cloudfront.net/avatar.jpg">
<img src="https://example.com/images/banner.png">
```

### Automatic Conversion (NEW)
The system now automatically converts relative paths:

**Input:** 
```html
<img src="/images/logo.png" alt="Logo">
```

**Output:**
```html
<img src="https://d3epchi0htsp3c.cloudfront.net/logo.png" alt="Logo">
```

---

## Template Best Practices 📋

### For HTML Email Content:

1. **Use Absolute URLs for All Media**
   ```html
   <!-- Always use full URLs -->
   <img src="https://cdn.example.com/image.png">
   ```

2. **Include Alt Text**
   ```html
   <!-- Helps with spam score and accessibility -->
   <img src="..." alt="Descriptive text">
   ```

3. **Use Inline CSS**
   ```html
   <!-- Email clients have limited CSS support -->
   <div style="color: #333; font-size: 14px;">
     Content here
   </div>
   ```

4. **Avoid JavaScript**
   ```html
   <!-- Email clients don't execute JavaScript -->
   <script>alert('This won't run')</script> ❌
   ```

### Placeholders Available:
- `{username}` - Recipient's username
- `{email}` - Recipient's email address

---

## Common Error Messages 🚨

| Error | Cause | Solution |
|-------|-------|----------|
| "Email service not configured" | Missing EMAIL_USER or EMAIL_PASS | Add to .env file |
| "ECONNREFUSED" | Can't connect to SMTP | Check EMAIL_SERVICE setting |
| "Invalid credentials" | Wrong EMAIL_PASS | Regenerate Gmail App Password |
| "Timeout waiting for response" | SMTP server slow | Increase timeout in axios call |
| "Images not showing in email" | Relative image paths | Use absolute URLs with CDN |

---

## Files Modified ✏️

1. **emails/templates/auth/welcomeEmail.html**
   - Fixed: Changed relative image path to absolute CloudFront URL

2. **test.js (EmailService)**
   - Added: `fixRelativeUrls()` function
   - Updated: `sendEmailBulk()` to use URL fixing

3. **routes/adminRoutes.js**
   - Enhanced: Error handling and logging
   - Added: Credential validation with debug info
   - Improved: Response messages

4. **views/admin/admin.ejs**
   - Updated: API endpoint to use `${API_BASE}` constant

---

## Next Steps 🚀

1. **Add Email Credentials** to your `.env` file
2. **Test Email Sending** via Admin Dashboard
3. **Monitor Logs** for any errors
4. **Check Recipient Emails** for delivery

For issues, check:
- Server console logs: `node server.js`
- Browser console: Open Dev Tools → Console
- Network tab: Check API response from `/api/admin/send-email`

---

*Last Updated: April 2026*
