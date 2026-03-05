# 🔧 QUICK SECURITY FIXES - CRITICAL VULNERABILITIES

This file contains ready-to-copy code fixes for the most critical vulnerabilities.

## Fix #1: Replace Hardcoded JWT Secrets

### ❌ CURRENT (VULNERABLE):
```javascript
// File: routes/authentication/googleAuth.js (multiple locations)
const secret = "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2";
jwt.sign(payload, secret);
jwt.verify(token, secret);
```

### ✅ FIXED (SECURE):

**Step 1: Update .env file**
```env
# Add these new environment variables
JWT_SECRET_USER_LOGIN=your_very_long_random_secret_min_32_chars_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o
JWT_SECRET_2FA=another_random_secret_min_32_chars_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k
JWT_SECRET_EMAIL_VERIFY=email_verify_secret_min_32_chars_abcdefghijklmnopqrstuvwxyz123456
JWT_SECRET_PASSWORD_RESET=password_reset_secret_min_32_chars_zyxwvutsrqponmlkjihgfedcba654321
JWT_SECRET_FILE_PURCHASE=file_purchase_secret_min_32_chars_1q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h
```

**Step 2: Generate secure random secrets (Linux/Mac)**
```bash
# Generate random 64-character string
openssl rand -base64 48

# Run 5 times and put in .env
```

**Step 3: Update googleAuth.js**
```javascript
// At file top, add:
require('dotenv').config();

// Replace all instances of hardcoded secrets:

// OLD:
jwt.sign({ userId: user.id }, "3a1f0b9d5c7e...", { expiresIn: "7d" });

// NEW:
jwt.sign(
  { userId: user.id },
  process.env.JWT_SECRET_USER_LOGIN,
  { expiresIn: "7d" }
);

// For email verification:
jwt.sign(
  { userId: user._id, email: email },
  process.env.JWT_SECRET_EMAIL_VERIFY,
  { expiresIn: "1d" }
);

jwt.verify(token, process.env.JWT_SECRET_EMAIL_VERIFY);

// For 2FA:
jwt.sign(
  { userId: user.id },
  process.env.JWT_SECRET_2FA,
  { expiresIn: "5m" }
);

jwt.verify(token, process.env.JWT_SECRET_2FA);
```

---

## Fix #2: Fix NoSQL Injection on /check/username

### ❌ VULNERABLE:
```javascript
router.post("/check/username", async (req, res) => {
  let exists = await User.findOne({
    username: new RegExp("^" + req.body.username + "$", "i"),
  });
  res.json({ exists: !!exists });
});
```

### ✅ FIXED:
```javascript
router.post("/check/username", async (req, res) => {
  try {
    // 1. Validate input format
    const username = String(req.body.username || "").trim();
    
    if (!username) {
      return res.status(400).json({ error: "Username required" });
    }
    
    // 2. Whitelist check - only allow alphanumeric, underscore, hyphen
    if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: "Invalid username format" });
    }
    
    // 3. Exact match only (not regex)
    const user = await User.findOne({
      username: { $eq: username.toLowerCase() }
    });
    
    // 4. Return safe response
    res.json({ exists: !!user });
  } catch (err) {
    console.error("Check username error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
```

---

## Fix #3: Add Authorization Checks for File Operations

### ❌ VULNERABLE - /delete-file
```javascript
app.post("/delete-file", authenticateJWT_user, async (req, res) => {
  const { fileId } = req.body;
  
  // NO OWNERSHIP CHECK - ANYONE CAN DELETE ANY FILE
  const file = await File.findByIdAndRemove(fileId);
  res.json({ success: true });
});
```

### ✅ FIXED:
```javascript
app.post("/delete-file", authenticateJWT_user, async (req, res) => {
  try {
    const { fileId } = req.body;
    
    // 1. Validate fileId format
    if (!fileId || !fileId.match(/^[0-9a-f]{24}$/i)) {
      return res.status(400).json({ error: "Invalid file ID" });
    }
    
    // 2. Fetch file
    const file = await File.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }
    
    // 3. CHECK OWNERSHIP - CRITICAL!
    if (file.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ 
        error: "You don't have permission to delete this file" 
      });
    }
    
    // 4. Delete file from S3 first
    // ... S3 deletion code ...
    
    // 5. Delete database record
    await File.findByIdAndDelete(fileId);
    
    res.json({ success: true, message: "File deleted" });
  } catch (err) {
    console.error("Delete file error:", err);
    res.status(500).json({ error: "Delete failed" });
  }
});
```

---

## Fix #4: Prevent IDOR on Profile Viewing

### ❌ VULNERABLE:
```javascript
router.get("/profile/:username", authenticateJWT_user, async (req, res) => {
  const user = await User.findOne({
    username: new RegExp(`^${req.params.username}$`, "i")
  });
  
  // NO CHECK IF VIEWING OWN PROFILE
  // Can view anyone's files, earnings, data
  const files = await File.find({ userId: user._id });
  res.render("publicprofile", { files, user });
});
```

### ✅ FIXED:
```javascript
router.get("/profile/:username", authenticateJWT_user, async (req, res) => {
  try {
    const username = String(req.params.username || "").trim();
    
    // Only allow view if:
    // 1. Viewing own profile, OR
    // 2. User public viewing is enabled
    
    const profileUser = await User.findOne({
      username: { $eq: username.toLowerCase() }
    });
    
    if (!profileUser) {
      return res.status(404).render("404.ejs");
    }
    
    // Check if it's own profile or public
    const isOwnProfile = profileUser._id.toString() === req.user._id.toString();
    const isPublic = profileUser.profileVisibility === "public";
    
    if (!isOwnProfile && !isPublic) {
      return res.status(403).render("404.ejs");  // Hide existence
    }
    
    // Get files - only if own profile or files marked public
    let files = [];
    if (isOwnProfile) {
      files = await File.find({ userId: profileUser._id });
    } else {
      files = await File.find({
        userId: profileUser._id,
        isPublic: true  // Add isPublic field to File model
      });
    }
    
    // Never expose:
    // - Email
    // - Phone
    // - Social links
    // - Earnings/balance
    const safeProfile = {
      username: profileUser.username,
      bio: profileUser.bio,
      joins: profileUser.joinedOn,
      followers: profileUser.followers.length,
      following: profileUser.following.length,
      isVerified: profileUser.ISVERIFIED,
      files: files.length
    };
    
    res.render("publicprofile", { 
      profile: safeProfile, 
      files: files.slice(0, 10)  // Limit to 10
    });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).render("500.ejs");
  }
});
```

---

## Fix #5: Add CSRF Protection

### Step 1: Install package
```bash
npm install csurf
```

### Step 2: Setup middleware in server.js
```javascript
const csrf = require('csurf');
const sessionMiddleware = require('express-session');

// Setup session
app.use(sessionMiddleware({
  secret: process.env.SESSION_SECRET || 'change-this-secret', 
  resave: false,
  saveUninitialized: true,
  cookie: { 
    httpOnly: true, 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Setup CSRF protection
const csrfProtection = csrf({ cookie: false });
```

### Step 3: Apply to state-changing routes
```javascript
// For forms (GET):
app.get('/delete-file-page', csrfProtection, (req, res) => {
  res.render('delete-file', { csrfToken: req.csrfToken() });
});

// For API endpoints (POST/PUT/DELETE):
app.post('/delete-file', csrfProtection, authenticateJWT_user, async (req, res) => {
  // CSRF token automatically validated
  // ...
});
```

---

## Fix #6: Secure Cookie Settings

### ❌ VULNERABLE (server.js, line 273):
```javascript
res.cookie("token", token, {
  httpOnly: true,
  secure: false,  // ALLOWS HTTP
  maxAge: 7 * 24 * 60 * 60 * 1000,
});
```

### ✅ FIXED:
```javascript
res.cookie("token", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",  // HTTPS only
  sameSite: "strict",  // Prevent CSRF and cross-site cookie access
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: "/",
  domain: process.env.NODE_ENV === "production" ? ".vidyari.com" : undefined
});
```

---

## Fix #7: Add Input Validation to /auth/login

### Install validation package
```bash
npm install zod
```

### ✅ SECURE LOGIN IMPLEMENTATION:
```javascript
const { z } = require('zod');

const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password too long")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[0-9]/, "Password must contain number")
});

router.post("/auth/login", async (req, res) => {
  try {
    // 1. Validate input
    const { email, password } = loginSchema.parse(req.body);
    
    // 2. Normalize
    const normalizedEmail = email.toLowerCase().trim();
    
    // 3. Rate limiting check
    // ... (implement with redis)
    
    // 4. Find user
    const user = await User.findOne({ email: normalizedEmail });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // 5. Compare password
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // 6. Check email verification
    if (!user.isEmailVerified) {
      return res.status(403).json({ 
        error: "Please verify your email first",
        verificationEmailSent: true
      });
    }
    
    // 7. Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET_USER_LOGIN,
      { expiresIn: "7d" }
    );
    
    // 8. Set secure cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    // 9. Log successful login
    await logActivity({
      userId: user._id,
      action: "login",
      timestamp: new Date()
    });
    
    // 10. Return minimal response
    res.json({ 
      success: true,
      user: {
        id: user._id,
        username: user.username
      }
    });
    
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ 
        error: "Validation failed",
        details: err.errors[0]
      });
    }
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});
```

---

## Fix #8: Remove Sensitive Logs

### ❌ DELETE THESE:
```javascript
// server.js line 118
console.log("Mongo URI:", process.env.MONGODB_URI);

// routes/authentication/googleAuth.js line 326
console.log("Latest course ID:", latestCourse._id);

// routes/authentication/googleAuth.js line 347
console.log("User profile pic URL:", user.profilePicUrl);

// routes/authentication/googleAuth.js line 810
console.log("password save for user ", user.username, "passwordHash", user.passwordHash);

// And all console.log in catch blocks showing errors
console.error("Error in ..:", err);
```

### ✅ REPLACE WITH:
```javascript
// Safe logging
console.log("✅ MongoDB connected successfully");
console.log("User profile loaded");
console.log("// Password updated");

// For errors, never expose details:
console.error("Operation failed - [ID:" + req.id + "]");
// (Use request ID for tracking without exposing details)
```

---

## Fix #9: Add Rate Limiting

### ❌ CURRENT:  
```javascript
router.post("/auth/login", async (req, res) => {
  // No rate limiting - brute force possible
});
```

### ✅ FIXED:
```javascript
const rateLimit = require('express-rate-limit');

// Strict rate limiting for auth
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 attempts
  message: "Too many login attempts, please try again later",
  standardHeaders: true,      // Return rate limit info in headers
  legacyHeaders: false,
  keyGenerator: (req) => req.ip + req.body.email  // Per-user limit
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 3                      // 3 signups per email
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 30                     // 30 requests
});

// Apply limiters
router.post("/auth/login", loginLimiter, async (req, res) => { ... });
router.post("/auth/signup", signupLimiter, async (req, res) => { ... });
app.use("/api/", apiLimiter);
```

---

## .env Template

Add this to your .env file:

```env
# Database
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/dbname

# JWT Secrets (generate new ones!)
JWT_SECRET=your_main_secret_min_32_chars_long_random_string
JWT_SECRET_USER_LOGIN=your_user_login_secret_min_32_chars_random
JWT_SECRET_2FA=your_2fa_secret_min_32_chars_random_string
JWT_SECRET_EMAIL_VERIFY=your_email_verify_secret_min_32_chars_random
JWT_SECRET_PASSWORD_RESET=your_password_reset_secret_min_32_chars_random
JWT_SECRET_FILE_PURCHASE=your_file_purchase_secret_min_32_chars_random
SESSION_SECRET=your_session_secret_min_32_chars_random_string

# AWS S3
AWS_REGION=ap-south-1
S3_IMAGE_BUCKET=vidyari3
S3_MAIN_FILE_BUCKET=vidyarimain2
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Payment
RAZORPAY_KEY_ID=your_key_id
RAZORPAY_KEY_SECRET=your_secret_key
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# Firebase
FIREBASE_SERVICE_ACCOUNT={"type":"service_account",...}  # JSON stringified

# Supabase
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_key

# Admin
ADMIN_USERNAME=unique_admin_username
ADMIN_PASSWORD_HASH=bcrypt_hash_of_password

# Environment
NODE_ENV=production
PORT=8000
```

---

## Testing Checklist

After applying fixes, test:

- [ ] Cannot login with hardcoded JWT anymore
- [ ] Cannot create account with weak passwords
- [ ] Login limited to 5 attempts per 15 minutes
- [ ] Cannot delete other user's files
- [ ] Cannot view other user's private profile data
- [ ] CSRF token required on POST requests
- [ ] Cookies require HTTPS in production
- [ ] No sensitive data in error messages
- [ ] Can't enumerate usernames via /check/username
- [ ] All tokens signed with environment variable secrets

---

## Progress Tracking

- [ ] Fix all hardcoded JWT secrets
- [ ] Add authorization checks to all endpoints
- [ ] Implement CSRF protection
- [ ] Add rate limiting
- [ ] Remove sensitive logs
- [ ] Add input validation
- [ ] Secure cookie settings
- [ ] Regenerate all credentials
- [ ] Deploy to production
- [ ] Monitor for attacks using tools like Snyk, npm audit
