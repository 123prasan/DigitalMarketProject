# 🛠️ DETAILED IMPLEMENTATION GUIDE - SECURITY FIXES

## File-by-File Implementation Instructions

---

## 1. UPDATE .env SETUP (CRITICAL)

### Step 1: Create .env.example

**File:** `.env.example` (NEW FILE)
```env
# ============================================
# DATABASE CONFIGURATION
# ============================================
NODE_ENV=development
MONGODB_URI=mongodb+srv://username:password@cluster0.mongodb.net/dbname?retryWrites=true&w=majority

# ============================================
# AUTHENTICATION & SECURITY
# ============================================
# Generate using: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
JWT_SECRET_USER_LOGIN=your-64-character-random-string-here
JWT_SECRET=your-64-character-random-string-here
JWT_SECRET_2FA=your-64-character-random-string-here
SESSION_SECRET=your-64-character-random-string-here

# ============================================
# OAUTH CONFIGURATION
# ============================================
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=https://vidyari.com/auth/google/callback

# ============================================
# AWS CONFIGURATION
# ============================================
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=ap-south-1
AWS_S3_BUCKET_NAME=vidyari3

# ============================================
# PAYMENT CONFIGURATION
# ============================================
RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...
RAZORPAY_WEBHOOK_SECRET=...

# ============================================
# EMAIL CONFIGURATION
# ============================================
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-specific-password
EMAIL_SERVICE=gmail

# ============================================
# FIREBASE CONFIGURATION
# ============================================
# Use: firebase-admin service account JSON (base64 encoded)
FIREBASE_SERVICE_ACCOUNT=eyJ...

# ============================================
# SUPABASE CONFIGURATION
# ============================================
SUPABASE_URL=https://yourproject.supabase.co
SUPABASE_SERVICE_ROLE_KEY=...

# ============================================
# ADMIN CONFIGURATION
# ============================================
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=$2b$12$... (bcrypt hash)

# ============================================
# APP CONFIGURATION
# ============================================
PORT=3000
BASE_URL=https://vidyari.com
ALLOWED_ORIGINS=https://vidyari.com,https://www.vidyari.com

# ============================================
# CLOUDFRONT CONFIGURATION
# ============================================
CLOUDFRONT_DOMAIN=d3epchi0htsp3c.cloudfront.net
CLOUDFRONT_KEY_PAIR_ID=...
CF_PRIVATE_KEY_PATH=./private-pem/pk-...

# ============================================
# SUPPORT CONFIGURATION
# ============================================
SUPPORT_EMAIL=support@vidyari.com
SUPPORT_PHONE=+918861419230
COMPANY_NAME=Vidyari
```

### Step 2: Update .gitignore

**File:** `.gitignore` (UPDATE EXISTING)
```gitignore
# ============================================
# CRITICAL: Never commit sensitive files
# ============================================
.env
.env.local
.env.*.local
.env.production

# Credentials
serviceAccountKey.json
firebase-key.json

# Private keys
private_keys/
private-pem/

# AWS CLI
.aws/
.awsconfig

# SSL certificates
*.pem
*.key
*.crt
*.csr

# Logs containing sensitive info
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# Dependencies
node_modules/
npm-debug.log

# Build outputs
dist/
build/
.next/

# Temporary files
temp/
tmp/
.DS_Store

# Test coverage
coverage/
.nyc_output/
```

### Step 3: Update package.json with security check scripts

**File:** `package.json` (UPDATE)
```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "check-secrets": "grep -r \"password\\|secret\\|key\" --include=\"*.js\" --exclude-dir=node_modules . || echo '✅ No hardcoded secrets found'",
    "security-check": "npm run check-secrets && npm run audit && echo '✅ Security checks complete'"
  }
}
```

---

## 2. FIX SERVER.JS (CRITICAL)

### Update: Remove CORS vulnerability + Add Security Headers

**File:** `server.js`

Replace the CORS and middleware section:

```javascript
// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Load environment variables
require("dotenv").config();

// Validate critical environment variables
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET_USER_LOGIN',
  'JWT_SECRET',
  'SESSION_SECRET'
];

requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ CRITICAL: Missing environment variable: ${varName}`);
    process.exit(1);
  }
});

// Import security packages
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();

// ============================================
// SECURITY HEADERS
// ============================================

// Use Helmet to set various HTTP headers
app.use(helmet());

// Additional CSP configuration
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://d3epchi0htsp3c.cloudfront.net"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:", "https://d3*.cloudfront.net"],
    connectSrc: ["'self'", "https://vidyari.com"],
    fontSrc: ["'self'", "https:"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}));

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(301, `https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// ============================================
// CORS CONFIGURATION
// ============================================

const corsOptions = {
  origin: (process.env.ALLOWED_ORIGINS || 'https://vidyari.com').split(','),
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-CSRF-Token',
    'X-Requested-With'
  ],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// ============================================
// BODY PARSING WITH SIZE LIMITS
// ============================================

app.use(express.json({ limit: '10kb' })); // ✅ Size limit prevents DoS
app.use(express.urlencoded({ limit: '10kb', extended: false }));

// ============================================
// DATA SANITIZATION
// ============================================

// Remove $ and . from user-supplied data (NoSQL injection prevention)
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`🔒 Sanitized field: ${key}`);
  }
}));

// ============================================
// RATE LIMITING
// ============================================

// Global rate limiter for all requests
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: '⚠️ Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skip: (req) => req.method === 'OPTIONS' // Skip preflight
});

app.use(globalLimiter);

// Stricter rate limiter for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per 15 minutes
  keyGenerator: (req) => req.body?.email || req.body?.username || req.ip,
  message: '❌ Too many login attempts. Please try again after 15 minutes.',
  skip: (req) => req.method !== 'POST'
});

// ============================================
// REQUEST ID MIDDLEWARE (AUDIT TRAIL)
// ============================================

const { v4: uuidv4 } = require('uuid');

app.use((req, res, next) => {
  req.id = uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// ============================================
// LOGGING MIDDLEWARE
// ============================================

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;
  const ip = req.ip;
  
  // Log request
  console.log(`[${timestamp}] ${method} ${path} - IP: ${ip} - Request ID: ${req.id}`);
  
  // Log response
  const originalSend = res.send;
  res.send = function(data) {
    console.log(`[${timestamp}] RESPONSE: ${method} ${path} - Status: ${res.statusCode}`);
    return originalSend.call(this, data);
  };
  
  next();
});

// ============================================
// NEVER LOG SENSITIVE DATA
// ============================================

// ❌ REMOVED: console.log("Mongo URI:", process.env.MONGODB_URI);

// ✅ REPLACED WITH:
console.log("✅ Database configuration loaded from environment variables");
console.log(`✅ Running in ${process.env.NODE_ENV} mode`);
console.log(`✅ CORS enabled for origins: ${process.env.ALLOWED_ORIGINS}`);
```

---

## 3. FIX AUTHENTICATION - jwtAuth.js (CRITICAL)

**File:** `routes/authentication/jwtAuth.js`

```javascript
require("dotenv").config();
const express = require("express");
const User = require("../../models/userData");
const jwt = require("jsonwebtoken");

// ============================================
// JWT CONFIGURATION WITH VALIDATION
// ============================================

const JWT_SECRET = process.env.JWT_SECRET_USER_LOGIN;
const JWT_EXPIRY = process.env.JWT_EXPIRY || '7d';

// Validate JWT secret on startup
if (!JWT_SECRET) {
  throw new Error('❌ CRITICAL: JWT_SECRET_USER_LOGIN is not set in environment variables');
}

// Ensure minimum entropy
if (JWT_SECRET.length < 32) {
  throw new Error('❌ CRITICAL: JWT_SECRET must be at least 32 characters long');
}

// ============================================
// JWT AUTHENTICATION MIDDLEWARE
// ============================================

const authenticateJWT_user = async (req, res, next) => {
  try {
    let token;

    // Extract token from Authorization header or cookies
    const authHeader = req.header("Authorization");
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies?.token) {
      token = req.cookies.token;
    }

    if (!token) {
      req.user = null;
      return next();
    }

    // ✅ ENHANCED JWT VERIFICATION
    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET, {
        algorithms: ['HS256'], // ✅ Only accept HS256
        issuer: 'vidyari-app', // ✅ Verify issuer
        audience: 'users' // ✅ Verify audience
      });
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        console.log("⏰ Token expired for user attempt");
        req.user = null;
        return next();
      } else if (err.name === 'JsonWebTokenError') {
        console.log("🔒 Invalid token signature");
        req.user = null;
        return next();
      }
      throw err;
    }

    // ✅ Validate token structure
    if (!payload.userId || typeof payload.userId !== 'string') {
      console.log("❌ Invalid token structure");
      req.user = null;
      return next();
    }

    // Fetch user from database (never trust JWT completely)
    const user = await User.findById(payload.userId)
      .select("-passwordHash -twoFASecret -__v")
      .lean();

    if (user) {
      console.log(`✅ User authenticated: ${user._id}`);
      req.user = user;
    } else {
      console.log("⚠️ Token valid but user not found in database");
      req.user = null;
    }

    next();
  } catch (err) {
    console.error("❌ Authentication error:", err.message);
    req.user = null;
    next();
  }
};

module.exports = authenticateJWT_user;
```

---

## 4. FIX AUTHENTICATION - googleAuth.js (CRITICAL)

**File:** `routes/authentication/googleAuth.js`

Replace the entire authentication strategy section:

```javascript
require("dotenv").config();
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const mongoose = require("mongoose");
const User = require("../../models/userData");
const router = express.Router();
const bcrypt = require("bcrypt");

// ============================================
// VALIDATE REQUIRED ENVIRONMENT VARIABLES
// ============================================

const requiredVars = [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_CALLBACK_URL',
  'JWT_SECRET_USER_LOGIN',
  'SESSION_SECRET'
];

requiredVars.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`❌ MISSING: ${varName}`);
    process.exit(1);
  }
});

// ============================================
// MIDDLEWARE
// ============================================

router.use(express.json());

// ✅ STRICT RATE LIMITING FOR AUTH ENDPOINTS
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 attempts
  keyGenerator: (req) => req.body?.email || req.ip,
  message: '❌ Too many login attempts. Please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => !['POST'].includes(req.method)
});

const twoFALimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // Only 3 2FA attempts
  keyGenerator: (req) => req.body?.token || req.ip,
  message: '❌ 2FA attempt limit exceeded. Please try again in 5 minutes.',
  standardHeaders: true,
  legacyHeaders: false
});

router.use("/auth/", authLimiter); // ✅ Rate limit auth routes

// ============================================
// SECURE SESSION CONFIGURATION
// ============================================

// Using RedisStore is recommended for production (install: npm install redis connect-redis)
// For now, keeping simple configuration but MUST switch to Redis in production

const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // ✅ Prevent JavaScript access
    secure: process.env.NODE_ENV === 'production', // ✅ HTTPS only in production
    sameSite: 'strict', // ✅ CSRF protection
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    domain: process.env.NODE_ENV === 'production' 
      ? process.env.ALLOWED_ORIGINS?.split(',')[0]?.replace(/https?:\/\//, '')
      : undefined
  }
};

router.use(session(sessionConfig));

// ============================================
// INITIALIZE PASSPORT
// ============================================

router.use(passport.initialize());
router.use(passport.session());

// ============================================
// GOOGLE OAUTH STRATEGY
// ============================================

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, // ✅ From environment
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // ✅ From environment
      callbackURL: process.env.GOOGLE_CALLBACK_URL, // ✅ From environment
      state: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user exists
        let user = await User.findOne({ googleId: profile.id });
        let userWithEmail = await User.findOne({ email: profile.emails[0].value });

        if (!user && !userWithEmail) {
          // ✅ Create new user with validation
          let username = profile.displayName.replace(/\s+/g, '');
          let finalUsername = username;

          // Ensure unique username
          while (await User.findOne({ username: finalUsername })) {
            finalUsername = `${username}_${Math.floor(Math.random() * 10000)}`;
          }

          user = await User.create({
            googleId: profile.id,
            username: finalUsername,
            email: profile.emails[0].value,
            fullName: profile.displayName,
            profilePicUrl: profile.photos[0]?.value || null,
            isEmailVerified: true,
            role: 'Buyer'
          });

          console.log(`✅ New user created: ${user._id}`);
        } else if (userWithEmail && !user) {
          // Link Google ID to existing user
          await User.findByIdAndUpdate(userWithEmail._id, { googleId: profile.id });
          user = userWithEmail;
        }

        return done(null, user);
      } catch (err) {
        console.error('❌ Google OAuth error:', err.message);
        return done(err, null);
      }
    }
  )
);

// ============================================
// PASSPORT SERIALIZATION
// ============================================

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id).select("-passwordHash -twoFASecret");
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ============================================
// GOOGLE OAUTH ROUTES
// ============================================

router.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account"
  })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  async (req, res) => {
    try {
      const user = req.user;

      // Check if 2FA is enabled
      if (user.twoFAEnabled) {
        const tempToken = jwt.sign(
          { userId: user.id },
          process.env.JWT_SECRET_2FA, // ✅ Use 2FA secret from env
          { expiresIn: "5m", issuer: 'vidyari-app' }
        );

        return res.redirect(`/verify-2fa?token=${encodeURIComponent(tempToken)}`);
      }

      // Issue long-lived JWT
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET_USER_LOGIN, // ✅ From environment
        { expiresIn: "7d", issuer: 'vidyari-app', audience: 'users' }
      );

      // Set secure cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        domain: process.env.NODE_ENV === "production" 
          ? ".vidyari.com" 
          : undefined
      });

      console.log(`✅ User logged in via Google: ${user._id}`);
      res.redirect("/");
    } catch (err) {
      console.error('❌ Callback error:', err);
      res.redirect("/");
    }
  }
);

// ============================================
// 2FA VERIFICATION
// ============================================

router.post("/verify-2fa", twoFALimiter, async (req, res) => {
  try {
    const { token, code } = req.body;

    if (!token || !code) {
      return res.status(400).json({ error: 'Missing token or code' });
    }

    // ✅ Verify 2FA token
    const payload = jwt.verify(token, process.env.JWT_SECRET_2FA, {
      algorithms: ['HS256'],
      issuer: 'vidyari-app'
    });

    const user = await User.findById(payload.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: "base32",
      token: code,
      window: 2 // Allow 2 time steps
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }

    // Issue actual JWT token
    const jwtToken = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET_USER_LOGIN,
      { expiresIn: "7d", issuer: 'vidyari-app', audience: 'users' }
    );

    res.cookie("token", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    console.log(`✅ 2FA verification successful: ${user._id}`);
    res.json({
      success: true,
      message: "2FA verified successfully",
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    });
  } catch (err) {
    console.error("❌ 2FA verification error:", err.message);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '2FA token expired. Please log in again.' });
    }

    res.status(500).json({ error: 'Verification failed' });
  }
});

module.exports = router;
```

---

## 5. ADD CSRF PROTECTION TO PAYMENT ROUTES (CRITICAL)

**File:** `routes/paymentRoutes.js`

Add at the top:

```javascript
const csurf = require('csurf');
const cookieParser = require('cookie-parser');

// ============================================
// CSRF PROTECTION SETUP
// ============================================

const csrfProtection = csurf({
  cookie: false, // Using session instead
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Apply CSRF protection to all routes
router.use(csrfProtection);

// Add this route to provide CSRF token
router.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
```

Update the payment initialization route:

```javascript
router.post("/initiate-payment", 
  authenticateJWT, 
  requireAuth, 
  csrfProtection, // ✅ Add CSRF protection
  async (req, res) => {
    try {
      const { courseId } = req.body;
      const studentId = req.user._id;

      // Validate courseId is valid ObjectId
      if (!mongoose.Types.ObjectId.isValid(courseId)) {
        return res.status(400).json({ error: "Invalid course ID format" });
      }

      // ✅ Validate student is authenticated
      if (!studentId) {
        return res.status(401).json({ error: "Unauthorized access" });
      }

      if (!courseId) {
        return res.status(400).json({ error: "courseId is required" });
      }

      // Fetch course
      const course = await Course.findById(courseId).populate("userId", "email name");
      if (!course) {
        return res.status(404).json({ error: "Course not found" });
      }

      // ✅ Check if student already enrolled
      if (course.enrolledStudents?.includes(studentId)) {
        return res.status(400).json({ error: "You are already enrolled in this course" });
      }

      // Validate course price
      const price = course.price || 0;
      if (price <= 0) {
        return res.status(400).json({ error: "Course is not available for purchase" });
      }

      // Rest of implementation...
    } catch (error) {
      console.error("Payment initiation error:", error);
      res.status(500).json({ error: "Failed to initiate payment" });
    }
  }
);
```

Fix payment verification (CRITICAL AUTHORIZATION FIX):

```javascript
router.post("/verify-payment", 
  authenticateJWT, 
  requireAuth, 
  csrfProtection, // ✅ Add CSRF protection
  async (req, res) => {
    try {
      const { orderId, paymentId: razorpayPaymentId, signature } = req.body;
      const studentId = req.user._id;

      // ✅ CRITICAL: Validate input parameters
      if (!orderId || !razorpayPaymentId || !signature) {
        return res.status(400).json({ error: "Missing payment details" });
      }

      // ✅ CRITICAL: Verify payment belongs to current user
      const coursePayment = await CoursePayment.findOne({
        orderId: orderId,
        studentId: studentId // ✅ MUST verify ownership
      }).populate("courseId instructorId");

      if (!coursePayment) {
        console.error(`⚠️ Unauthorized payment access attempt: User ${studentId} tried to access order ${orderId}`);
        return res.status(403).json({ error: "Unauthorized payment access" });
      }

      // Verify signature
      const body = orderId + "|" + razorpayPaymentId;
      const expectedSignature = crypto
        .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
        .update(body)
        .digest("hex");

      if (expectedSignature !== signature) {
        await coursePayment.markAsFailed("Signature verification failed", "INVALID_SIGNATURE");
        return res.status(400).json({ error: "Payment verification failed" });
      }

      // Mark signature as verified
      coursePayment.signatureVerified = true;
      coursePayment.status = "PROCESSING";
      coursePayment.paymentId = razorpayPaymentId;
      await coursePayment.save();

      // ✅ Rest of implementation (enrollment logic with atomic operations)
      const course = await Course.findById(coursePayment.courseId);
      const instructor = await User.findById(coursePayment.instructorId);

      // Use atomic operation to prevent race conditions
      const updated = await Course.findOneAndUpdate(
        {
          _id: coursePayment.courseId,
          enrolledStudents: { $ne: studentId } // Only if not already enrolled
        },
        {
          $addToSet: { enrolledStudents: studentId }, // Atomic add to set
          $inc: { enrollCount: 1 }
        },
        { new: true }
      );

      if (!updated) {
        console.warn(`User ${studentId} is already enrolled in course ${coursePayment.courseId}`);
      }

      console.log(`✅ Payment verified and processed: ${orderId}`);
      res.json({
        success: true,
        message: "Payment verified and enrollment complete",
        courseId: coursePayment.courseId
      });
    } catch (error) {
      console.error("Payment verification error:", error);
      res.status(500).json({ error: "Failed to verify payment" });
    }
  }
);
```

---

## 6. FIX ADMIN AUTHENTICATION (CRITICAL)

**File:** `routes/adminRoutes.js`

Add proper admin verification:

```javascript
// ============================================
// ADMIN MIDDLEWARE WITH ENHANCED CHECKS
// ============================================

const verifyAdminAccess = async (req, res, next) => {
  try {
    // ✅ Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // ✅ Check if user is admin
    const adminRoles = ['admin', 'Admin', 'ADMIN'];
    if (!adminRoles.includes(req.user.role)) {
      console.warn(`🚨 Unauthorized admin access attempt by user: ${req.user._id}`);
      return res.status(403).json({ error: 'Admin access required' });
    }

    // ✅ Check if admin account is active
    if (req.user.isSuspended || req.user.isBanned) {
      console.warn(`🚨 Suspended/banned admin ${req.user._id} attempted access`);
      return res.status(403).json({ error: 'Your admin account has been suspended' });
    }

    next();
  } catch (err) {
    console.error('Admin verification error:', err);
    res.status(500).json({ error: 'Authorization check failed' });
  }
};

// Apply strict rate limiting to admin endpoints
const adminLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 50, // 50 requests per minute (higher than user, but still limited)
  message: 'Admin rate limit exceeded'
});

router.use(adminLimiter);
router.use(verifyAdminAccess);

// Now define admin routes...
router.get('/stats', async (req, res) => {
  // Admin verified at middleware level
  // ... rest of implementation
});
```

---

## 7. CREATE INPUT VALIDATION MODULE (HIGH)

**File:** `services/inputValidator.js` (NEW)

```javascript
const Joi = require('joi');
const validator = require('validator');

// ============================================
// VALIDATION SCHEMAS
// ============================================

const schemas = {
  coursePayment: Joi.object({
    courseId: Joi.string()
      .required()
      .regex(/^[0-9a-fA-F]{24}$/, 'valid MongoDB ID')
      .message('Invalid course ID format'),
    paymentMethod: Joi.string()
      .valid('card', 'netbanking', 'wallet', 'upi')
      .required()
  }),

  userUpdate: Joi.object({
    email: Joi.string()
      .email()
      .optional(),
    username: Joi.string()
      .alphanum()
      .min(3)
      .max(30)
      .optional(),
    bio: Joi.string()
      .max(300)
      .optional(),
    fullName: Joi.string()
      .max(100)
      .optional()
  }),

  loginRequest: Joi.object({
    email: Joi.string()
      .email()
      .required(),
    password: Joi.string()
      .min(8)
      .required()
  }),

  searchQuery: Joi.object({
    q: Joi.string()
      .max(100)
      .trim()
      .required(),
    category: Joi.string()
      .max(50)
      .optional(),
    limit: Joi.number()
      .max(100)
      .default(10)
      .optional()
  })
};

// ============================================
// VALIDATION MIDDLEWARE FACTORY
// ============================================

const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body || req.query, {
      abortEarly: false,
      stripUnknown: true, // Remove unknown fields
      convert: true // Convert types when possible
    });

    if (error) {
      const messages = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message
      }));

      return res.status(400).json({
        error: 'Validation failed',
        details: messages
      });
    }

    // Attach validated data
    req.validated = value;
    next();
  };
};

// ============================================
// CUSTOM VALIDATORS
// ============================================

const sanitizers = {
  sanitizeEmail: (email) => {
    return validator.normalizeEmail(email);
  },

  sanitizeString: (str) => {
    return validator.escape(str).trim();
  },

  validateMongoId: (id) => {
    return /^[0-9a-fA-F]{24}$/.test(id);
  },

  validateFileSize: (size, maxSize = 500 * 1024 * 1024) => {
    return size <= maxSize;
  },

  sanitizeSearchQuery: (query) => {
    // Escape regex special characters
    return query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
};

module.exports = {
  validate,
  schemas,
  sanitizers
};
```

---

## ✅ IMPLEMENTATION CHECKLIST

After applying all fixes, verify:

```bash
# 1. Test CORS
curl -v -H "Origin: https://attacker.com" \
  https://vidyari.com/api/payments/balance \
  2>&1 | grep "Access-Control"
# Should NOT see Access-Control-Allow-Origin header for attacker.com

# 2. Test CSRF Protection
curl -X POST https://vidyari.com/api/payments/initiate-payment \
  -H "Content-Type: application/json" \
  -d '{"courseId":"123"}' \
  -c cookies.txt -b cookies.txt
# Should return 403 Forbidden without CSRF token

# 3. Test Rate Limiting
for i in {1..10}; do
  curl -X POST https://vidyari.com/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}'
  sleep 0.1
done
# After 5 attempts, should get rate limit error

# 4. Test Input Validation
curl -X POST https://vidyari.com/api/payments/initiate-payment \
  -H "Content-Type: application/json" \
  -d '{"courseId":"INVALID"}'
# Should return validation error

# 5. Verify No Hardcoded Secrets
grep -r "secret\|password\|key" --include="*.js" . | grep -v node_modules
# Should return nothing or only env variable references
```

---

**STATUS:** Implementation Guide Ready  
**NEXT STEP:** Apply fixes one by one and test thoroughly

