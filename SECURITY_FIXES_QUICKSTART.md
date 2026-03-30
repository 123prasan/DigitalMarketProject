# 🚨 CRITICAL SECURITY FIXES - QUICK START GUIDE

## ⏰ EMERGENCY ACTION ITEMS (DO TODAY)

### 1️⃣ REVOKE ALL EXPOSED CREDENTIALS (15 MINUTES)

**Google OAuth:**
- Login to Google Cloud Console
- Go to APIs & Services > Credentials
- Delete credentials: `999822886943-57g7g478kmkq4aqebukvlei2mijppqof`
- Create new credentials
- Update `.env`

**AWS Credentials:**
```bash
# AWS Console → Identity & Access Management (IAM)
# Delete user/key: AKIA2OQX6ZSLZNKOSPEG
# Create new access key
# Rotate immediately in all deployments
```

**Razorpay:**
- Login to Razorpay Dashboard
- Settings > API Keys
- Regenerate both test and live keys
- Update `.env`

**MongoDB:**
- Connect to MongoDB Atlas
- Database Access > Edit User
- Change password for `prasannaprasanna35521`
- Update connection string

**Supabase:**
- Open Supabase Dashboard
- Settings > API Keys
- Regenerate service role key
- Update `.env`

**Gmail App Password:**
- Google Account > Security
- App passwords
- Delete current app password
- Create new one
- Update `.env`

---

### 2️⃣ REMOVE .ENV FROM GIT (15 MINUTES)

```bash
# Remove from git history
git filter-branch --tree-filter 'rm -f .env' HEAD

# Update .gitignore
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore
echo "serviceAccountKey.json" >> .gitignore
echo "private_keys/" >> .gitignore

git add .gitignore
git commit -m "Add sensitive files to gitignore"
git push -f origin main --prune
```

**Create** `.env.example`:
```env
# Database
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/db

# Authentication
JWT_SECRET_USER_LOGIN=<min-32-character-key>
JWT_SECRET=<min-32-character-key>
JWT_SECRET_2FA=<min-32-character-key>
SESSION_SECRET=<min-32-character-key>

# Google OAuth
GOOGLE_CLIENT_ID=<your-client-id>.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=<your-client-secret>
GOOGLE_CALLBACK_URL=https://vidyari.com/auth/google/callback

# AWS
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=ap-south-1
AWS_S3_BUCKET_NAME=vidyari3

# Payment
RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...

# Other
NODE_ENV=production
PORT=8000
```

---

### 3️⃣ FIX CRITICAL CODE VULNERABILITIES (1 HOUR)

#### A. Fix CORS (server.js)
```javascript
// ❌ BEFORE
app.use(cors());

// ✅ AFTER
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://vidyari.com'],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
};
app.use(cors(corsOptions));
```

#### B. Add Security Headers (server.js)
```javascript
// ✅ ADD THIS
const helmet = require('helmet');
app.use(helmet());

// Add after other middleware
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));
```

#### C. Add CSRF Protection (server.js)
```javascript
const csurf = require('csurf');

const csrfProtection = csurf({ 
  cookie: false,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Add to POST/PUT/DELETE routes
app.post('/api/payments/initiate-payment', csrfProtection, requireAuth, paymentController);
```

#### D. Implement Rate Limiting (server.js)
```javascript
const rateLimit = require('express-rate-limit');

// Auth rate limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
  keyGenerator: (req) => req.body?.email || req.ip,
  message: 'Too many login attempts'
});

// 2FA rate limiter
const twoFALimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 3,
  message: '2FA attempt limit exceeded'
});

// Global API limiter
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100
});

app.use('/api/', apiLimiter);
app.post('/auth/login', authLimiter, loginController);
app.post('/verify-2fa', twoFALimiter, verify2FAController);
```

#### E. Fix Session Configuration (googleAuth.js)
```javascript
// ❌ BEFORE
router.use(session({
  secret: "supersecret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // ❌ NO
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

// ✅ AFTER
router.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new RedisStore({ client: redisClient }), // ✅ Use Redis
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    domain: process.env.NODE_ENV === 'production' ? '.vidyari.com' : undefined
  },
}));
```

#### F. Fix JWT Validation (jwtAuth.js)
```javascript
// ✅ FIXED
const JWT_SECRET = process.env.JWT_SECRET_USER_LOGIN;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET_USER_LOGIN is required');
}

const authenticateJWT_user = async (req, res, next) => {
  try {
    let token;
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

    // ✅ Enhanced verification
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'vidyari-app'
    });

    if (!payload.userId) {
      throw new Error('Invalid token structure');
    }

    const user = await User.findById(payload.userId).select("-passwordHash");
    req.user = user || null;
    next();
  } catch (err) {
    console.error("Auth error:", err.message);
    req.user = null;
    next();
  }
};
```

#### G. Fix Payment Authorization (paymentRoutes.js)
```javascript
// ✅ ADD AUTHORIZATION CHECKS
router.post("/verify-payment", authenticateJWT, requireAuth, async (req, res) => {
  const { orderId, paymentId, signature } = req.body;
  const studentId = req.user._id;

  // ✅ VERIFY PAYMENT BELONGS TO USER
  const coursePayment = await CoursePayment.findOne({
    orderId: orderId,
    studentId: studentId // ✅ CRITICAL: Verify ownership
  });

  if (!coursePayment) {
    return res.status(403).json({ error: 'Unauthorized payment access' });
  }

  // ... rest of verification
});
```

---

### 4️⃣ REMOVE EXPOSED FILES (10 MINUTES)

```bash
# Remove service account key
git rm --cached serviceAccountKey.json
echo "serviceAccountKey.json" >> .gitignore
git commit -m "Remove Firebase key"

# Remove test files with credentials
git rm --cached demoemail.js
rm demoemail.js
git commit -m "Remove test file with credentials"
```

---

### 5️⃣ REMOVE CREDENTIAL LOGGING (5 MINUTES)

```javascript
// In server.js, REMOVE this line:
console.log("Mongo URI:", process.env.MONGODB_URI);

// Replace with:
console.log("✅ Database connection successful");
```

---

## 👷 DEPLOYMENT CHECKLIST

Before deploying to production:

```bash
# 1. Install security dependencies
npm install helmet express-rate-limit joi validator sanitizer express-mongo-sanitize helmet-csp

# 2. Run security audit
npm audit
npm audit fix

# 3. Check for hardcoded secrets
grep -r "password\|secret\|key" --include="*.js" --exclude-dir=node_modules .

# 4. Verify no .env files in repo
git ls-files | grep -E "\.env|key|secret|password"

# 5. Production env vars set correctly
echo "Checking environment variables..."
[[ -n "$JWT_SECRET_USER_LOGIN" ]] && echo "✅ JWT_SECRET_USER_LOGIN set" || echo "❌ JWT_SECRET_USER_LOGIN missing"
[[ -n "$MONGODB_URI" ]] && echo "✅ MONGODB_URI set" || echo "❌ MONGODB_URI missing"
# ... check all others

# 6. HTTPS/SSL configured
# [Confirm with DevOps/deployment team]

# 7. WAF rules configured
# [Confirm with security team]

# 8. Backups enabled
# [Confirm with DevOps]

# 9. Monitoring/alerting setup
# [Confirm with SRE/monitoring team]

# 10. Incident response plan ready
# [Review with security team]
```

---

## 🔑 ENVIRONMENT VARIABLES TO CREATE

Generate secure random values:

```bash
# Generate for .env (NEVER commit)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Store these securely:
JWT_SECRET_USER_LOGIN=<64 character hex value>
JWT_SECRET=<64 character hex value>
JWT_SECRET_2FA=<64 character hex value>
SESSION_SECRET=<64 character hex value>

# Update .env locally and NEVER commit
```

---

## 🧪 SECURITY TESTING

After fixes, test with:

```bash
# 1. Test CORS
curl -H "Origin: https://attacker.com" https://vidyari.com/api/test
# Should NOT have Access-Control-Allow-Origin in response

# 2. Test CSRF
# Try POST without CSRF token, should fail

# 3. Test Rate Limiting
for i in {1..10}; do curl https://vidyari.com/auth/login -d "email=test@test.com"; done
# After 5 attempts, should get rate limit error

# 4. Test SQL Injection
curl "https://vidyari.com/api/search?q='; DROP TABLE users;--"
# Should be sanitized/escaped

# 5. Test IDOR
# Try to access another user's course: /api/courses/other-user-course-id
# Should get 403 Forbidden
```

---

## 📊 BEFORE/AFTER CODE EXAMPLES

### Example 1: CORS
```javascript
// ❌ BEFORE
app.use(cors()); // Allows ALL origins

// ✅ AFTER
app.use(cors({
  origin: ['https://vidyari.com', 'https://www.vidyari.com'],
  credentials: true
}));
```

### Example 2: Session Secret
```javascript
// ❌ BEFORE
secret: "supersecret"

// ✅ AFTER
secret: process.env.SESSION_SECRET
```

### Example 3: Rate Limiting
```javascript
// ❌ BEFORE
No rate limiting

// ✅ AFTER
const limiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
app.post('/auth/login', limiter, handler);
```

### Example 4: CSRF
```javascript
// ❌ BEFORE
app.post('/api/payments/initiate', paymentHandler); // No CSRF token

// ✅ AFTER
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: false });

app.post('/api/payments/initiate', csrfProtection, paymentHandler);

// Client must include X-CSRF-Token header
```

### Example 5: Authorization
```javascript
// ❌ BEFORE
const payment = await Payment.findOne({ orderId: req.body.orderId });

// ✅ AFTER
const payment = await Payment.findOne({
  orderId: req.body.orderId,
  studentId: req.user._id // Verify ownership
});

if (!payment) {
  return res.status(403).json({ error: 'Unauthorized' });
}
```

---

## 📞 NEXT STEPS

1. **Today:** Execute all items in "EMERGENCY ACTION ITEMS"
2. **This Week:** Fix all CRITICAL vulnerabilities
3. **Next Week:** Implement HIGH severity fixes
4. **Next Month:** Complete MEDIUM severity fixes
5. **Ongoing:** Regular security audits

---

## 📚 RESOURCES

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/nodejs-security/)
- [Express Security](https://expressjs.com/en/advanced/best-practice-security.html)
- [MongoDB Security](https://docs.mongodb.com/manual/security/)
- [Node.js Helmet](https://helmetjs.github.io/)

---

**CRITICAL:** Do not skip any steps. This application has severe security issues.

