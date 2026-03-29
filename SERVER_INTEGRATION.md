# Server.js Integration Step-by-Step

## Step 1: Add Import at Top of server.js

**Location**: Line 55 (near other route imports)

**Find this section**:
```javascript
const fileReviewRoutes = require("./routes/fileReviewRoutes");
const progressRoutes = require("./routes/progressroutes");
const paymentRoutes = require("./routes/paymentRoutes");
```

**Add after it**:
```javascript
const activityTrackingRoutes = require('./routes/activityTrackingRoutes');
```

**Full context**:
```javascript
const fileReviewRoutes = require("./routes/fileReviewRoutes");
const progressRoutes = require("./routes/progressroutes");
const paymentRoutes = require("./routes/paymentRoutes");
const activityTrackingRoutes = require('./routes/activityTrackingRoutes');  // ← ADD THIS LINE
const instructorPayoutRoutes = require("./routes/instructorPayoutRoutes");
```

---

## Step 2: Register Routes with Express App

**Location**: Line 345 (in the app.use section)

**Find this section**:
```javascript
app.use("/api/courses", courseRoutes);
app.use("/api/reviews", reviewRoutes);
app.use("/api/file-reviews", fileReviewRoutes);
app.use("/api/progress", progressRoutes);
app.use("/api/payments", paymentRoutes);
app.use("/api/instructor", instructorPayoutRoutes);
```

**Add this new line**:
```javascript
app.use('/api', activityTrackingRoutes);
```

**Full context after addition**:
```javascript
app.use("/api/courses", courseRoutes);
app.use("/api/reviews", reviewRoutes);
app.use("/api/file-reviews", fileReviewRoutes);
app.use("/api/progress", progressRoutes);
app.use("/api/payments", paymentRoutes);
app.use('/api', activityTrackingRoutes);  // ← ADD THIS LINE
app.use("/api/instructor", instructorPayoutRoutes);
```

---

## Step 3: Verify Installation

After making these changes, verify the setup:

```bash
# 1. Install uuid dependency (if not already done)
npm install uuid

# 2. Restart the server
npm start

# 3. Check for errors in console - should see no errors related to activity tracking
```

**Expected console output**:
```
Server running on port 3000
Connected to MongoDB
ActivityTracker routes registered successfully
```

---

## Step 4: Test the Routes

Once the server is running, test the routes:

```bash
# Test 1: Create a test activity
curl -X POST http://localhost:3000/api/track-activity \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "activityType": "page_view",
    "pageType": "home"
  }'

# Test 2: Get user interests
curl http://localhost:3000/api/user-interests \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Test 3: Get trending content
curl http://localhost:3000/api/trending-content?days=7&limit=10
```

---

## Troubleshooting

### Error: "Cannot find module './routes/activityTrackingRoutes'"
- Make sure file `routes/activityTrackingRoutes.js` exists
- Check the path is correct relative to server.js
- Verify file is not named differently

### Error: "uuid is not defined"
- Run: `npm install uuid`
- Make sure package.json has uuid in dependencies
- Restart the server

### Error: "jwtAuth is not defined" in the routes file
- The route already imports: `const jwtAuth = require('./jwtAuth');`
- Make sure [routes/authentication/jwtAuth.js](routes/authentication/jwtAuth.js) exists (it should)

### Routes returning 404
- Make sure you used `app.use('/api', activityTrackingRoutes);`
- Check that routes are registered BEFORE error handling middleware
- Verify token is included in Authorization header

---

## Complete Integration Verification Checklist

- [ ] File `routes/activityTrackingRoutes.js` created
- [ ] File `models/userActivity.js` created
- [ ] File `public/js/activity-tracker.js` created
- [ ] Import added to server.js (line ~55)
- [ ] Routes registered with `app.use('/api', activityTrackingRoutes);` (line ~346)
- [ ] `npm install uuid` completed
- [ ] Server started without errors
- [ ] Can POST to `/api/track-activity`
- [ ] Can GET from `/api/trending-content`
- [ ] Database `useractivities` collection created automatically
- [ ] Frontend script loads without errors

---

## Available Routes After Integration

Once integrated, these routes will be available:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/track-activity` | Required | Record user activity |
| GET | `/api/user-interests` | Required | Get user's top interests |
| GET | `/api/trending-content` | Optional | Get trending courses/files |
| POST | `/api/recommend-assets` | Required | Get personalized recommendations |
| GET | `/api/activity-summary` | Required | Get user activity stats |
| GET | `/api/user-search-history` | Required | Get user's search history |
| DELETE | `/api/clear-activity` | Required | Delete user's activity data |

---

## Next Steps After Integration

1. ✅ Integrate routes into server.js
2. ✅ Install dependencies
3. ✅ Add activity tracking script to views
4. ✅ Set user ID in frontend
5. ✅ Add recommendations widget to homepage
6. ✅ Monitor activity collection
7. ✅ Deploy recommendations

See [ACTIVITY_TRACKING_GUIDE.md](ACTIVITY_TRACKING_GUIDE.md) for complete implementation guide.

---
