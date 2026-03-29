# User Activity Tracking - Real Data Verification Guide

## System Overview

The activity tracking system tracks REAL user behavior across your platform:
- **Page views** - When users visit courses/files
- **Clicks** - On buttons, links, download buttons, etc.
- **Searches** - Search queries and results
- **Time spent** - Duration on pages
- **Scroll depth** - How far down the page users scroll

## How to Verify Real Data is Being Tracked

### Step 1: Open Browser Developer Console
1. Press **F12** or **Ctrl+Shift+I** to open DevTools
2. Go to the **Console** tab
3. Look for messages starting with ✓ and ⚠

### Step 2: Check Initialization
When you visit any page (logged in), you should see:
- **✓ ActivityTracker initialized - User ID:** (if logged in)
- **⚠ ActivityTracker initialized - No user ID (guest user)** (if not logged in)

**Note:** Activities are ONLY tracked for authenticated users. Guest users are not tracked.

### Step 3: Trigger Activities and Watch Console
1. **Click buttons/links** on pages
   - Console log: `✓ Activity sent: { type: 'click', userId: '... }`
   
2. **Perform a search**
   - Console log: `✓ Activity sent: { type: 'search', userId: '... }`
   
3. **Browse a course or file**
   - Console log: `✓ Activity sent: { type: 'page_view', userId: '... }`

### Step 4: Server Logs Verification
Check your terminal/server logs for:
```
✓ Activity tracked for user: {
  userId: '...',
  activityType: 'click',
  courseId: null,
  fileId: null,
  timestamp: '2026-03-29T...'
}
```

## Data Storage

Activities are stored in MongoDB under the `useractivities` collection with:
- **userId** - User who performed the activity
- **activityType** - Type: click, page_view, search, time_spent, download, etc.
- **courseId/fileId** - Which course/file was interacted with
- **scrollDepth** - Percentage of page scrolled
- **timeSpentSeconds** - Time spent on page
- **timestamp** - When the activity occurred

## Admin Dashboard Real-Time Data

The admin "User Behavior" section shows REAL aggregated data:

1. **Total Activities** - Count of all tracked activities
2. **Active Users** - Number of unique users who performed activities
3. **Avg Time Spent** - Average time spent on trending content
4. **Activity Trends Chart** - Line chart of activities over 7 days
5. **Activity Type Distribution** - Breakdown by activity type
6. **Top Searched Queries** - Most frequently searched terms
7. **Top Engaged Users** - Users with most interactions
8. **Trending Content** - Most popular courses/files
9. **Interest Categories** - Popular content categories
10. **Activity Heatmap** - Activity by hour of day

## Testing with Real User Activity

### To generate sample data:
1. **Log in** to your platform as a regular user
2. **Browse courses** - Click course links
3. **View files** - Open and browse files
4. **Perform searches** - Use search functionality
5. **Engage content** - Click buttons, like, review, etc.

### Then check admin dashboard
1. Log in to `/admin-login` 
2. Click **User Behavior** menu
3. You should see real aggregated data from your activities

## Troubleshooting Real Data Issues

### ❌ No data in admin dashboard?
1. **Check browser console** - Look for ✓ Activity sent messages
2. **Verify you're logged in** - Activities only tracked for authenticated users
3. **Check server logs** - Should show "✓ Activity tracked for user"
4. **Wait for activities** - Data only appears after user interactions
5. **Check MongoDB** - Query: `db.useractivities.find()`

### ❌ Console shows "User not authenticated"?
1. Make sure you're **logged in** to the platform
2. Check if JWT cookie is present (DevTools > Application > Cookies)
3. Cookie name should be `jwt`

### ❌ Server shows "Unauthorized"?
1. The `/api/track-activity` endpoint requires authentication
2. Ensure JWT token is being sent with requests
3. Check if JWT_SECRET in .env is correct

## Data Privacy & Retention

- Activities are automatically deleted after **90 days**
- TTL index on `createdAt` field handles cleanup
- User can clear their activity: `DELETE /api/clear-activity`

## Sample Real Data Output

### Activity Summary
```json
{
  "_id": "click",
  "count": 45,
  "avgTimeSpent": 1205  // seconds
}
```

### Trending Content (Enriched with real titles)
```json
{
  "_id": { "courseId": "123abc" },
  "totalInteractions": 87,
  "uniqueUserCount": 12,
  "avgTimeSpent": 3420,
  "content": {
    "_id": "123abc",
    "title": "Web Development Masterclass",
    "category": "Programming",
    "price": 299,
    "rating": 4.8,
    "enrollCount": 2541
  }
}
```

## Next Steps

1. ✅ Verify tracking is working (check console logs)
2. ✅ Generate user activities (browse, click, search)
3. ✅ Monitor admin dashboard (should show real data)
4. ✅ Use data for recommendations (API: `/api/recommend-assets`)
5. ✅ Monitor engaging content (trending courses/files)

---

**Key Point:** The system tracks REAL user behavior. Data quality depends on actual user interactions with your platform. More users = More data = Better recommendations.
