# Activity Tracking & Recommendation System - Integration Guide

## Overview
This system tracks user activities (clicks, searches, page views, time spent) and uses that data to provide personalized recommendations for digital assets (courses and files).

## Components

### 1. Database Model
- **File**: `models/userActivity.js`
- Tracks: page views, clicks, searches, lessons, downloads, time spent
- Auto-expires after 90 days
- Indexed for fast queries

### 2. API Routes
- **File**: `routes/activityTrackingRoutes.js`
- Endpoints:
  - `POST /api/track-activity` - Record user activities
  - `GET /api/user-interests` - Get top interests
  - `GET /api/trending-content` - Get trending courses/files
  - `POST /api/recommend-assets` - Get personalized recommendations
  - `GET /api/activity-summary` - User activity statistics
  - `GET /api/user-search-history` - Recent searches
  - `DELETE /api/clear-activity` - Clear activity data (privacy)

### 3. Frontend Tracking Library
- **File**: `public/js/activity-tracker.js`
- Auto-tracks: page views, clicks, scrolls, searches, time spent
- Manual tracking: lessons, file downloads, previews
- Batched submissions to reduce server load

## Integration Steps

### Step 1: Update server.js
Add this line in your server.js file (with other route imports):

```javascript
const activityTrackingRoutes = require('./routes/activityTrackingRoutes');
```

Then register the routes (typically after other routes):
```javascript
app.use('/api', activityTrackingRoutes);
```

**Location in server.js**: Find the section with `app.use('/api'` or route registrations and add these lines.

---

### Step 2: Add uuid dependency
The activity routes use the `uuid` package. Install it:

```bash
npm install uuid
```

---

### Step 3: Enable Frontend Tracking
Add this script to your **base layout/template** (before closing `</body>` tag):

**In your main EJS layout or header template (e.g., `views/layout.ejs` or include in your base template):**

```html
<!-- Activity Tracking -->
<script src="/js/activity-tracker.js"></script>
<script>
  // Initialize activity tracker when DOM is ready
  document.addEventListener('DOMContentLoaded', function() {
    ActivityTracker_Instance.init({
      autoTrack: true,
      batchInterval: 10000,
      trackElements: [
        'a[href]',
        'button',
        '.download-btn',
        '.like-btn',
        '.review-btn',
        '.enroll-btn',
        '.add-to-cart',
        '.filter-btn',
        '.search-form input',
        '[data-track]'  // Any element with data-track attribute
      ]
    });
  });
</script>
```

---

### Step 4: Add User ID to Frontend
For the tracking to work, the frontend needs to know the current user ID. Add this to your layout template (in the `<body>` tag or near it):

```html
<div style="display:none;" data-user-id="<%= user ? user._id : '' %>"></div>

<!-- Or in a script tag: -->
<script>
  window.currentUserId = '<%= user ? user._id : "" %>';
  localStorage.setItem('userId', window.currentUserId);
</script>
```

---

### Step 5: Manual Tracking for Specific Actions

**Track Lesson Start/Completion** (in your course player view):
```javascript
// When lesson starts
ActivityTracker_Instance.trackLessonStart('lesson-id', 'course-id');

// When lesson completes
ActivityTracker_Instance.trackLessonComplete('lesson-id', 'course-id');
```

**Track File Download** (in your file details view):
```javascript
// After download initiated
ActivityTracker_Instance.trackFileDownload('file-id');
```

**Track File Preview**:
```javascript
ActivityTracker_Instance.trackFilePreview('file-id');
```

---

### Step 6: Display Recommendations

**Get User's Personalized Recommendations**:
```javascript
const recommendations = await ActivityTracker_Instance.getRecommendations(10, 'both');
console.log('Recommended courses/files:', recommendations.recommendations);
console.log('Top categories:', recommendations.topCategories);
```

**Get Trending Content** (for homepage/discovery):
```javascript
const trending = await ActivityTracker_Instance.getTrendingContent(7, 10);
// Use trending data to populate a "Trending Now" section
```

**Get User's Top Interests**:
```javascript
const interests = await ActivityTracker_Instance.getUserInterests(10);
// Display to user or use for personalization
```

---

## Usage Examples

### Example 1: Add Recommendations Widget to Homepage
```html
<div id="recommendations-section" style="display:none;">
  <h2>Recommended For You</h2>
  <div id="recommendations-container"></div>
</div>

<script>
  document.addEventListener('DOMContentLoaded', async function() {
    const user = '<%= user ? user._id : "" %>';
    
    if (user) {
      try {
        const recommendations = await ActivityTracker_Instance.getRecommendations(8, 'both');
        
        if (recommendations.recommendations.length > 0) {
          const container = document.getElementById('recommendations-container');
          recommendations.recommendations.forEach(item => {
            const content = item.content || {};
            const html = `
              <div class="recommendation-card">
                <h3>${content.title || 'N/A'}</h3>
                <p>Category: ${content.category || 'N/A'}</p>
                <p>Price: $${content.price || '0'}</p>
                <a href="${content.slug ? `/courses/${content.slug}` : '#'}">View</a>
              </div>
            `;
            container.innerHTML += html;
          });
          document.getElementById('recommendations-section').style.display = 'block';
        }
      } catch (error) {
        console.error('Error loading recommendations:', error);
      }
    }
  });
</script>
```

### Example 2: Display Trending Courses on Homepage
```html
<div id="trending-section">
  <h2>Trending Now</h2>
  <div id="trending-container"></div>
</div>

<script>
  document.addEventListener('DOMContentLoaded', async function() {
    try {
      const trending = await ActivityTracker_Instance.getTrendingContent(7, 6);
      const container = document.getElementById('trending-container');
      
      trending.forEach(item => {
        const content = item.content || {};
        const uniqueUsers = item.uniqueUserCount || 0;
        const html = `
          <div class="trending-card">
            <h3>${content.title || 'N/A'}</h3>
            <p>Engaging with ${uniqueUsers} users</p>
            <p>Average time: ${Math.round(item.avgTimeSpent / 60)} min</p>
            <a href="${content.slug ? `/courses/${content.slug}` : '#'}">Explore</a>
          </div>
        `;
        container.innerHTML += html;
      });
    } catch (error) {
      console.error('Error loading trending:', error);
    }
  });
</script>
```

### Example 3: User Activity Dashboard
```html
<div id="activity-dashboard">
  <h2>Your Activity</h2>
  <div id="activity-summary"></div>
</div>

<script>
  document.addEventListener('DOMContentLoaded', async function() {
    const user = '<%= user ? user._id : "" %>';
    
    if (user) {
      const summary = await ActivityTracker_Instance.getActivitySummary(30);
      const container = document.getElementById('activity-summary');
      
      let html = '<ul>';
      summary.forEach(activity => {
        html += `
          <li>
            <strong>${activity._id}</strong>: ${activity.count} times
            <br/>Avg time: ${Math.round(activity.avgTimeSpent / 60)} min
          </li>
        `;
      });
      html += '</ul>';
      container.innerHTML = html;
    }
  });
</script>
```

---

## Data Collection

The system automatically collects:

| Activity | Tracked | Data |
|----------|---------|------|
| **Page Views** | ✓ | Page type, referrer, timestamp |
| **Clicks** | ✓ | Element ID/class, page context |
| **Searches** | ✓ | Query text, results count |
| **Time Spent** | ✓ | Duration in seconds, scroll depth |
| **Lesson Progress** | ✓ | Lesson ID, course ID, completion status |
| **File Downloads** | ✓ | File ID, timestamp |
| **Scroll Depth** | ✓ | Percentage of page scrolled |
| **Session Info** | ✓ | Session ID (persistent for 24h), user agent |

---

## Privacy & Data Management

### User Data Deletion
Users can delete their activity data via:
```javascript
ActivityTracker_Instance.clearActivity();
```

### Data Retention
- Activity data auto-expires after 90 days
- No sensitive information (passwords, payment data) is tracked
- Only behavioral data is collected

### GDPR Compliance
- Data is tied to user ID, supports right-to-deletion
- Clear privacy policy explanation needed in user agreement
- Session IDs are anonymous until authenticated

---

## Advanced Features

### 1. Category-Based Recommendations
The system learns user's interests by analyzing their interactions with courses/files in specific categories.

### 2. Trending Content Algorithm
- Considers: unique user count, interaction frequency, average time spent
- Updates regularly (configurable in API)
- Shows popular content independent of user history

### 3. Search History Tracking
- Deduplicates and counts search frequency
- Shows what users search for most
- Helps with content discovery optimization

### 4. Session Persistence
- Session ID stored in localStorage for 24 hours
- Groups all user activities within a session
- Helps understand user behavior patterns

---

## Troubleshooting

### Activities Not Being Tracked
1. Check browser console for errors: `F12 → Console`
2. Verify user is logged in (not guest)
3. Check Network tab to see if `/api/track-activity` requests are succeeding
4. Verify `data-user-id` is being set correctly

### Recommendations Not Showing
1. Check if user has enough activity history
2. Verify user's interests match available courses/files
3. Check if recommended courses are marked as `published: true`

### Database Growing Too Large
- Activity records auto-expire after 90 days (TTL index)
- To manually clean old data:
```javascript
db.useractivities.deleteMany({ createdAt: { $lt: new Date(Date.now() - 90*24*60*60*1000) } })
```

---

## Performance Considerations

- Activity submissions are batched to reduce server load
- Database indices optimize common queries
- Recommendations are generated on-demand (can be cached)
- Consider implementing Redis caching for trending content

---

## Next Steps

1. ✅ Install dependencies: `npm install uuid`
2. ✅ Add routes to `server.js`
3. ✅ Include tracking script in layout template
4. ✅ Set user ID in frontend
5. ✅ Add recommendations widget to homepage
6. ✅ Test tracking in browser console
7. ✅ Monitor data collection for first week
8. ✅ Deploy recommendations to users

---

## API Documentation

### POST /api/track-activity
Records a user activity.

**Required Auth**: JWT token (user must be logged in)

**Body**:
```json
{
  "activityType": "click|search|page_view|time_spent|lesson_start|lesson_complete|file_download",
  "pageType": "course|file|search|home|category",
  "courseId": "optional-mongo-id",
  "fileId": "optional-mongo-id",
  "searchQuery": "optional-search-text",
  "timeSpentSeconds": 120,
  "scrollDepth": 75,
  "metadata": {}
}
```

### GET /api/user-interests
Returns user's top interests based on activity.

**Query Params**: `limit=10`

**Response**:
```json
[
  {
    "interactionCount": 5,
    "timeSpent": 600,
    "content": { "title": "...", "category": "..." }
  }
]
```

### POST /api/recommend-assets
Gets personalized recommendations.

**Required Auth**: JWT token

**Body**:
```json
{
  "limit": 10,
  "assetType": "both|courses|files"
}
```

### GET /api/trending-content
Gets trending courses/files across all users.

**Query Params**: `days=7&limit=10`

---
