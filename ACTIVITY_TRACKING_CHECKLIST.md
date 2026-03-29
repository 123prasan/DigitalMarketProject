# Activity Tracking Implementation Checklist

## Quick Setup (15 minutes)

### Phase 1: Backend Setup (5 minutes)

- [ ] **Install dependencies**
  ```bash
  npm install uuid
  ```

- [ ] **Add import to server.js (line ~55)**
  ```javascript
  const activityTrackingRoutes = require('./routes/activityTrackingRoutes');
  const User = require("./models/userData");
  ```

- [ ] **Register routes in server.js (add after line 345)**
  ```javascript
  app.use('/api', activityTrackingRoutes);
  ```

### Phase 2: Frontend Setup (10 minutes)

- [ ] **Include tracking script in base template**
  
  Find your main layout template (usually `views/layout.ejs` or similar base template used by all pages).
  
  Add before `</body>`:
  ```html
  <!-- Activity Tracking -->
  <script src="/js/activity-tracker.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      ActivityTracker_Instance.init({ autoTrack: true });
    });
  </script>
  ```

- [ ] **Add user ID to DOM**
  
  In the same template, add inside `<body>` tag or near `<script>`:
  ```html
  <div style="display:none;" data-user-id="<%= user ? user._id : '' %>"></div>
  ```

- [ ] **Test it**
  
  1. Open your app in browser
  2. Log in as a user
  3. Open DevTools (F12)
  4. Go to Console tab
  5. Try: `ActivityTracker_Instance.getUserInterests()` 
  6. Check Network tab for `/api/track-activity` requests (should appear when clicking)

---

## Integration by Sections

### Dashboard/Homepage - Add Recommendations

Add this to your homepage view (e.g., `views/home.ejs` or dashboard):

```html
<div id="recommendations-section" style="display:none; margin: 20px 0;">
  <h2>Recommended For You</h2>
  <div id="recommendations-container" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px;">
    <!-- Recommendations will be loaded here -->
  </div>
</div>

<script>
  document.addEventListener('DOMContentLoaded', async function() {
    const user = '<%= user ? user._id : "" %>';
    
    if (user) {
      try {
        const recommendations = await ActivityTracker_Instance.getRecommendations(8, 'both');
        
        if (recommendations.recommendations && recommendations.recommendations.length > 0) {
          const container = document.getElementById('recommendations-container');
          container.innerHTML = '';
          
          recommendations.recommendations.forEach(item => {
            const content = item.content || {};
            const isCourse = item._id.courseId;
            const link = isCourse 
              ? `/course/${content.slug}` 
              : `/files/${content.slug}`;
            
            const html = `
              <div style="border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                <h3 style="margin: 0 0 10px 0;">${content.title || 'N/A'}</h3>
                <p style="margin: 5px 0; color: #666;">${content.category || ''}</p>
                <p style="margin: 5px 0; font-weight: bold;">$${content.price || '0'}</p>
                <a href="${link}" style="color: #007bff; text-decoration: none;">View Details →</a>
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

- [ ] Added recommendations to homepage

---

### Discovery/Search Page - Add Trending Content

Add this to your search/discovery page (e.g., `views/search.ejs`):

```html
<section id="trending-section" style="margin: 30px 0;">
  <h2>Trending Now</h2>
  <div id="trending-container" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px;">
    <!-- Trending content will be loaded here -->
  </div>
</section>

<script>
  document.addEventListener('DOMContentLoaded', async function() {
    try {
      const trending = await ActivityTracker_Instance.getTrendingContent(7, 6);
      const container = document.getElementById('trending-container');
      
      if (trending && trending.length > 0) {
        container.innerHTML = '';
        trending.forEach(item => {
          const content = item.content || {};
          const isCourse = item._id.courseId;
          const link = isCourse 
            ? `/course/${content.slug}` 
            : `/files/${content.slug}`;
          const uniqueUsers = item.uniqueUserCount || 0;
          
          const html = `
            <div style="border: 2px solid #ff9800; padding: 15px; border-radius: 8px;">
              <div style="background: #ff9800; color: white; padding: 5px 10px; border-radius: 4px; display: inline-block; font-size: 12px; margin-bottom: 10px;">
                Trending
              </div>
              <h3 style="margin: 10px 0;">${content.title || 'N/A'}</h3>
              <p style="margin: 5px 0; color: #666;">👥 ${uniqueUsers} users engaged</p>
              <p style="margin: 5px 0; color: #666;">⏱️ Avg ${Math.round(item.avgTimeSpent / 60)} min spent</p>
              <a href="${link}" style="color: #ff9800; text-decoration: none; font-weight: bold;">Explore →</a>
            </div>
          `;
          container.innerHTML += html;
        });
      }
    } catch (error) {
      console.error('Error loading trending:', error);
    }
  });
</script>
```

- [ ] Added trending content section

---

### Course Lesson Player - Track Lesson Interactions

In your course player view (e.g., `views/courseplayer.ejs`):

```html
<script>
  // When lesson is loaded/started
  function onLessonStart(lessonId, courseId) {
    if (ActivityTracker_Instance) {
      ActivityTracker_Instance.trackLessonStart(lessonId, courseId);
    }
  }

  // When lesson is completed
  function onLessonComplete(lessonId, courseId) {
    if (ActivityTracker_Instance) {
      ActivityTracker_Instance.trackLessonComplete(lessonId, courseId);
    }
  }

  // Example: Call when lesson item is clicked
  document.querySelectorAll('.lesson-item').forEach(item => {
    item.addEventListener('click', function() {
      const lessonId = this.dataset.lessonId;
      const courseId = '<%= courseId %>'; // Get from server
      onLessonStart(lessonId, courseId);
    });
  });
</script>
```

- [ ] Added lesson tracking to course player

---

### File Details Page - Track Downloads & Previews

In your file details view (e.g., `views/file-details.ejs`):

```html
<script>
  // Track when download button is clicked
  document.getElementById('download-btn').addEventListener('click', function(e) {
    const fileId = '<%= file._id %>';
    ActivityTracker_Instance.trackFileDownload(fileId);
    // Let the normal download happen
  });

  // Track when preview is activated
  document.getElementById('preview-btn').addEventListener('click', function(e) {
    const fileId = '<%= file._id %>';
    ActivityTracker_Instance.trackFilePreview(fileId);
  });
</script>
```

- [ ] Added file tracking to file details page

---

### User Dashboard - Show Activity Stats

Add activity summary to user's personal dashboard:

```html
<div id="activity-section" style="margin: 20px 0;">
  <h3>Your Activity (Last 30 Days)</h3>
  <div id="activity-summary" style="background: #f5f5f5; padding: 15px; border-radius: 8px;">
    Loading activity...
  </div>
</div>

<script>
  document.addEventListener('DOMContentLoaded', async function() {
    const user = '<%= user ? user._id : "" %>';
    
    if (user) {
      try {
        const summary = await ActivityTracker_Instance.getActivitySummary(30);
        const container = document.getElementById('activity-summary');
        
        if (summary && summary.length > 0) {
          let html = '<table style="width: 100%; border-collapse: collapse;">';
          html += '<tr style="border-bottom: 1px solid #ddd;"><th style="text-align: left; padding: 8px;">Activity Type</th><th style="text-align: left; padding: 8px;">Count</th><th style="text-align: left; padding: 8px;">Avg Time</th></tr>';
          
          summary.forEach(activity => {
            const avgTime = activity.avgTimeSpent ? Math.round(activity.avgTimeSpent / 60) : 0;
            html += `
              <tr style="border-bottom: 1px solid #eee;">
                <td style="padding: 8px;">${activity._id}</td>
                <td style="padding: 8px;">${activity.count}</td>
                <td style="padding: 8px;">${avgTime} min</td>
              </tr>
            `;
          });
          html += '</table>';
          container.innerHTML = html;
        } else {
          container.innerHTML = '<p>No activity recorded yet. Start exploring!</p>';
        }
      } catch (error) {
        console.error('Error loading activity:', error);
        document.getElementById('activity-summary').innerHTML = '<p>Error loading activity summary</p>';
      }
    }
  });
</script>
```

- [ ] Added activity dashboard to user profile

---

## Testing Checklist

- [ ] Backend running without errors
- [ ] Database model created successfully
- [ ] `/api/track-activity` endpoint responding with 200
- [ ] Frontend script loading without console errors
- [ ] Clicks being tracked (check Network tab)
- [ ] Searches being tracked
- [ ] Time spent being recorded
- [ ] Recommendations loading for users with activity history
- [ ] Trending content loading
- [ ] User interests displaying correctly

---

## Database Verification

To verify activities are being recorded:

```javascript
// In MongoDB shell or MongoDBCompass
db.useractivities.find().sort({ createdAt: -1 }).limit(5)

// Should show recent activities like:
// {
//   userId: ObjectId("..."),
//   sessionId: "uuid-here",
//   activityType: "click",
//   pageType: "course",
//   createdAt: ISODate("2024-...")
// }
```

- [ ] Verified activities in database

---

## Performance Optimization (Optional)

### Enable Caching for Trending Content
In your routes, implement Redis caching:

```javascript
// routes/activityTrackingRoutes.js - Add at top
const redis = require('redis');
const client = redis.createClient();

// Cache trending content for 1 hour
router.get('/trending-content', async (req, res) => {
  const cacheKey = `trending_${req.query.days || 7}_${req.query.limit || 10}`;
  
  // Try cache first
  const cached = await client.get(cacheKey);
  if (cached) return res.json(JSON.parse(cached));
  
  // ... get data and cache
  client.setex(cacheKey, 3600, JSON.stringify(data));
});
```

- [ ] (Optional) Set up Redis caching

---

## Troubleshooting

**Issue**: Activities not being tracked
- Check DevTools Console/Network
- Verify user is logged in
- Check database connection
- Look for errors in server logs

**Issue**: Recommendations empty
- Need minimum 5+ activities from user
- Verify courses/files exist and have categories
- Check that courses are marked `published: true`

**Issue**: Slow performance
- Activities are high volume - consider archiving old data
- Implement caching for trending/recommendations
- Add database indices (already included in model)

---

## Summary

Once you complete this checklist:
✅ Users' activities are recorded (clicks, searches, time spent)
✅ System learns user preferences over time
✅ Personalized recommendations shown based on behavior
✅ Trending content displayed to drive engagement
✅ User can see their own activity patterns

This data can then be used for:
- Personalized course/file suggestions
- Content discovery improvements
- User engagement analytics
- A/B testing recommendations
- Trending sections

---
