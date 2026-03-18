# Course Data Persistence Verification Checklist

**Purpose**: Verify that all data collected in gencourse.ejs is properly saved to MongoDB and retrievable in course-detail.ejs and courseplayer.ejs.

---

## Pre-Testing Setup

### API Endpoints Available
- [ ] `/api/courses/generate-presigned-url` - Generates signed S3 URLs
- [ ] `/api/courses/create-course` - Saves course data to MongoDB
- [ ] `/courses/:courseId` - Retrieves course for display (if implemented)

### MongoDB Connection
- [ ] MongoDB running and accessible
- [ ] Database has Course collection
- [ ] Previous test courses cleared (optional cleanup)

### CloudFront Setup
- [ ] CloudFront domain accessible: `d3epchi0htsp3c.cloudfront.net`
- [ ] S3 bucket folders exist: `images/`, `videos/`, `pdfs/`, `documents/`
- [ ] Bucket has proper CORS configuration

---

## Step 1: Create Test Course

**Location**: Open gencourse.ejs

### Form Fields - Basic Metadata
- [ ] **Title**: Enter a unique test title (e.g., "Test Course - $(date)")
  - ✓ Critical: This must appear in course-detail.ejs as course heading
  
- [ ] **Description**: Enter test description with multiple sentences
  - ✓ Critical: This must display on course-detail.ejs
  
- [ ] **Price**: Enter a test price (e.g., 999 for paid, or 0 for free)
  - ✓ Critical: course.price must save to MongoDB
  - ✓ Derived: course.isFree must be calculated (price === 0)
  
- [ ] **Category**: Select a category (e.g., "Programming")
  - ✓ Critical: course.category must save to MongoDB

### Media Files
- [ ] **Course Thumbnail**: Upload an image file (.jpg, .png, .gif)
  - ✓ Expected S3 Path: `/courses/uploads/images/{filename}`
  - ✓ Expected MongoDB Field: `course.thumbnailUrl`
  - ✓ Usage: Displays in course-detail.ejs `<img src="<%= course.thumbnailUrl %>">`
  
- [ ] **Intro Video (choose one)**:
  - [ ] Option A: Upload video file (.mp4, .webm)
    - ✓ Expected S3 Path: `/courses/uploads/videos/{filename}`
    - ✓ Expected MongoDB Field: `course.introVideoUrl`
  - [ ] Option B: Paste direct video URL
    - ✓ Expected MongoDB Field: `course.introVideoUrl` (same field)
    - Note: Must be valid streaming URL

### Course Content (Modules & Resources)
- [ ] **Add at least 1 Module** with title (e.g., "Module 1: Getting Started")
  - [ ] **Add at least 2 Resources** to the module:
    - [ ] **Resource 1 - Video**: Upload .mp4 file or paste YouTube/streaming URL
      - ✓ Expected S3 Path (if file): `/courses/uploads/videos/{filename}`
      - ✓ Expected MongoDB Field: `course.modules[0].resources[0].url`
      - ✓ Expected Field: `course.modules[0].resources[0].type = "Video"`
      
    - [ ] **Resource 2 - PDF**: Upload .pdf file or paste PDF URL
      - ✓ Expected S3 Path (if file): `/courses/uploads/pdfs/{filename}`
      - ✓ Expected MongoDB Field: `course.modules[0].resources[1].url`
      - ✓ Expected Field: `course.modules[0].resources[1].type = "Document"`

### Tags
- [ ] **Add at least 3 tags**: Add meaningful keywords (e.g., "javascript", "beginner", "web-development")
  - ✓ Expected MongoDB Field: `course.tags = ["javascript", "beginner", "web-development"]`

---

## Step 2: Submit Course & Monitor Upload

**Action**: Click "Create Course" / Submit button

### Upload Progress
- [ ] Thumbnail file uploads successfully
- [ ] Intro video file uploads successfully
- [ ] Module resources upload successfully
- [ ] No error messages displayed
- [ ] Success message shown (if implemented)

### File Upload Verification
After upload completes, check browser Network/Console tab:
- [ ] All presigned URL requests successful (HTTP 200)
- [ ] All S3 PUT requests successful (HTTP 200)
- [ ] createCourse API call successful (HTTP 200/201)

---

## Step 3: Verify MongoDB Stored ALL Fields

**Location**: MongoDB database or API response

### Query Course by Title
```javascript
db.courses.findOne({ title: "Test Course - $(date)" })
```

### Verify Basic Metadata Fields
- [ ] `course.title` = test title entered
  - Current Value: ________________
  
- [ ] `course.description` = test description entered
  - Current Value: ________________
  
- [ ] `course.price` = test price entered
  - Current Value: ________________
  
- [ ] `course.isFree` = calculated correctly
  - Expected: true if price was 0, otherwise false
  - Current Value: ________________

- [ ] `course.category` = test category selected
  - Current Value: ________________
  
- [ ] `course.published` = false (default)
  - Current Value: ________________

### Verify Media URLs Are Saved
- [ ] `course.thumbnailUrl` exists and contains CloudFront domain
  - Expected Pattern: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/images/*`
  - Current Value: ________________
  
- [ ] `course.introVideoUrl` exists and contains CloudFront domain
  - Expected Pattern: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/videos/*`
  - Current Value: ________________

### Verify Modules & Resources Saved
- [ ] `course.modules` array has 1+ items
  - Number of modules: ________________
  
- [ ] `course.modules[0].title` = module title entered
  - Current Value: ________________
  
- [ ] `course.modules[0].resources` has 2+ items
  - Number of resources: ________________
  
- [ ] `course.modules[0].resources[0].type` = "Video"
  - Current Value: ________________
  
- [ ] `course.modules[0].resources[0].url` contains CloudFront URL
  - Expected Pattern: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/videos/*`
  - Current Value: ________________
  
- [ ] `course.modules[0].resources[1].type` = "Document"
  - Current Value: ________________
  
- [ ] `course.modules[0].resources[1].url` contains CloudFront URL
  - Expected Pattern: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/pdfs/*`
  - Current Value: ________________

### Verify Tags Saved
- [ ] `course.tags` is an array with 3+ items
  - Tags: ________________
  
- [ ] Tags match what was entered
  - All entries correct: [ ] Yes [ ] No

---

## Step 4: Display Course in course-detail.ejs

**Location**: Load course-detail.ejs with test course

**Note**: You may need to:
1. Manually pass courseId as query parameter, OR
2. Implement a route that retrieves the course from MongoDB by ID

### Verify Page Displays Without Errors
- [ ] No JavaScript errors in console
- [ ] Page loads without 404 or 500 errors
- [ ] No "undefined" text visible on page

### Verify Basic Metadata Display
- [ ] Course title displays correctly
  - Displayed: ________________
  - Matches MongoDB: [ ] Yes [ ] No

- [ ] Course description displays correctly
  - Matches MongoDB: [ ] Yes [ ] No

- [ ] Course price displays correctly
  - Displayed: ________________
  - Matches MongoDB: [ ] Yes [ ] No

- [ ] Course badge shows status (published/unpublished)
  - NOTE: This uses `course.published` field
  - Displayed Status: ________________
  - Expected: "Unpublished" (since we set it to false)

### Verify Thumbnail Displays
- [ ] Thumbnail <img> tag loads without 404
  - Image URL: ________________
  
- [ ] Image displays properly (not broken image icon)
  - Loaded: [ ] Yes [ ] No
  
- [ ] Image src attribute matches `course.thumbnailUrl` from MongoDB
  - Verified: [ ] Yes [ ] No

### Verify Intro Video Displays (if implemented)
- [ ] Intro video player shows on page
- [ ] Video <video> or <iframe> src attribute matches `course.introVideoUrl`
- [ ] Video plays (or at least doesn't show 404)

---

## Step 5: Play Course Content in courseplayer.ejs

**Location**: Open courseplayer.ejs with test course

### Verify Page Loads Correctly
- [ ] Course title displays at top
- [ ] Module list shows (e.g., "Module 1: Getting Started")
- [ ] No JavaScript errors in console

### Play Lesson Resources
- [ ] Click on first resource (Video)
  - [ ] Video player loads
  - [ ] Video src attribute contains CloudFront URL
  - [ ] Video plays (or shows valid HTTP request in Network tab)
  - Final URL accessed: ________________

- [ ] Click on second resource (PDF/Document)
  - [ ] PDF preview or download link appears
  - [ ] PDF src attribute contains CloudFront URL
  - [ ] PDF loads without 404
  - Final URL accessed: ________________

### Verify CloudFront URLs Work
- [ ] All video URLs use CloudFront domain: `d3epchi0htsp3c.cloudfront.net`
  - Verified: [ ] Yes [ ] No

- [ ] All PDF URLs use CloudFront domain: `d3epchi0htsp3c.cloudfront.net`
  - Verified: [ ] Yes [ ] No

- [ ] Files are served from correct subfolders:
  - Videos from `/courses/uploads/videos/`: [ ] Yes [ ] No
  - PDFs from `/courses/uploads/pdfs/`: [ ] Yes [ ] No

---

## Step 6: End-to-End Validation

### Data Persistence Complete
- [ ] Data flows: gencourse.ejs → coursecontroller.js → MongoDB ✓
- [ ] Data flows: MongoDB → course-detail.ejs display ✓
- [ ] Data flows: MongoDB → courseplayer.ejs playback ✓

### No Data Loss
- [ ] All fields from gencourse.ejs form are in MongoDB
- [ ] All CloudFront URLs are accessible (no broken links)
- [ ] All media files uploaded to correct S3 folders

### Views Display Correctly
- [ ] course-detail.ejs shows: title, description, price, thumbnail, intro video, status badge
- [ ] courseplayer.ejs shows: modules, resources, playable videos/PDFs

---

## Common Issues to Debug

### Issue: Field Undefined in course-detail.ejs
**Solution**: Check that field name matches MongoDB document:
- ❌ `course.isPremium` (doesn't exist)
- ✅ `course.published` (correct field)

### Issue: Files Uploaded but URLs Not Saved
**Solution**: Verify coursecontroller.js createCourse() saves:
- `thumbnailUrl` from courseImage upload
- `introVideoUrl` from introVideoFile or direct URL
- Each resource's `url` field in modules

### Issue: CloudFront URLs Return 403/404
**Solution**: Check:
- CloudFront domain is correct: `d3epchi0htsp3c.cloudfront.net`
- S3 bucket has proper permissions
- Files are in correct subfolders (images/, videos/, pdfs/)

### Issue: Videos Don't Play in courseplayer.ejs
**Solution**: Verify:
- `course.modules[].resources[].url` contains valid CloudFront URL
- Video file exists in S3 at the path shown in returned URL
- CloudFront distribution is active and cached

---

## Success Criteria

✅ **All of the following must be true**:

1. MongoDB course document has ALL fields collected in gencourse.ejs
2. course-detail.ejs displays all course metadata without errors
3. courseplayer.ejs loads and plays all resources (videos, PDFs)
4. All CloudFront URLs are accessible (HTTP 200, not 404)
5. Thumbnail image displays correctly
6. No "undefined" values visible in any view
7. No data is missing compared to what was entered in the form

---

## Completion Status

| Date | Course Title | Result | Notes |
|------|-------------|--------|-------|
|      |             | ✅/❌  |       |
|      |             | ✅/❌  |       |
|      |             | ✅/❌  |       |

**Overall Result**: [ ] PASS ✅  [ ] FAIL ❌

**Date Completed**: ________________

**Tested By**: ________________

---

## Next Steps After Verification

Once all checks pass:

1. Test with multiple courses to ensure consistency
2. Test with various file types (different video codecs, image formats, etc.)
3. Test error cases (invalid file uploads, missing fields)
4. Implement course search and filtering
5. Add ratings and reviews system
6. Implement student enrollment and payment

---

## Reference Documentation

- **Inline Comments in gencourse.ejs**: Explains each courseData field and its lifecycle
- **Session Checklist**: /memories/session/course-data-flow-summary.md
- **Code Files**:
  - Frontend: views/gencourse.ejs
  - Backend: controllers/coursecontroller.js
  - Database: models/course.js
  - Display: views/course-detail.ejs, views/courseplayer.ejs
