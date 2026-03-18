# Quick Reference: Course Creation Code Patterns

## File Structure Overview

```
PROJECT ROOT
├── views/
│   ├── createcourse.ejs          [Dashboard container - includes gencourse]
│   ├── createcourse2.ejs         [Legacy course creation form]
│   ├── gencourse.ejs             [Main 3-step course form - 2800+ lines]
│   ├── course-detail.ejs         [Display created course]
│   ├── courseplayer.ejs          [Play lessons/modules]
│   └── instructor-mycourses.ejs  [List instructor's courses]
│
├── controllers/
│   └── coursecontroller.js       [AWS S3 + MongoDB backend]
│
├── models/
│   ├── course.js                 [Course schema]
│   ├── courseProgress.js         [Student progress tracking]
│   └── user*.js                  [User-related schemas]
│
└── routes/
    └── courseroutes.js           [API endpoints]
```

---

## Key Entry Points

### 1. CREATE COURSE DASHBOARD
**Route**: `/coursecreation` (Server renders createcourse.ejs)
**File**: [routes/courseroutes.js](routes/courseroutes.js#L29)
```javascript
router.get("/coursecreation", (req, res) => {
    res.render("gencourse.ejs");
});
```

### 2. CREATE PRESIGNED URL ENDPOINT
**Route**: `POST /api/courses/generate-presigned-url`
**Auth**: JWT required
**File**: [controllers/coursecontroller.js](controllers/coursecontroller.js#L78)
```javascript
exports.generatePresignedUrl = async (req, res) => {
    const { fileName, fileType, fileCategory } = req.body;
    // Returns: { signedUrl, finalUrl }
}
```

### 3. CREATE COURSE (SAVE TO DB)
**Route**: `POST /api/courses/create-course`
**Auth**: JWT required
**File**: [controllers/coursecontroller.js](controllers/coursecontroller.js#L139)
```javascript
exports.createCourse = async (req, res) => {
    // Maps frontend data → MongoDB schema
    // Saves: title, description, price, modules, tags, etc.
}
```

---

## Form Submission Flow

```
User fills form in gencourse.ejs
    ↓
validateFormOnSubmit() [Lines 1451-1475]
    ├─ validateStep1() [Lines 1323-1333]
    ├─ validateStep2() [Lines 1389-1430]
    └─ validateTags()  [Lines 1432-1436]
    ↓
collectCourseData() [Lines 1755-1875]
    ├─ Gather modules from DOM
    ├─ Gather resources from each module
    └─ Gather tags
    ↓
uploadOrchestrator(courseData) [Lines 1575-1750]
    ├─ getPresignedUrl() for each file [Lines 1476-1508]
    ├─ uploadFileToS3() in parallel [Lines 1544-1573]
    ├─ Map CloudFront URLs back to courseData
    └─ POST finalCoursePayload to /api/courses/create-course
    ↓
Backend: createCourse() [coursecontroller.js:139]
    ├─ Map frontend modules → database submodules
    ├─ Calculate total duration
    ├─ Parse learningOutcomes & requirements
    └─ Save to MongoDB
    ↓
Success! Show modal & reset form
```

---

## CSS Classes Quick Map

### Structural
```
.module-item                 → Each module container
.module-title                → Module heading (editable)
.edit-module-btn             → Edit module name
.delete-module-btn           → Remove module

.resource-item              → Each lesson/resource container
.resource-title             → Resource heading (editable)
.resource-type-btn          → Toggle Video/Document
.resource-file-error        → Error message container

.modules-container          → Wrapper for all modules
.resources-container        → Wrapper for lessons in a module

.add-module-btn             → Add new module button
.add-resource-btn           → Add new resource button
```

### Form Controls
```
.file-input                 → Hidden file input (video/document)
.upload-btn                 → File upload trigger button
.resource-url-input         → URL text input (YouTube, etc.)
.resource-duration          → Duration input (minutes)

.video-container            → Video preview wrapper
#video-iframe               → iframe for YouTube
#intro-video-preview-upload → Video player for uploaded files
```

### Status & Feedback
```
.tag                        → Individual tag element
.remove-tag                 → Delete tag button
#tags-container             → Tags wrapper

#upload-progress-container  → Upload progress UI (hidden by default)
#overall-progress-bar       → Progress bar fill
.upload-item                → Individual file upload item
```

### Step Navigation
```
.progress-step-active       → Current step indicator
.progress-step-complete     → Completed step indicator
.form-step                  → Form step container
```

---

## Data Structures

### Frontend courseData Object (Collected at submission)
```javascript
{
    // Basic Metadata
    title: "string",                    // 5-80 chars, required
    description: "string",              // 20-500 chars, required
    price: number,                      // 300+, required
    category: "string",                 // 3-50 chars, required
    level: "Beginner|Intermediate|Advanced|All Levels",
    
    // Learning Content
    learningOutcomes: ["string", ...],  // From textarea, split by \n
    requirements: ["string", ...],      // From textarea, split by \n
    
    // Intro Video (EITHER URL OR FILE, not both)
    introVideoUrl: "string|null",       // YouTube URL
    introVideoFile: File|null,          // Video file object
    
    // Thumbnail
    courseImage: File,                  // Image file object
    
    // Course Structure
    modules: [
        {
            title: "string",            // Module name
            order: number,
            resources: [
                {
                    title: "string",              // Resource/lesson name
                    type: "Video|Document",
                    url: "string|null",           // YouTube/Vimeo URL
                    file: File|null,              // Uploaded file
                    duration: number,            // Minutes
                    order: number
                },
                ...
            ]
        },
        ...
    ],
    
    // Tags
    tags: ["string", ...]               // Min 2 required
}
```

### Backend Saved Course Schema (MongoDB)
```javascript
{
    _id: ObjectId,
    title: "string",
    description: "string",
    price: number,
    category: "string",
    thumbnailUrl: "https://d3epchi0htsp3c.cloudfront.net/...",
    introVideoUrl: "https://d3epchi0htsp3c.cloudfront.net/...",
    
    modules: [
        {
            _id: ObjectId,
            unit: "string",              // Module unit name
            order: number,
            submodules: [
                {
                    _id: ObjectId,
                    title: "string",
                    type: "Video|Document",
                    fileUrl: "https://d3epchi0htsp3c.cloudfront.net/courses/uploads/videos/...",
                    externalUrl: "https://youtube.com/...",
                    duration: number,
                    order: number
                },
                ...
            ]
        },
        ...
    ],
    
    tags: ["string", ...],
    level: "string",
    duration: number,                  // Total in minutes
    learningOutcomes: ["string", ...],
    requirements: ["string", ...],
    userId: ObjectId,
    enrollCount: number,
    published: boolean,
    isFree: boolean,
    createdAt: Date,
    updatedAt: Date,
    ...
}
```

### Presigned URL Response
```javascript
{
    signedUrl: "https://s3.amazonaws.com/...",  // For PUT request
    finalUrl: "https://d3epchi0htsp3c.cloudfront.net/courses/uploads/{folder}/{hash}-{name}"
}
```

---

## Important Functions Reference

### gencourse.ejs JavaScript Functions

| Function | Location | Purpose |
|----------|----------|---------|
| `createModuleElement(count)` | 745 | Generate module HTML template |
| `createResourceElement(id)` | 811 | Generate resource/lesson HTML template |
| `validateFormOnSubmit()` | 1451 | Final validation before upload |
| `validateStep1()` | 1323 | Validate course details |
| `validateStep2()` | 1389 | Validate modules & resources |
| `getPresignedUrl(file)` | 1476 | Request signed URL from backend |
| `uploadFileToS3(signedUrl, file)` | 1544 | Upload file directly to S3 |
| `uploadOrchestrator(courseData)` | 1575 | Orchestrate all file uploads |
| `handleResourceTypeSwitch(button)` | 914 | Switch resource between Video/Document |
| `handleVideoOptionChange()` | 1080 | Toggle intro video between URL/File |
| `determineFileCategory(file)` | 1518 | Auto-detect file type for S3 folder |

### Course Controller Functions
| Function | File | Purpose |
|----------|------|---------|
| `generatePresignedUrl()` | controllers/coursecontroller.js:78 | Create signed S3 URL |
| `createCourse()` | controllers/coursecontroller.js:139 | Save course to MongoDB |
| `determineFileFolder()` | controllers/coursecontroller.js:52 | Map file type to S3 folder |

---

## S3 & CloudFront Integration

### File Upload to S3
```
User selects file in gencourse.ejs
    ↓
Frontend calls: POST /api/courses/generate-presigned-url
    {fileName, fileType, fileCategory}
    ↓
Backend determines folder (images/videos/pdfs/documents)
    ↓
Backend generates signed URL (1 hour expiry)
    ↓
Frontend does XMLHttpRequest PUT to signedUrl
    ↓
File stored in: s3://vidyari3/courses/uploads/{folder}/{hash}-{filename}
    ↓
CloudFront URL returned: https://d3epchi0htsp3c.cloudfront.net/courses/uploads/{folder}/{hash}-{filename}
```

### File Category Detection (Auto)
```javascript
.jpg/.png/.gif/.webp/.svg → /images/
.pdf                        → /pdfs/
.mp4/.webm/video/*         → /videos/
.doc/.docx/.ppt/.xls/...   → /documents/
```

### Folder Structure in S3
```
s3://vidyari3/
└── courses/
    └── uploads/
        ├── images/
        │   ├── {hash}-course-thumbnail.jpg
        │   └── ...
        ├── videos/
        │   ├── {hash}-intro.mp4
        │   ├── {hash}-lesson1.mp4
        │   └── ...
        ├── pdfs/
        │   ├── {hash}-guide.pdf
        │   └── ...
        └── documents/
            ├── {hash}-notes.docx
            └── ...
```

---

## Form Validation Rules

### Step 1: Course Details
| Field | Min | Max | Required | Type |
|-------|-----|-----|----------|------|
| Title | 5 | 80 | ✓ | Text |
| Description | 20 | 500 | ✓ | Text |
| Price | 300 | 1,000,000 | ✓ | Number |
| Category | 3 | 50 | ✓ | Text |
| Intro Video | - | - | ✓ | URL or File |
| Course Image | - | - | ✓ | Image File |
| Level | - | - | ✓ | Dropdown |
| Learning Outcomes | - | - | ✓ | Text |
| Requirements | - | - | ✓ | Text |

### Step 2: Curriculum
| Requirement | Rule |
|-------------|------|
| Modules | Min 1 required |
| Resources per Module | Each module must have ≥1 resource |
| Resource Content | EITHER file OR URL required |
| Resource Title | Required (auto-filled) |
| Resource Type | Video or Document |
| Duration | Optional (defaults to 30 mins) |

### Step 3: Tags
| Requirement | Rule |
|-------------|------|
| Tags | Min 2 required |
| Tag Format | Any string |

---

## Common Issues & Solutions

### Issue 1: File Upload Fails with 400/403
**Possible Causes**:
- Missing `fileCategory` detection
- MIME type mismatch
- S3 bucket permissions

**Solution**: Check `determineFileCategory()` function, verify AWS credentials in env

### Issue 2: CloudFront URLs 404
**Possible Causes**:
- S3 file not uploaded successfully
- Distribution not configured correctly
- File in wrong S3 folder

**Solution**: Verify file exists in S3, check CloudFront distribution settings

### Issue 3: Form Total Duration Calculating Wrong
**Possible Causes**:
- Resource duration not being parsed
- NaN values in duration fields

**Solution**: Ensure duration inputs are number type, default to 30 if NaN

### Issue 4: Module/Resource Not Persisting After Page Reload
**Note**: gencourse.ejs is client-side only until submit - no localStorage implemented
**Solution**: Add localStorage or auto-save feature if persistence needed during editing

---

## Extension Points for Customization

### 1. Add More Resource Types
Currently supports: Video, Document

**To Add Audio**:
```javascript
// In gencourse.ejs, createResourceElement():
else if (resourceType === 'audio') {
    inputHTML = `
    <input type="file" accept="audio/*" ... />
    ...
    `;
}

// In coursecontroller.js, determineFileFolder():
if (['mp3', 'wav', 'flac'].includes(ext)) {
    return 'audio';  // New S3 folder
}
```

### 2. Add Lesson Prerequisites
```javascript
// In course.js schema:
submodules: [
    {
        ...existing,
        prerequisiteLessonId: ObjectId,  // NEW
        minScoreRequired: Number,        // NEW
    }
]
```

### 3. Add Quiz After Lesson
```javascript
// In modules structure:
submodules: [
    {
        ...existing,
        hasQuiz: Boolean,
        quiz: {
            questions: [...]
        }
    }
]
```

### 4. Add Course Bundles
```javascript
// New collection:
courseBundleSchema = {
    title: String,
    courses: [ObjectId],        // Array of course IDs
    bundlePrice: Number,
    discount: Number,
}
```

### 5. Add Instructor Course Analytics
```javascript
// Track in course.js:
{
    ...existing,
    analytics: {
        totalEnrollments: Number,
        completionRate: Number,
        averageRating: Number,
        revenueEarned: Number,
    }
}
```

---

## Testing Checklist

- [ ] Can create course with minimum fields
- [ ] Can add multiple modules dynamically
- [ ] Can add multiple resources to each module
- [ ] Can upload video file and get CloudFront URL
- [ ] Can upload document file and get CloudFront URL
- [ ] Can paste YouTube URL for intro video
- [ ] Can upload course thumbnail image
- [ ] Can switch resource type between Video/Document
- [ ] Can delete module and resources
- [ ] Can edit module and resource names inline
- [ ] Can tag course with multiple tags (≥2)
- [ ] Form validation shows errors correctly
- [ ] Upload progress displays correctly
- [ ] Final course data saved to MongoDB
- [ ] CloudFront URLs resolve without 404
- [ ] Can retrieve created course in course-detail.ejs
- [ ] Can play course modules in courseplayer.ejs
- [ ] Logged-in user can access course creation
- [ ] Non-logged-in user redirected to login
- [ ] Course published flag works correctly
