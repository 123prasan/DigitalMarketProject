# Course Creation & File Upload Architecture

## Overview
The course creation system uses a multi-step form interface with async file uploads to AWS S3 and CloudFront CDN delivery. The architecture separates the frontend form from the file upload orchestration.

---

## 1. VIEWS - Course Creation Interfaces

### Primary Creator Dashboard
- **File**: [views/createcourse.ejs](views/createcourse.ejs)
  - Main creator dashboard/landing page
  - **Includes**: tabs for `fileupload`, `gencourse`, `instructor-mycourses`, `enrolled-students`
  - **Line 410**: Includes the gencourse view: `<%-include("gencourse")%>`
  - Acts as a container with navigation tabs

### Main Course Creation Form
- **File**: [views/gencourse.ejs](views/gencourse.ejs)
  - Complete 3-step course creation form
  - **2800+ lines** of modern HTML/CSS/JavaScript
  - **Step 1** (Lines 235-358): Basic course details
  - **Step 2** (Lines 360-413): Curriculum with modules & lessons
  - **Step 3** (Lines 415-460): Tags & submission
  - **Form ID**: `multi-step-form`

### Legacy Course Creation Form
- **File**: [views/createcourse2.ejs](views/createcourse2.ejs)
  - Alternative/legacy course creation view
  - Tag-based system with jsPDF and XLSX export support

---

## 2. FORM STRUCTURE & MODULES

### Step 1: Course Details
**Form Fields** (Lines 235-358 in gencourse.ejs):
```html
<!-- Basic Metadata -->
<input id="course-title" />          <!-- Max 80 chars -->
<textarea id="course-description" />  <!-- Max 500 chars -->
<input type="number" id="course-price" min="300" max="1000000" />
<input id="course-category" />
<select id="course-level">           <!-- Beginner/Intermediate/Advanced/All Levels -->
<textarea id="course-learning-outcomes" />  <!-- NewLine or comma-separated -->
<textarea id="course-requirements" />       <!-- NewLine or comma-separated -->

<!-- Intro Video (Choice: URL or File) -->
<input type="radio" name="video-option" value="url" />  <!-- YouTube URL -->
<input type="radio" name="video-option" value="file" /> <!-- Upload File -->
<input type="url" id="intro-video-url" />
<input type="file" id="intro-video-file" accept="video/*" />

<!-- Course Thumbnail -->
<input type="file" id="course-image-file" accept="image/*" />
```

### Step 2: Curriculum (Modules & Lessons)
**Container**: `modules-container` (Line 368)
**Add Module Button**: `add-module-btn` (Line 361)

#### Module Structure (Lines 745-810):
```javascript
const createModuleElement = (count) => {
    return `
    <div class="module-item">           <!-- Each module -->
        <h3 class="module-title">Module ${count}</h3>
        <button class="edit-module-btn" />
        <button class="delete-module-btn" />
        <div class="resources-container" />  <!-- Lesson resources -->
        <button class="add-resource-btn" >+ Add Resource</button>
    </div>
    `;
};
```

#### Resource (Lesson) Structure (Lines 811-900):
```javascript
const createResourceElement = (id) => {
    return `
    <div class="resource-item" data-resource-id="${id}">
        <h4 class="resource-title">New Resource ${id}</h4>
        <button class="resource-type-btn" data-type="video">Video</button>
        <button class="resource-type-btn" data-type="document">Document</button>
        
        <!-- Dynamic Content Input -->
        <div class="dynamic-input-container">
            <!-- For Video -->
            <button class="upload-btn" data-type="video" data-resource-id="${id}">
                Upload Video File
            </button>
            <input type="file" id="video-file-input-${id}" accept="video/*" />
            <input type="text" class="resource-url-input" placeholder="Paste URL..." />
            
            <!-- For Document -->
            <button class="upload-btn" data-type="document" data-resource-id="${id}">
                Upload Document File
            </button>
            <input type="file" id="document-file-input-${id}" 
                   accept=".pdf,.doc,.docx,.txt,.ppt,.pptx,.xls,.xlsx" />
            
            <!-- Duration -->
            <input type="number" class="resource-duration" value="30" min="1" />
        </div>
    </div>
    `;
};
```

### Step 3: Tags & Submission
**Container**: `tags-container` (referenced in tag input handlers)
**Submit Button**: `submitBtn` (for final submission)

---

## 3. FILE UPLOAD HANDLING

### 3A. File Category Auto-Detection (Lines 1518-1542)
```javascript
function determineFileCategory(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    const mimeType = file.type.toLowerCase();
    
    // Returns: 'images', 'pdfs', 'videos', or 'documents'
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(ext)) 
        return 'images';
    else if (['pdf'].includes(ext)) 
        return 'pdfs';
    else if (mimeType.startsWith('video/')) 
        return 'videos';
    else if (['doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx'].includes(ext)) 
        return 'documents';
    return 'videos'; // default
}
```

### 3B. Pre-signed URL Generation (Lines 1476-1508)
**Endpoint**: `POST /api/courses/generate-presigned-url`
**Request Body**:
```javascript
{
    fileName: "course-thumbnail.jpg",
    fileType: "image/jpeg",
    fileCategory: "images" (optional - auto-detected if not provided)
}
```

**Response**:
```javascript
{
    signedUrl: "https://s3.amazonaws.com/...",  // For direct S3 upload
    finalUrl: "https://d3epchi0htsp3c.cloudfront.net/courses/uploads/images/..."
}
```

### 3C. Direct S3 Upload (Lines 1544-1573)
```javascript
function uploadFileToS3(signedUrl, file, onProgress) {
    // XMLHttpRequest with progress tracking
    // PUT request to signedUrl with file as body
    // Calls onProgress(percentComplete) for UI updates
    // Success = HTTP 200 response
}
```

### 3D. Upload Orchestrator (Lines 1575-1750)
**Main Controller**: `uploadOrchestrator(courseData)` (Lines 1575-1750)

**Process**:
1. **Identify Files to Upload** (Lines 1584-1598):
   - Course thumbnail image
   - Intro video (if file selected)
   - Module resources (videos/documents)
   - Creates progress tracking map

2. **Create Upload Tasks** (Lines 1607-1625):
   - Maps each file to async upload task
   - Tracks individual file progress
   - Updates overall progress bar

3. **Execute Parallel Uploads** (Lines 1627-1628):
   ```javascript
   const uploadedFileResults = 
       await Promise.all(uploadTasks.map(task => task()));
   ```

4. **Map CloudFront URLs Back** (Lines 1632-1644):
   ```javascript
   uploadedFileResults.forEach(result => {
       if (result.type === 'thumbnail') {
           finalCoursePayload.thumbnailUrl = result.finalUrl;
       } else if (result.type === 'resource') {
           finalCoursePayload.modules[result.moduleIndex]
               .resources[result.resourceIndex].fileUrl = result.finalUrl;
       }
   });
   ```

5. **Send Final Payload** (Lines 1652-1664):
   ```javascript
   const finalResponse = await fetch('/api/courses/create-course', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify(finalCoursePayload)
   });
   ```

---

## 4. DATA PERSISTENCE & BACKEND

### Backend Controller
**File**: [controllers/coursecontroller.js](controllers/coursecontroller.js)

#### GeneratePresignedUrl Function (Lines 78-134)
- Creates S3 PutObjectCommand with auto-detected folder
- Generates 1-hour expiring signed URL
- Returns both signed URL and CloudFront finalUrl
- Folder mapping: images, videos, pdfs, documents

#### CreateCourse Function (Lines 139-250)
**Key Transformations**:
- Maps frontend `modules` → backend `modules`
- Maps resource `title`, `type`, `fileUrl`, `externalUrl`
- Calculates total `duration` from all resources (in minutes)
- Parses `learningOutcomes` and `requirements` from comma/newline-separated
- Sets `isFree` based on price
- Automatically calculates `duration` (30 min per resource default)

**Course Model Schema**:
```javascript
// Submodule (Lesson)
{
    title: String,
    type: String (enum: ["Video", "Document"]),
    fileUrl: String,           // CloudFront URL (primary)
    externalUrl: String,       // YouTube/Vimeo URL or duplicate of fileUrl
    duration: Number,          // in minutes
    order: Number
}

// Module
{
    unit: String,
    submodules: [submoduleSchema],
    order: Number
}

// Course
{
    title: String,
    description: String,
    price: Number,
    category: String,
    thumbnailUrl: String,
    introVideoUrl: String,
    modules: [moduleSchema],
    tags: [String],
    level: String,
    duration: Number,          // Total in minutes
    learningOutcomes: [String],
    requirements: [String],
    userId: ObjectId,
    published: Boolean,
    ...
}
```

### Routes
**File**: [routes/courseroutes.js](routes/courseroutes.js)

```javascript
router.get("/coursecreation", (req, res) => {
    res.render("gencourse.ejs");
});

router.post("/generate-presigned-url", authenticateJWT_user, generatePresignedUrl);

router.post("/create-course", authenticateJWT_user, createCourse);
```

---

## 5. S3 & CloudFront ARCHITECTURE

### AWS S3 Folder Structure
```
s3://vidyari3/courses/uploads/
├── images/          → Course thumbnails, preview images
├── videos/          → Intro videos, course videos  
├── pdfs/            → PDF documents
└── documents/       → Word, Excel, PowerPoint files
```

### CloudFront URLs
**Base Domain**: `https://d3epchi0htsp3c.cloudfront.net`

**Examples**:
- Thumbnail: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/images/{unique-hash}-thumbnail.jpg`
- Video: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/videos/{unique-hash}-intro.mp4`
- PDF: `https://d3epchi0htsp3c.cloudfront.net/courses/uploads/pdfs/{unique-hash}-guide.pdf`

**Unique Naming**: `crypto.randomBytes(16).toString('hex') + '-' + fileName`

---

## 6. KEY CODE PATTERNS

### Pattern 1: Adding a Module
```javascript
// Event listener on add-module-btn (Line 805)
addModuleBtn.addEventListener('click', () => {
    moduleCount++;
    const newModule = createModuleElement(moduleCount);
    modulesContainer.insertAdjacentHTML('beforeend', newModule);
    // Reattach event listeners for new module
});
```

### Pattern 2: Adding a Resource to Module
```javascript
// Event delegation on add-resource-btn
document.addEventListener('click', (e) => {
    if (e.target.closest('.add-resource-btn')) {
        resourceCount++;
        const newResource = createResourceElement(resourceCount);
        const resourcesContainer = 
            e.target.closest('.module-item').querySelector('.resources-container');
        resourcesContainer.insertAdjacentHTML('beforeend', newResource);
    }
});
```

### Pattern 3: Resource Type Switching
```javascript
// Switch between Video and Document resources
const handleResourceTypeSwitch = (button) => {
    const resourceType = button.dataset.type;
    const resourceId = button.closest('.resource-item').dataset.resourceId;
    
    // Update dynamic input container with Video or Document UI
    const dynamicInputContainer = 
        button.closest('.resource-item').querySelector('.dynamic-input-container');
    
    if (resourceType === 'video') {
        // Show video upload + URL input
    } else if (resourceType === 'document') {
        // Show document upload only
    }
    validateStep2(); // Re-validate
};
```

### Pattern 4: Video Preview Toggle
```javascript
// Toggle between YouTube URL and File upload for Intro Video
const handleVideoOptionChange = () => {
    const isUrlSelected = videoOptionUrl.checked;
    videoUrlContainer.classList.toggle('hidden', !isUrlSelected);
    videoFileContainer.classList.toggle('hidden', isUrlSelected);
    validateIntroVideo();
};

// YouTube URL preview
introVideoUrlInput.addEventListener('input', () => {
    const url = introVideoUrlInput.value.trim();
    const youtubeRegex = /(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/ ]{11})/i;
    const match = url.match(youtubeRegex);
    if (match && match[1]) {
        videoIframe.src = `https://www.youtube.com/embed/${match[1]}`;
        introVideoIframePreview.classList.remove('hidden');
    }
});
```

### Pattern 5: Form Validation
```javascript
function validateStep1() {
    const isTitleValid = validateTitle();      // 5-80 chars
    const isDescValid = validateDescription(); // 20-500 chars
    const isPriceValid = validatePrice();      // 300+ min
    const isVideoValid = validateIntroVideo(); // URL or File
    const isImageValid = validateImageFile();  // Image required
    return isTitleValid && isDescValid && isPriceValid && 
           isVideoValid && isImageValid;
}

function validateStep2() {
    const modules = modulesContainer.querySelectorAll('.module-item');
    if (modules.length === 0) return false;
    
    modules.forEach((moduleEl, mIndex) => {
        const resources = moduleEl.querySelectorAll('.resource-item');
        resources.forEach((resourceEl, rIndex) => {
            const fileInput = resourceEl.querySelector('.file-input');
            const urlInput = resourceEl.querySelector('.resource-url-input');
            const hasContent = fileInput?.files.length > 0 || 
                             (urlInput?.value.trim() !== '');
            if (!hasContent) return false;
        });
    });
    return true;
}
```

### Pattern 6: Data Collection Before Upload
```javascript
// Submit handler (Lines 1755-1875)
const courseData = {
    title: document.getElementById('course-title').value.trim(),
    description: document.getElementById('course-description').value.trim(),
    price: parseFloat(document.getElementById('course-price').value) || 0,
    category: document.getElementById('course-category').value.trim(),
    level: document.getElementById('course-level').value.trim(),
    
    learningOutcomes: 
        document.getElementById('course-learning-outcomes').value.trim()
            .split('\n').map(item => item.trim()).filter(item => item),
    requirements: 
        document.getElementById('course-requirements').value.trim()
            .split('\n').map(item => item.trim()).filter(item => item),
    
    introVideoOption: document.querySelector('input[name="video-option"]:checked').value,
    introVideoUrl: document.getElementById('intro-video-url').value.trim() || null,
    introVideoFile: document.getElementById('intro-video-file').files[0] || null,
    
    courseImage: document.getElementById('course-image-file').files[0] || null,
    
    modules: [],
    tags: []
};

// Gather Modules
document.querySelectorAll('.module-item').forEach((moduleEl, moduleIndex) => {
    const module = {
        title: moduleEl.querySelector('.module-title').textContent.trim(),
        order: moduleIndex + 1,
        resources: []
    };
    
    moduleEl.querySelectorAll('.resource-item').forEach((resourceEl, rIndex) => {
        const resourceType = 
            resourceEl.querySelector('.resource-type-btn.bg-sky-500')?.dataset.type;
        const resource = {
            title: resourceEl.querySelector('.resource-title').textContent.trim(),
            type: resourceType.charAt(0).toUpperCase() + resourceType.slice(1),
            url: resourceEl.querySelector('.resource-url-input')?.value.trim() || null,
            file: resourceEl.querySelector('.file-input')?.files[0] || null,
            duration: parseInt(resourceEl.querySelector('.resource-duration')?.value) || 30,
            order: rIndex + 1
        };
        
        // Prioritize file over URL if both exist
        if (resource.file && resource.url) resource.url = null;
        module.resources.push(resource);
    });
    
    courseData.modules.push(module);
});

// Gather Tags
document.querySelectorAll('#tags-container .tag').forEach(tagEl => {
    courseData.tags.push(tagEl.querySelector('span:first-child').textContent.trim());
});
```

---

## 7. ERROR HANDLING & VALIDATION

### Validation Functions (Lines 1260-1399)
```javascript
validateTitle()              // 5-80 chars
validateDescription()        // 20-500 chars
validatePrice()              // 300-1,000,000
validateCategory()           // 3-50 chars
validateIntroVideo()         // URL or File required
validateImageFile()          // Image file required
validateStep1()              // All step1 validations
validateStep2()              // Module & resource checks
validateTags()               // Min 2 tags required
validateFormOnSubmit()       // Final check before upload
```

### Error Display
```javascript
function displayError(element, message) {
    const errorEl = element.id ? 
        document.getElementById(element.id + '-error') :
        element.querySelector('p.error');
    
    if (errorEl) {
        if (message) {
            errorEl.textContent = message;
            errorEl.classList.remove('hidden');
        } else {
            errorEl.classList.add('hidden');
        }
    }
}
```

---

## 8. FILE UPLOAD UI COMPONENTS

### Upload Progress Display (Lines 1129-1166)
```html
<div id="upload-progress-container" class="hidden mt-6 p-4 bg-gray-50 rounded-lg">
    <div class="mb-4">
        <div class="flex justify-between mb-2">
            <span>Upload Progress</span>
            <span id="overall-progress-text">0%</span>
        </div>
        <div class="w-full bg-gray-200 rounded-full h-2">
            <div id="overall-progress-bar" class="bg-sky-500 h-2 rounded-full w-0"></div>
        </div>
    </div>
    <ul id="upload-list" class="space-y-2"></ul>
</div>
```

### Upload Item Template (Lines 1167-1197)
```html
<li class="upload-item flex items-center justify-between p-3 bg-gray-100 rounded">
    <div class="upload-icon-container">
        <i class="fas fa-spinner fa-spin text-sky-500"></i>
    </div>
    <span class="file-name">filename.mp4</span>
    <span class="progress-percentage text-sm">0%</span>
</li>
```

---

## 9. NEXT STEPS FOR READING RELATED FILES

- **Course Display**: [views/course-detail.ejs](views/course-detail.ejs) - How course metadata is displayed
- **Course Playback**: [views/courseplayer.ejs](views/courseplayer.ejs) - How lessons/modules are played
- **Course Progress**: [models/courseProgress.js](models/courseProgress.js) - Track user progress
- **File Model**: [models/file.js](models/file.js) - General file handling
- **Instructor Earnings**: [models/InstructorEarnings.js](models/InstructorEarnings.js) - Payment tracking

---

## 10. SUMMARY TABLE

| Component | Location | Purpose | Key IDs/Classes |
|-----------|----------|---------|-----------------|
| Form Container | gencourse.ejs:1 | Main form wrapper | `#multi-step-form` |
| Step 1: Course Details | Lines 235-358 | Basic metadata | `#course-title`, `#course-description`, etc. |
| Step 2: Curriculum | Lines 360-413 | Modules & lessons | `#modules-container`, `.module-item`, `.resource-item` |
| Step 3: Tags | Lines 415-460 | Searchability tags | `#tags-container`, `.tag` |
| Module Creator | Lines 745-810 | Dynamic module HTML | `createModuleElement()` |
| Resource Creator | Lines 811-900 | Dynamic resource HTML | `createResourceElement()` |
| Upload Orchestrator | Lines 1575-1750 | File upload handler | `uploadOrchestrator()` |
| Backend Handler | coursecontroller.js:139 | MongoDB save | `createCourse()` |
| DB Schema | models/course.js:1 | Data structure | `courseSchema`, `moduleSchema`, `submoduleSchema` |
| Route Handler | courseroutes.js:29 | Endpoint mapping | `/coursecreation`, `/create-course` |

