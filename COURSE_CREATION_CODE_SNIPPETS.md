# Course Creation - Code Snippets & Examples

## 1. MODULE & RESOURCE CREATION PATTERNS

### Adding a New Module Dynamically
```javascript
// From gencourse.ejs, Line 805-810

addModuleBtn.addEventListener('click', () => {
    moduleCount++;
    const newModule = createModuleElement(moduleCount);
    if (modulesContainer) {
        modulesContainer.insertAdjacentHTML('beforeend', newModule);
        attachModuleEventListeners(modulesContainer.lastElementChild);
    }
});
```

### Module HTML Template
```javascript
// From gencourse.ejs, Lines 745-810
const createModuleElement = (count) => {
    return `
    <div class="module-item p-4 bg-gray-800 border border-gray-700 rounded-lg shadow-sm">
        <div class="flex justify-between items-center mb-4">
            <div class="editable-container">
                <h3 class="module-title font-bold text-md sm:text-lg text-white">
                    Module ${count}
                </h3>
            </div>
            <div class="flex items-center space-x-2">
                <button type="button" class="edit-module-btn text-sky-400 hover:text-sky-300 focus:outline-none">
                    <i class="fas fa-edit"></i>
                </button>
                <button type="button" class="delete-module-btn text-red-500 hover:text-red-400 focus:outline-none">
                    <i class="fas fa-trash-alt"></i>
                </button>
            </div>
        </div>
        <div class="space-y-4">
            <div class="flex justify-between items-center flex-wrap gap-2">
                <span class="text-sm text-gray-400">Lesson Resources</span>
                <button type="button" class="add-resource-btn bg-sky-200 text-sky-800 font-semibold py-1 px-3 rounded-full hover:bg-sky-300 transition-colors duration-200 text-sm">
                    + Add Resource
                </button>
            </div>
            <div class="resources-container space-y-2"></div>
        </div>
    </div>`;
};
```

### Resource/Lesson HTML Template
```javascript
// From gencourse.ejs, Lines 811-910
const createResourceElement = (id) => {
     return `
    <div class="resource-item bg-gray-900 border border-gray-700 rounded-lg overflow-hidden" data-resource-id="${id}">
        <div class="flex justify-between items-center p-4 cursor-pointer" data-accordion-toggle>
            <div class="flex items-center space-x-3 flex-grow min-w-0">
                <i class="fas fa-grip-vertical text-gray-500 hidden sm:block cursor-grab resource-handle"></i>
                <div class="editable-container flex-grow min-w-0">
                    <h4 class="resource-title font-medium text-white text-sm sm:text-base truncate">
                        New Resource ${id}
                    </h4>
                </div>
            </div>
            <div class="flex items-center space-x-3 flex-shrink-0">
                <span class="edit-resource-btn text-sky-400 hover:text-sky-300 cursor-pointer">
                    <i class="fas fa-edit"></i>
                </span>
                <span class="delete-resource-btn text-red-500 hover:text-red-400 cursor-pointer">
                    <i class="fas fa-trash-alt"></i>
                </span>
                <i class="fas fa-chevron-down text-gray-400 transform transition-transform duration-200"></i>
            </div>
        </div>
        <div class="resource-details p-4 pt-0 hidden space-y-4">
            <!-- Type Selection: Video vs Document -->
            <div class="flex justify-around mb-4 p-1 bg-gray-700 rounded-xl">
                <button type="button" class="resource-type-btn flex items-center justify-center gap-2 p-3 w-1/2 rounded-xl transition-all duration-300 bg-sky-500 text-white shadow-lg" data-type="video">
                    <i class="fas fa-video w-5 h-5"></i>
                    <span class="font-semibold text-sm sm:text-base">Video</span>
                </button>
                <button type="button" class="resource-type-btn flex items-center justify-center gap-2 p-3 w-1/2 rounded-xl transition-all duration-300 text-gray-300 hover:bg-gray-600" data-type="document">
                    <i class="fas fa-file-alt w-5 h-5"></i>
                    <span class="font-semibold text-sm sm:text-base">Document</span>
                </button>
            </div>

            <!-- Dynamic Input Container (Updated based on type) -->
            <div class="dynamic-input-container space-y-4">
                <!-- For Video Type -->
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-1">Resource Content</label>
                    <div class="flex items-center gap-4 bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-700 mb-2">
                        <i class="fas fa-upload text-sky-400 w-5 h-5"></i>
                        <button type="button" class="flex-1 text-left text-gray-400 font-medium truncate upload-btn" data-type="video" data-resource-id="${id}">
                            Upload Video File
                        </button>
                        <input type="file" id="video-file-input-${id}" class="hidden file-input" accept="video/*" data-resource-id="${id}" data-type="video">
                    </div>
                    <div class="flex items-center gap-4 bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-700">
                        <i class="fas fa-link text-green-400 w-5 h-5"></i>
                        <input type="text" placeholder="Paste URL (e.g., YouTube, Vimeo)" class="resource-url-input flex-1 bg-transparent focus:outline-none placeholder-gray-500 text-white font-medium">
                    </div>
                    <p class="resource-file-error text-red-400 text-sm mt-1 hidden"></p>
                </div>

                <!-- Duration Field -->
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-1">Duration (minutes)</label>
                    <input type="number" class="resource-duration w-full bg-gray-800 border border-gray-600 text-white rounded-md shadow-sm p-2 focus:ring-sky-400 focus:border-sky-400" placeholder="e.g., 30 minutes" min="1" value="30">
                    <p class="text-gray-400 text-xs mt-1">Estimated duration of this resource in minutes</p>
                </div>
            </div>
        </div>
    </div>`;
};
```

---

## 2. FILE UPLOAD PATTERNS

### Get Presigned URL
```javascript
// From gencourse.ejs, Lines 1476-1508

async function getPresignedUrl(file) {
    const backendUrl = '/api/courses/generate-presigned-url';
    try {
        const response = await fetch(backendUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                fileName: file.name, 
                fileType: file.type,
                fileCategory: determineFileCategory(file)  // Auto-detect
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to get pre-signed URL.');
        }
        
        return await response.json(); // { signedUrl, finalUrl }
    } catch (error) {
        console.error("Error getting pre-signed URL:", error);
        throw error;
    }
}
```

### Upload File to S3
```javascript
// From gencourse.ejs, Lines 1544-1573

function uploadFileToS3(signedUrl, file, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('PUT', signedUrl, true);
        xhr.setRequestHeader('Content-Type', file.type);

        // Track upload progress
        xhr.upload.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentComplete = Math.round((event.loaded / event.total) * 100);
                onProgress(percentComplete);
            }
        };

        xhr.onload = () => {
            if (xhr.status === 200) {
                onProgress(100);
                resolve();
            } else {
                reject(new Error(`S3 Upload failed: ${xhr.status} ${xhr.statusText}`));
            }
        };
        
        xhr.onerror = () => reject(new Error('Network error during S3 upload.'));
        xhr.send(file);
    });
}
```

### Determine File Category
```javascript
// From gencourse.ejs, Lines 1518-1542

function determineFileCategory(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    const mimeType = file.type.toLowerCase();
    
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(ext) || 
        mimeType.startsWith('image/')) {
        return 'images';
    } else if (['pdf'].includes(ext) || mimeType === 'application/pdf') {
        return 'pdfs';
    } else if (mimeType.startsWith('video/')) {
        return 'videos';
    } else if (['doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx'].includes(ext)) {
        return 'documents';
    }
    return 'videos'; // default
}
```

---

## 3. UPLOAD ORCHESTRATION

### Full Upload Orchestrator Function
```javascript
// From gencourse.ejs, Lines 1575-1750

async function uploadOrchestrator(courseData) {
    if (!uploadProgressContainer || !uploadList || !overallProgressBar || !overallProgressText) {
        return;
    }

    uploadProgressContainer.classList.remove('hidden');
    uploadList.innerHTML = '';
    updateOverallProgress(0);
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin mr-2"></i> <span>Uploading...</span>`;

    try {
        // 1. IDENTIFY FILES TO UPLOAD
        const filesToUpload = [];
        const uploadProgressMap = new Map();

        if (courseData.courseImage) {
            const fileInfo = { type: 'thumbnail', file: courseData.courseImage };
            filesToUpload.push(fileInfo);
            uploadProgressMap.set(fileInfo, 0);
        }
        
        if (courseData.introVideoFile) {
            const fileInfo = { type: 'introVideo', file: courseData.introVideoFile };
            filesToUpload.push(fileInfo);
            uploadProgressMap.set(fileInfo, 0);
        }
        
        courseData.modules.forEach((module, mIndex) => {
            module.resources.forEach((resource, rIndex) => {
                if (resource.file) {
                    const fileInfo = { 
                        type: 'resource', 
                        file: resource.file, 
                        moduleIndex: mIndex, 
                        resourceIndex: rIndex 
                    };
                    filesToUpload.push(fileInfo);
                    uploadProgressMap.set(fileInfo, 0);
                }
            });
        });

        // Calculate total size for accurate progress
        const totalSize = filesToUpload.reduce((sum, fi) => sum + fi.file.size, 0);
        let totalUploaded = 0;

        const updateTotalProgress = () => {
            totalUploaded = Array.from(uploadProgressMap.entries()).reduce((sum, [fi, progress]) => {
                return sum + (fi.file.size * (progress / 100));
            }, 0);
            const overallPercent = totalSize > 0 ? 
                Math.round((totalUploaded / totalSize) * 100) : 
                (filesToUpload.length > 0 ? 0 : 100);
            updateOverallProgress(overallPercent);
        };

        // 2. CREATE UPLOAD TASKS
        const uploadTasks = filesToUpload.map(fileInfo => {
            const progressItem = createUploadItem(fileInfo.file.name);
            const onProgress = (percentage) => {
                updateItemProgress(progressItem, percentage);
                uploadProgressMap.set(fileInfo, percentage);
                updateTotalProgress();
            };

            return async () => {
                try {
                    const { signedUrl, finalUrl } = await getPresignedUrl(fileInfo.file);
                    await uploadFileToS3(signedUrl, fileInfo.file, onProgress);
                    return { ...fileInfo, finalUrl };
                } catch(uploadError) {
                    console.error(`Error uploading ${fileInfo.file.name}:`, uploadError);
                    progressItem.querySelector('.progress-percentage').textContent = 'Error';
                    progressItem.querySelector('.progress-percentage').classList.remove('text-sky-400', 'text-green-400');
                    progressItem.querySelector('.progress-percentage').classList.add('text-red-400');
                    const iconContainer = progressItem.querySelector('.upload-icon-container');
                    if(iconContainer) iconContainer.innerHTML = '<i class="fas fa-exclamation-circle text-red-400 text-xl"></i>';
                    throw uploadError;
                }
            };
        });

        // 3. EXECUTE UPLOADS IN PARALLEL
        const uploadedFileResults = await Promise.all(uploadTasks.map(task => task()));
        updateOverallProgress(100);

        // 4. MAP CLOUDFRONT URLS BACK TO COURSEDATA
        const finalCoursePayload = JSON.parse(JSON.stringify(courseData)); // Deep clone
        uploadedFileResults.forEach(result => {
            if (result.type === 'thumbnail') {
                finalCoursePayload.thumbnailUrl = result.finalUrl;
            } else if (result.type === 'introVideo') {
                finalCoursePayload.introVideoUrl = result.finalUrl;
            } else if (result.type === 'resource') {
                finalCoursePayload.modules[result.moduleIndex]
                    .resources[result.resourceIndex].fileUrl = result.finalUrl;
                finalCoursePayload.modules[result.moduleIndex]
                    .resources[result.resourceIndex].url = null;
            }
        });

        // Clean up file objects before sending to backend
        delete finalCoursePayload.courseImage;
        delete finalCoursePayload.introVideoFile;
        finalCoursePayload.modules.forEach(m => 
            m.resources.forEach(r => delete r.file)
        );

        // 5. SEND FINAL PAYLOAD TO BACKEND
        const finalBackendUrl = '/api/courses/create-course';
        const finalResponse = await fetch(finalBackendUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(finalCoursePayload)
        });

        if (!finalResponse.ok) {
            const error = await finalResponse.json();
            throw new Error(error.message || 'Failed to save course data on the server.');
        }
        
        const backendResponse = await finalResponse.json();

        // SUCCESS!
        showModal("Success!", "Course created successfully!", false, true);
        resetForm();

    } catch (error) {
        console.error("Course creation failed:", error);
        showModal("Upload Failed", `An error occurred: ${error.message}`);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<i class="fas fa-save"></i> <span>Save Course</span>`;
    }
}
```

---

## 4. DATA COLLECTION PATTERN

### Collect Form Data Before Upload
```javascript
// From gencourse.ejs, Lines 1755-1875

// User clicks submit → validateFormOnSubmit() → collectCourseData()

const courseData = {
    // Basic Metadata
    title: document.getElementById('course-title').value.trim(),
    description: document.getElementById('course-description').value.trim(),
    price: parseFloat(document.getElementById('course-price').value) || 0,
    category: document.getElementById('course-category').value.trim(),
    level: document.getElementById('course-level').value.trim(),
    
    // Learning Content (multiline → array)
    learningOutcomes: document.getElementById('course-learning-outcomes')
        .value.trim()
        .split('\n')
        .map(item => item.trim())
        .filter(item => item),
    requirements: document.getElementById('course-requirements')
        .value.trim()
        .split('\n')
        .map(item => item.trim())
        .filter(item => item),
    
    // Intro Video (EITHER URL OR FILE)
    introVideoOption: document.querySelector('input[name="video-option"]:checked').value,
    introVideoUrl: document.getElementById('intro-video-url').value.trim() || null,
    introVideoFile: document.getElementById('intro-video-file').files[0] || null,
    
    // Thumbnail
    courseImage: document.getElementById('course-image-file').files[0] || null,
    
    // Course Structure
    modules: [],
    tags: []
};

// GATHER MODULES
document.querySelectorAll('.module-item').forEach((moduleEl, moduleIndex) => {
    const module = {
        title: moduleEl.querySelector('.module-title').textContent.trim(),
        order: moduleIndex + 1,
        resources: []
    };
    
    // GATHER RESOURCES
    moduleEl.querySelectorAll('.resource-item').forEach((resourceEl, resourceIndex) => {
        const resourceTypeBtn = resourceEl.querySelector('.resource-type-btn.bg-sky-500');
        const resourceType = resourceTypeBtn ? resourceTypeBtn.dataset.type : 'video';
        const resource = {
            title: resourceEl.querySelector('.resource-title').textContent.trim(),
            type: resourceType.charAt(0).toUpperCase() + resourceType.slice(1), // Video or Document
            url: resourceEl.querySelector('.resource-url-input')?.value.trim() || null,
            file: resourceEl.querySelector('.file-input')?.files[0] || null,
            duration: parseInt(resourceEl.querySelector('.resource-duration')?.value) || 30,
            order: resourceIndex + 1
        };
        
        // Prioritize file if both exist
        if(resource.file && resource.url) {
            resource.url = null;
        }
        module.resources.push(resource);
    });
    
    courseData.modules.push(module);
});

// GATHER TAGS
document.querySelectorAll('#tags-container .tag').forEach(tagEl => {
    courseData.tags.push(
        tagEl.querySelector('span:first-child').textContent.trim()
    );
});

// ADJUST VIDEO OPTION
if (courseData.introVideoOption === 'file') {
    courseData.introVideoUrl = null;
} else {
    courseData.introVideoFile = null;
}
delete courseData.introVideoOption; // Remove temporary field

// NOW DATA IS READY - SEND TO ORCHESTRATOR
await uploadOrchestrator(courseData);
```

---

## 5. BACKEND COURSE CREATION

### Backend Controller
```javascript
// From controllers/coursecontroller.js, Lines 139-250

exports.createCourse = async (req, res) => {
    try {
        console.log(req.body)
        const courseDataFromFrontend = req.body;

        // Check authentication
        if (!req.user) {
            return res.status(401).json({ message: "Authentication required" });
        }

        const mockUserId = req.user._id;
        if (!mongoose.Types.ObjectId.isValid(mockUserId)) {
            return res.status(400).json({ message: "Invalid User ID format" });
        }

        // MAP FRONTEND DATA TO BACKEND SCHEMA
        const mappedModules = courseDataFromFrontend.modules.map(module => ({
            unit: module.title,
            order: module.order,
            submodules: module.resources.map(resource => {
                const cloudFrontUrl = resource.fileUrl;
                
                return {
                    title: resource.title,
                    type: resource.type,
                    fileUrl: cloudFrontUrl,
                    externalUrl: resource.url || cloudFrontUrl,
                    order: resource.order,
                    duration: resource.duration && !isNaN(resource.duration) ? 
                        parseInt(resource.duration) : 30
                };
            })
        }));

        // CALCULATE TOTAL DURATION
        let totalDurationMinutes = 0;
        mappedModules.forEach(module => {
            module.submodules.forEach(submodule => {
                if (submodule.duration && !isNaN(submodule.duration)) {
                    totalDurationMinutes += parseInt(submodule.duration);
                }
            });
        });

        if (totalDurationMinutes === 0 && mappedModules.length > 0) {
            totalDurationMinutes = mappedModules.reduce((sum, module) => {
                return sum + (module.submodules.length * 30);
            }, 0);
        }

        // PARSE LEARNING OUTCOMES & REQUIREMENTS
        const learningOutcomes = courseDataFromFrontend.learningOutcomes
            ? (Array.isArray(courseDataFromFrontend.learningOutcomes) 
                ? courseDataFromFrontend.learningOutcomes 
                : courseDataFromFrontend.learningOutcomes
                    .split(',')
                    .map(item => item.trim())
                    .filter(item => item))
            : [];

        const requirements = courseDataFromFrontend.requirements
            ? (Array.isArray(courseDataFromFrontend.requirements) 
                ? courseDataFromFrontend.requirements 
                : courseDataFromFrontend.requirements
                    .split(',')
                    .map(item => item.trim())
                    .filter(item => item))
            : [];

        // CREATE COURSE DOCUMENT
        const newCourse = new Course({
            title: courseDataFromFrontend.title,
            description: courseDataFromFrontend.description,
            price: courseDataFromFrontend.price,
            category: courseDataFromFrontend.category,
            thumbnailUrl: courseDataFromFrontend.thumbnailUrl,
            introVideoUrl: courseDataFromFrontend.introVideoUrl,
            tags: courseDataFromFrontend.tags,
            modules: mappedModules,
            userId: mockUserId,
            duration: totalDurationMinutes,
            learningOutcomes: learningOutcomes,
            requirements: requirements,
            level: courseDataFromFrontend.level || "All Levels",
            isFree: courseDataFromFrontend.price === 0 || courseDataFromFrontend.price === null,
            published: false,
            discountPrice: courseDataFromFrontend.discountPrice || null,
        });

        const savedCourse = await newCourse.save();
        res.status(201).json(savedCourse);

    } catch (error) {
        console.error("Error creating course:", error);
        if (error.code === 11000) {
            return res.status(409).json({ message: "A course with this title already exists." });
        }
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: error.message });
        }
        res.status(500).json({ message: "Failed to create course" });
    }
};
```

---

## 6. FORM VALIDATION PATTERNS

### Validate All Steps
```javascript
// From gencourse.ejs, Lines 1323-1436

function validateStep1() {
    const isTitleValid = validateTitle();
    const isDescriptionValid = validateDescription();
    const isPriceValid = validatePrice();
    const isCategoryValid = validateCategory();
    const isVideoValid = validateIntroVideo();
    const isImageValid = validateImageFile();
    return isTitleValid && isDescriptionValid && isPriceValid && 
           isCategoryValid && isVideoValid && isImageValid;
}

function validateStep2() {
    let isValid = true;
    const modules = modulesContainer.querySelectorAll('.module-item');

    if (modules.length === 0) {
        showModal('Curriculum Error', 'Please add at least one module.');
        isValid = false;
    } else {
        modules.forEach((moduleEl, mIndex) => {
            const resources = moduleEl.querySelectorAll('.resource-item');
            if (resources.length === 0) {
                console.warn(`Module ${mIndex + 1} has no resources.`);
            } else {
                resources.forEach((resourceEl, rIndex) => {
                    const fileInput = resourceEl.querySelector('.file-input');
                    const urlInput = resourceEl.querySelector('.resource-url-input');
                    const errorEl = resourceEl.querySelector('.resource-file-error');
                    let hasContent = false;

                    if (fileInput && fileInput.files.length > 0) {
                        hasContent = true;
                    } else if (urlInput && urlInput.value.trim() !== '') {
                        try {
                            new URL(urlInput.value.trim());
                            hasContent = true;
                        } catch (_) {
                            displayError(errorEl, 'Invalid URL format.');
                            isValid = false;
                        }
                    }

                    if (!hasContent) {
                        displayError(errorEl, 'Please provide a file or a URL.');
                        isValid = false;
                    } else if (errorEl) {
                        displayError(errorEl, '');
                    }
                });
            }
        });
    }
    return isValid;
}

function validateTags() {
    const tags = tagsContainer.querySelectorAll('.tag');
    if (tags.length < 2) {
        return displayError(
            tagsContainer.parentElement.querySelector('#tags-error'), 
            'Please add at least two tags.'
        ), false;
    }
    return displayError(
        tagsContainer.parentElement.querySelector('#tags-error'), 
        ''
    ), true;
}

function validateFormOnSubmit() {
    const isStep1Valid = validateStep1();
    const isStep2Valid = validateStep2();
    const areTagsValid = validateTags();

    if (!isStep1Valid) {
        updateStep(1);
        showModal('Validation Error', 'Please correct the errors in the Course Details section.');
        return false;
    }
    if (!isStep2Valid) {
        updateStep(2);
        showModal('Validation Error', 'Please ensure all modules have resources with valid content.');
        return false;
    }
    if (!areTagsValid) {
        showModal('Validation Error', 'Please add at least two tags for the course.');
        return false;
    }

    return true;
}
```

### Individual Field Validators
```javascript
// From gencourse.ejs, Lines 1260-1322

function validateTitle() {
    const input = document.getElementById('course-title');
    const value = input.value.trim();
    if (value.length < 5) 
        return displayError(input, 'Title must be at least 5 characters.'), false;
    if (value.length > 80) 
        return displayError(input, 'Title cannot exceed 80 characters.'), false;
    return displayError(input, ''), true;
}

function validateDescription() {
    const input = document.getElementById('course-description');
    const value = input.value.trim();
    if (value.length < 20) 
        return displayError(input, 'Description must be at least 20 characters.'), false;
    if (value.length > 500) 
        return displayError(input, 'Description cannot exceed 500 characters.'), false;
    return displayError(input, ''), true;
}

function validatePrice() {
    const input = document.getElementById('course-price');
    const valueStr = input.value.trim();
    if (valueStr === '') 
        return displayError(input, 'Price is required.'), false;
    const value = parseFloat(valueStr);
    if (isNaN(value)) 
        return displayError(input, 'Please enter a valid number.'), false;
    if (value < 300) 
        return displayError(input, 'Price must be at least ₹300.'), false;
    if (value > 1000000) 
        return displayError(input, 'Price cannot exceed ₹1,000,000.'), false;
    return displayError(input, ''), true;
}

function validateIntroVideo() {
    const isUrlOption = document.getElementById('video-option-url').checked;
    const urlInput = document.getElementById('intro-video-url');
    const fileInput = document.getElementById('intro-video-file');
    const urlValue = urlInput.value.trim();
    const youtubeRegex = /^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.?be)\/.+$/;
    const errorElementId = 'intro-video-file';

    if (isUrlOption) {
        if (urlValue === '') 
            return displayError(errorElementId, 'YouTube URL is required.'), false;
        if (!youtubeRegex.test(urlValue)) 
            return displayError(errorElementId, 'Please enter a valid YouTube URL.'), false;
    } else {
        if (fileInput.files.length === 0) 
            return displayError(errorElementId, 'Video file is required.'), false;
        const file = fileInput.files[0];
        if (file && !file.type.startsWith('video/')) 
            return displayError(errorElementId, 'Please select a valid video file.'), false;
    }

    return displayError(errorElementId, ''), true;
}
```

---

## 7. RESOURCE TYPE SWITCHING

### Switch Between Video & Document
```javascript
// From gencourse.ejs, Lines 914-973

const handleResourceTypeSwitch = (button) => {
    const resourceItem = button.closest('.resource-item');
    const dynamicInputContainer = resourceItem.querySelector('.dynamic-input-container');
    const resourceType = button.dataset.type;
    const resourceId = resourceItem.dataset.resourceId;

    // Update button styles
    const allButtons = resourceItem.querySelectorAll('.resource-type-btn');
    allButtons.forEach(btn => {
        btn.classList.remove('bg-sky-500', 'text-white', 'shadow-lg');
        btn.classList.add('text-gray-300', 'hover:bg-gray-600');
    });
    button.classList.remove('text-gray-300', 'hover:bg-gray-600');
    button.classList.add('bg-sky-500', 'text-white', 'shadow-lg');

    // Update dynamic input area
    if (dynamicInputContainer) {
        let inputHTML = '';
        if (resourceType === 'video') {
            inputHTML = `
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-1">Resource Content</label>
                <div class="flex items-center gap-4 bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-700 mb-2">
                    <i class="fas fa-upload text-sky-400 w-5 h-5"></i>
                    <button type="button" class="flex-1 text-left text-gray-400 font-medium truncate upload-btn" data-type="video" data-resource-id="${resourceId}">
                        Upload Video File
                    </button>
                    <input type="file" id="video-file-input-${resourceId}" class="hidden file-input" accept="video/*" data-resource-id="${resourceId}" data-type="video">
                </div>
                <div class="flex items-center gap-4 bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-700">
                    <i class="fas fa-link text-green-400 w-5 h-5"></i>
                    <input type="text" placeholder="Paste URL (e.g., YouTube, Vimeo)" class="resource-url-input flex-1 bg-transparent focus:outline-none placeholder-gray-500 text-white font-medium">
                </div>
                <p class="resource-file-error text-red-400 text-sm mt-1 hidden"></p>
            </div>`;
        } else if (resourceType === 'document') {
            inputHTML = `
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-1">Resource Content</label>
                <div class="flex items-center gap-4 bg-gray-800 p-4 rounded-lg shadow-sm border border-gray-700">
                    <i class="fas fa-upload text-purple-400 w-5 h-5"></i>
                    <button type="button" class="flex-1 text-left text-gray-400 font-medium truncate upload-btn" data-type="document" data-resource-id="${resourceId}">
                        Upload Document File
                    </button>
                    <input type="file" id="document-file-input-${resourceId}" class="hidden file-input" accept=".pdf,.doc,.docx,.txt,.ppt,.pptx,.xls,.xlsx" data-resource-id="${resourceId}" data-type="document">
                </div>
                <p class="resource-file-error text-red-400 text-sm mt-1 hidden"></p>
            </div>`;
        }
        dynamicInputContainer.innerHTML = inputHTML;
        validateStep2();
    }
};
```

---

## 8. COURSE MODEL SCHEMA

### MongoDB Course Schema
```javascript
// From models/course.js

const submoduleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  type: { type: String, enum: ["Video", "Document"], required: true },
  fileUrl: { type: String },           // CloudFront URL
  externalUrl: { type: String },       // YouTube/Vimeo or backup
  duration: { type: Number },          // In minutes
  order: { type: Number }
}, { _id: true });

const moduleSchema = new mongoose.Schema({
  unit: { type: String, required: true },
  submodules: [submoduleSchema],
  order: { type: Number }
}, { _id: true });

const courseSchema = new mongoose.Schema({
  category: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  discountPrice: { type: Number },
  thumbnailUrl: { type: String },
  introVideoUrl: { type: String },
  title: { type: String, required: true, unique: true },
  contentTypeId: { type: mongoose.Schema.Types.ObjectId, ref: "ContentType" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  modules: [moduleSchema],
  tags: [{ type: String }],
  rating: { type: Number, default: 0 },
  enrollCount: { type: Number, default: 0 },
  duration: { type: Number },                    // Total in minutes
  learningOutcomes: [{ type: String }],
  requirements: [{ type: String }],
  level: { type: String, enum: ["Beginner", "Intermediate", "Advanced", "All Levels"], default: "All Levels" },
  isFree: { type: Boolean, default: false },
  published: { type: Boolean, default: false },
  version: { type: String },
  releaseDate: { type: Date },
  enrolledStudents: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
}, {
  timestamps: true
});

module.exports = mongoose.model("Course", courseSchema);
```

