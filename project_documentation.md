# Digital Market Project - Comprehensive Technical Documentation

**Version:** 1.0
**Date:** November 20, 2025
**Author:** Antigravity (AI Assistant)

---

## Table of Contents

1.  [Executive Summary](#1-executive-summary)
2.  [System Architecture](#2-system-architecture)
5.  [Frontend Architecture](#5-frontend-architecture)
    *   [View Layer (EJS)](#51-view-layer-ejs)
    *   [Client-Side Logic](#52-client-side-logic)
    *   [Styling](#53-styling)
6.  [Core Features Deep Dive](#6-core-features-deep-dive)
    *   [Secure File Uploads (S3 & Multipart)](#61-secure-file-uploads)

Key capabilities include:
*   **Digital Asset Marketplace**: Users can browse, purchase, and download digital files.
*   **Course Platform**: Creators can build structured courses with video and document lessons.
*   **Secure Payments**: Integrated with Razorpay for secure transaction processing.
*   **Real-Time Communication**: Built-in chat system allowing direct communication between users and creators.
*   **High-Performance Content Delivery**: Utilizes AWS S3 for storage and AWS CloudFront for global content delivery, including HLS video streaming.
*   **User Engagement**: Features like user profiles, dashboards, notifications, and progress tracking.

This document provides a comprehensive technical analysis of the system, intended for developers, architects, and stakeholders.

---

## 2. System Architecture

### 2.1. High-Level Overview

The application follows a **Monolithic Architecture** with a layered design, leveraging external cloud services for scalability.

*   **Client**: Web browser rendering server-side generated HTML (EJS) and executing client-side JavaScript.
*   **Server**: Node.js/Express application handling business logic, API routing, and HTML rendering.
*   **Database**: MongoDB (via Mongoose) for persistent storage of application data.
*   **Real-Time Layer**: WebSocket server (integrated with the main HTTP server) for chat functionality.
*   **External Services**:
    *   **AWS S3**: Object storage for user uploads (files, course videos).
    *   **AWS CloudFront**: CDN for fast content delivery and video streaming.
    *   **Razorpay**: Payment gateway.
    *   **Google/Facebook OAuth**: Authentication providers.
    *   **Firebase/Supabase**: (Used for specific auxiliary functions like notifications or legacy storage).

```mermaid
graph TD
    Client[Web Client] -->|HTTP/HTTPS| LB[Load Balancer / Proxy]
    LB --> Server[Node.js Express Server]
    
    subgraph "Application Server"
        Server --> Auth[Auth Module]
        Server --> API[REST API]
        Server --> Views[View Engine (EJS)]
        Server --> WS[WebSocket Server]
    end

    Server -->|Read/Write| DB[(MongoDB)]
    Server -->|Upload/Presign| S3[AWS S3]
    Server -->|Payment API| Razorpay[Razorpay]
    
    Client -->|WS Connection| WS
    Client -->|Stream Content| CF[AWS CloudFront]
    CF -->|Origin| S3
```

### 2.2. Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend Runtime** | Node.js | JavaScript runtime built on Chrome's V8 engine. |
| **Web Framework** | Express.js | Fast, unopinionated web framework for Node.js. |
| **Database** | MongoDB | NoSQL database for flexible data modeling. |
| **ODM** | Mongoose | Object Data Modeling library for MongoDB and Node.js. |
| **Templating** | EJS | Embedded JavaScript templates for server-side rendering. |
| **Styling** | TailwindCSS | Utility-first CSS framework (via PostCSS). |
| **Authentication** | Passport.js | Authentication middleware (Google, Facebook strategies). |
| **Session Mgmt** | JWT & Cookies | JSON Web Tokens for stateless auth, stored in HTTP-only cookies. |
| **Real-Time** | `ws` (WebSocket) | Native WebSocket implementation for Node.js. |
| **File Uploads** | Multer & AWS SDK | Handling multipart/form-data and S3 interactions. |
| **Cloud Provider** | AWS | S3, CloudFront, SES, SQS. |
| **Payment Gateway** | Razorpay | Payment processing integration. |

### 2.3. Directory Structure

The project follows a standard MVC (Model-View-Controller) pattern, though controllers are sometimes inline within routes or separated.

```text
DigitalMarketProject/
├── controllers/        # Business logic controllers
├── emails/             # Email templates and sending logic
├── models/             # Mongoose schemas and models
├── public/             # Static assets (CSS, JS, Images)
├── routes/             # API and View routes
│   ├── authentication/ # Auth-related routes
│   ├── bots/           # Background tasks/bots
│   └── ...             # Feature-specific routes
├── views/              # EJS templates
├── fileupload.js       # S3 upload handling logic
├── server.js           # Application entry point
├── package.json        # Dependencies and scripts
└── ...
```

---

## 3. Database Design

### 3.1. Overview

The database is MongoDB, chosen for its flexibility in handling varied content types (files, courses, user profiles). Mongoose is used to define schemas and enforce data integrity.

### 3.2. Data Models

#### **User (`models/userData.js`)**
Stores user identity and profile information.
*   `username`, `email`: Unique identifiers.
*   `passwordHash`: Bcrypt hashed password (for local auth).
*   `googleId`, `facebookId`: For OAuth.
*   `role`: Enum (`Buyer`, `seller`, `Admin`).
*   `balance`: Virtual or stored field for seller earnings.
*   `followers`, `following`: Arrays of User ObjectIds for social graph.

#### **File (`models/file.js`)**
Represents a standalone digital asset for sale.
*   `filename`, `filedescription`: Metadata.
*   `price`: Cost of the file.
*   `fileUrl`: S3 key or URL.
*   `category`: Classification.
*   `slug`: URL-friendly identifier.
*   `likes`, `downloadCount`: Engagement metrics.

#### **Course (`models/course.js`)**
Represents a structured learning path.
*   `title`, `description`, `price`.
*   `modules`: Array of module objects.
    *   `submodules`: Array of lessons (Video/Document).
        *   `fileUrl`: Path to content (S3/CloudFront).
        *   `type`: `Video` or `Document`.

#### **UserProgress (`models/courseProgress.js`)**
Tracks a user's journey through a course.
*   `userId`, `courseId`: References.
*   `progress`: Array of status objects for each lesson (`not_started`, `in_progress`, `completed`).

#### **Order (`models/Order.js`)**
Records purchase transactions.
*   `orderId`: Razorpay order ID.
*   `transactionId`: Razorpay payment ID.
*   `amount`, `status`, `items`.

#### **UserMessage (`models/UserMessage.js`)**
Stores chat history.
*   `senderId`, `recipientId`.
*   `conversationId`: Unique string (sorted IDs) to group messages.
*   `text`: Message content.
*   `status`: `sent`, `delivered`, `read`.

---

## 4. API Reference

### 4.1. Authentication (`routes/authentication/`)

*   `GET /auth/google`: Initiates Google OAuth flow.
*   `GET /auth/google/callback`: Handle Google redirect, create/update user, issue JWT.
*   `POST /auth/login`: Local login with email/password.
*   `POST /auth/signup`: Register new user.
*   `POST /auth/verify-2fa`: Verify Two-Factor Authentication code.

### 4.2. File Management (`fileupload.js`)

*   `POST /start-multipart-upload`: Initiates S3 multipart upload. Returns `uploadId`.
*   `GET /get-presigned-part-url`: Generates presigned URL for a specific chunk.
*   `POST /complete-multipart-upload`: Finalizes upload on S3 and creates `File` record in DB.
*   `POST /abort-multipart-upload`: Cancels an upload session.

### 4.3. Course Management (`routes/courseroutes.js`)

*   `POST /create-course`: Creates a new course with metadata.
*   `GET /api/courses/:courseId`: Fetches course details.
    *   *Logic*: Transforms S3 URLs to CloudFront URLs. For videos, it points to `.m3u8` HLS manifests.

### 4.4. Payments (`server.js`)

*   `POST /create-order`: Creates a Razorpay order.
*   `POST /verify-payment`: Verifies payment signature.
    *   *On Success*: Updates `Order`, `UserPurchases`, `UserDownloads`, and `UserBalance` (for sellers). Sends notifications.

### 4.5. Chat System (`routes/chatRoutes.js`)

*   `GET /api/chat/UserMessages/:userId`: Fetches chat history with a specific user.
*   `GET /api/chat/chat/:userId`: Renders the chat UI.

---

## 5. Frontend Architecture

### 5.1. View Layer (EJS)
The application uses **EJS** for server-side rendering.
*   `views/landing.ejs`: Home page.
*   `views/createcourse.ejs`: Dashboard for creators.
*   `views/user-chat.ejs`: Chat interface.
*   `views/courseplayer.ejs`: Video player and course navigation.

### 5.2. Client-Side Logic
Located in `public/js/` (inferred) or inline in EJS files.
*   **Upload Logic**: Handles chunking files and uploading to S3 presigned URLs.
*   **Chat Logic**: Manages WebSocket connection, sending/receiving messages, and updating UI.
*   **Video Player**: Likely uses a library like Video.js or Hls.js to play `.m3u8` streams.

### 5.3. Styling
**TailwindCSS** is used for styling, providing a utility-first approach. Custom styles are likely defined in a main CSS file or within the Tailwind config.

---

## 6. Core Features Deep Dive

### 6.1. Secure File Uploads
The project implements a robust **Multipart Upload** strategy directly to S3.
1.  **Initiation**: Client requests upload start. Server asks S3 for `uploadId`.
2.  **Chunking**: Client splits file into parts (e.g., 5MB chunks).
3.  **Presigning**: Client requests a presigned URL for each part.
4.  **Direct Upload**: Client PUTs data directly to S3 (bypassing server bandwidth).
5.  **Completion**: Client notifies server to assemble parts. Server confirms with S3 and saves metadata to MongoDB.

### 6.2. Payment Integration
**Razorpay** is the payment gateway.
1.  **Order Creation**: Server calls Razorpay API to create an order ID.
2.  **Checkout**: Client opens Razorpay modal with the order ID.
3.  **Verification**: After payment, Razorpay returns `payment_id` and `signature`.
4.  **Server Validation**: Server re-calculates HMAC signature to verify authenticity.
5.  **Fulfillment**: Database is updated atomically (using `Promise.all`) to record transaction, grant access, and update balances.

### 6.3. Real-Time Chat
Implemented using `ws` (WebSocket).
*   **Connection**: Users connect via WS. Server maps `userId` to `socket`.
*   **Routing**: Messages are routed directly to the recipient's socket if online.
*   **Persistence**: All messages are saved to MongoDB (`UserMessage`).
*   **Status**: Supports `sent`, `delivered`, `read` statuses.
*   **Notifications**: If recipient is offline, a push notification (via Firebase/custom logic) is triggered.

### 6.4. Video Streaming
For courses, the system uses **HLS (HTTP Live Streaming)**.
*   **Upload**: Videos are uploaded to S3.
*   **Processing**: (Likely handled by AWS MediaConvert triggered by S3 events - inferred from `video-trans` directory). Videos are converted to `.m3u8` playlists and `.ts` segments.
*   **Delivery**: `routes/courseroutes.js` rewrites S3 URLs to **CloudFront** URLs, pointing to the HLS manifest. This ensures adaptive bitrate streaming and low latency.

---

## 7. Security Implementation

*   **JWT Authentication**: Stateless authentication using JSON Web Tokens stored in HTTP-only cookies.
*   **Password Hashing**: `bcrypt` is used to hash passwords with salt.
*   **CSRF Protection**: `csurf` or similar mechanisms (implied by cookie settings like `SameSite`).
*   **XSS Protection**: `xss` library sanitizes user inputs.
*   **Rate Limiting**: `express-rate-limit` protects auth routes from brute force.
*   **Secure Headers**: `helmet` middleware sets security headers (HSTS, X-Frame-Options, etc.).
*   **Presigned URLs**: S3 access is restricted; uploads/downloads use short-lived presigned URLs.

---

## 8. Deployment & Infrastructure

*   **Environment Variables**: managed via `.env` (e.g., `MONGODB_URI`, `AWS_ACCESS_KEY_ID`, `RAZORPAY_KEY_ID`).
*   **Server**: Node.js process (likely managed by PM2 in production).
*   **Database**: MongoDB Atlas (Managed Cloud DB).
*   **Storage**: AWS S3 (Buckets for images and main files).
*   **CDN**: AWS CloudFront distribution pointing to S3 buckets.

---

## 9. User Manual

### For Buyers
1.  **Browse**: Explore files and courses on the landing page.
2.  **Purchase**: Click "Buy", complete payment via Razorpay.
3.  **Access**: Go to "My Downloads" or "My Courses" to access content.
4.  **Chat**: Use the chat feature to contact sellers for support.

### For Sellers/Creators
1.  **Upload**: Use the "Create Course" or "Upload File" dashboard.
2.  **Manage**: Set prices, descriptions, and categories.
3.  **Track**: View earnings and sales in the dashboard.
4.  **Payout**: Request withdrawals to your bank account (via UPI).

---

## 10. Developer Guide

### Setup
1.  Clone repository.
2.  Run `npm install`.
3.  Configure `.env` with all API keys.
4.  Run `npm start` or `node server.js`.

### Key Commands
*   `npm start`: Start production server.
*   `npm run dev`: Start development server (if configured).

### Contribution
*   Follow MVC pattern.
*   Ensure all new routes are protected with `authenticateJWT_user`.
*   Use `async/await` for DB operations.

## 11. Frontend Deep Dive

### 11.1. S3 Multipart Uploader (`views/fileupload.ejs`)

The file upload functionality is a critical component, handling large files (up to 8GB) directly from the browser to AWS S3. This bypasses the application server for the actual file data, preventing server bottlenecks.

#### **Architecture**
The uploader is implemented as a client-side JavaScript class `Uploader` embedded within `fileupload.ejs`.

**Key Components:**
1.  **`Uploader` Class**: Manages the state machine (idle, uploading, paused) and the upload queue.
2.  **`UIHandler` Class**: Manages DOM updates, template rendering, and modal displays.
3.  **Templates**: HTML `<template>` tags are used for different stages (`template-upload-form`, `template-preview`, `template-upload-progress`).

#### **Upload Workflow**
1.  **Initialization**:
    *   User selects a file.
    *   `Uploader` verifies file size against `MAX_FILE_SIZE_BYTES` (8GB).
2.  **Start (`startNext`)**:
    *   POST `/start-multipart-upload` with metadata (`fileName`, `fileType`).
    *   Server returns `uploadId` and `key`.
3.  **Chunking & Uploading (`_uploadChunks`)**:
    *   File is sliced into **5MB chunks**.
    *   For each chunk:
        *   GET `/get-presigned-part-url` with `uploadId`, `partNumber`, and `key`.
        *   PUT request is sent **directly to S3** using the presigned URL.
        *   `ETag` from the S3 response is stored.
4.  **Completion (`_completeUpload`)**:
    *   Once all chunks are uploaded, POST `/complete-multipart-upload`.
    *   Payload includes `parts` array (PartNumber + ETag).
    *   Server asks S3 to assemble the file and saves the record to MongoDB.

**Code Snippet (Chunk Upload Logic):**
```javascript
// Simplified logic from fileupload.ejs
const chunk = this.state.file.slice(start, end);
const response = await fetch(`/get-presigned-part-url?key=${key}&partNumber=${partNumber}...`);
const { url } = await response.json();

const xhr = new XMLHttpRequest();
xhr.open("PUT", url);
xhr.send(chunk);
```

### 11.2. Course Player SPA (`views/courseplayer.ejs`)

The course player is a self-contained Single Page Application (SPA) running inside a specific route. It handles video playback, progress tracking, and navigation without page reloads.

#### **State Management**
A global `appState` object tracks the current context:
```javascript
const appState = { 
    course: null,           // Full course object
    progress: null,         // User's progress data
    activeLessonId: null,   // Currently playing lesson ID
    lessonsFlat: [],        // Flattened list of all lessons
    hls: null,              // HLS.js instance
    lessonCompletedFlag: false 
};
```

#### **Video Playback Engine**
*   **HLS Integration**: Uses `hls.js` to play `.m3u8` streams served via CloudFront.
*   **Adaptive Bitrate**: Automatically adjusts quality based on bandwidth.
*   **Custom Controls**: Implements custom UI for Play/Pause, Volume, Speed (0.5x - 2x), and Quality Selection (Auto, 720p, 480p, etc.).

#### **Progress Tracking**
*   **Real-time Updates**: Listens to `timeupdate` event on the `<video>` element.
*   **Throttling**: Updates `in_progress` status at most every 5 seconds to reduce API load.
*   **Completion Logic**:
    *   When video reaches **80%**, it is marked as `completed`.
    *   Automatically advances to the next lesson after a short delay.

**Progress Sync Code:**
```javascript
// Throttled save function
const throttledSave = throttle((e) => {
    const percentage = (currentTime / duration) * 100;
    saveProgress(activeLessonId, 'in_progress', percentage);
}, 5000);
```

## 12. Backend Deep Dive

### 12.1. Video Transcoding Pipeline (`video-trans/sql.js`)

The project employs a sophisticated asynchronous video processing pipeline to convert uploaded videos into HLS (HTTP Live Streaming) format for adaptive bitrate streaming.

**Workflow:**
1.  **Upload**: User uploads a video to the S3 `courses/uploads/` folder.
2.  **Event Trigger**: S3 triggers an event notification to an **AWS SQS (Simple Queue Service)** queue.
3.  **Worker Polling (`sql.js`)**:
    *   The `sql.js` script (misnamed, actually a worker) continuously polls the SQS queue.
    *   It filters messages to ensure only video files (`.mp4`, `.mov`, etc.) are processed.
4.  **Transcoding Job**:
    *   The worker submits a job to **AWS MediaConvert**.
    *   **Input**: The raw video file from S3.
    *   **Output**: HLS playlist (`.m3u8`) and segments (`.ts`) stored in the `hls-output/` folder.
    *   **Presets**: The job is configured to output multiple resolutions/bitrates (e.g., 1080p, 720p, 480p) for adaptive streaming.

**Key Code (MediaConvert Job Submission):**
```javascript
const command = new CreateJobCommand({
    Role: config.mediaConvertRole,
    Settings: {
        Inputs: [{ FileInput: `s3://${config.inputBucket}/${inputKey}` }],
        OutputGroups: [{
            Name: "HLS Group",
            Outputs: [ /* Transcoding presets for different bitrates */ ]
        }]
    }
});
await mediaConvertClient.send(command);
```

### 12.2. Background Maintenance Bots (`routes/bots`)

The system includes automated maintenance scripts to keep the database and storage clean.

*   **Account Cleanup (`cleanUpAcc.js`)**:
    *   **Schedule**: Runs daily at midnight (`0 0 * * *`).
    *   **Task**: Deletes user accounts that have been created > 24 hours ago but remain **unverified**. This prevents database clutter from spam registrations.
*   **Course Cleanup (`cleanUpCourse.js`)**:
    *   **Task**: Identifies "abandoned" courses (unpublished for > 3 hours).
    *   **Action**:
        1.  Deletes associated raw files from the main S3 bucket.
        2.  Deletes HLS files from the HLS S3 bucket.
        3.  Deletes the Course document from MongoDB.

### 12.3. Email Notification System (`emails/`)

The project features a structured email system using EJS/HTML templates, organized by domain:

*   **Auth**: Welcome emails, Password Reset, Email Verification.
*   **Marketing**: Newsletters, Promotions.
*   **Seller**: Course approval, Payout confirmation.
*   **Transaction**: Purchase receipts, Invoice generation.
*   **System**: Maintenance alerts, Policy updates.

### 12.4. WebSocket Service (`services/websocket.js`)

Real-time communication is handled by a dedicated WebSocket service.

*   **Connection Handling**: Maps `userId` to active WebSocket connections.
*   **Private Messaging**: Routes messages between users in real-time.
*   **History**: Maintains an in-memory history of messages for active sessions (Note: Long-term persistence is handled by MongoDB in `server.js`).

## 13. Database Schema Reference

### 13.1. User Model (`models/userData.js`)

```javascript
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String }, // Null for OAuth users
    googleId: { type: String },
    facebookId: { type: String },
    role: { type: String, enum: ['buyer', 'seller', 'admin'], default: 'buyer' },
    isEmailVerified: { type: Boolean, default: false },
    profilePicUrl: { type: String },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    balance: { type: Number, default: 0 }, // For sellers
    createdAt: { type: Date, default: Date.now }
});
```

### 13.2. Course Model (`models/course.js`)

```javascript
const courseSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    price: { type: Number, required: true },
    thumbnailUrl: { type: String },
    category: { type: String },
    published: { type: Boolean, default: false },
    modules: [{
        unit: { type: String },
        submodules: [{
            title: { type: String },
            type: { type: String, enum: ['Video', 'Document'] },
            fileUrl: { type: String }, // S3 URL or CloudFront HLS URL
            duration: { type: Number }
        }]
    }],
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});
```

### 13.3. File Model (`models/file.js`)

```javascript
const fileSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    fileUrl: { type: String, required: true },
    price: { type: Number, default: 0 },
    category: { type: String },
    fileSize: { type: Number },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    downloadCount: { type: Number, default: 0 },
    slug: { type: String, unique: true }
});
```

## 14. Security Architecture

### 14.1. Authentication Flow
The application uses a hybrid authentication system combining Passport.js for OAuth and JWT for session management.

**Sequence:**
1.  **User Action**: Clicks "Login with Google".
2.  **Passport Strategy**: Redirects to Google OAuth consent screen.
3.  **Callback**: Google redirects back to `/auth/google/callback` with an authorization code.
4.  **User Creation/Lookup**:
    *   System checks if a user with `googleId` exists.
    *   If not, checks for email match.
    *   If new, creates user with random username (if collision) and `isEmailVerified: true`.
5.  **Session Generation**:
    *   A JWT is signed containing `userId`.
    *   Token is set as an `httpOnly` cookie named `token`.
6.  **Client State**: Browser sends this cookie with every subsequent request.

### 14.2. Protection Measures
*   **Rate Limiting**: `express-rate-limit` restricts `/auth/` routes to 100 requests per 15 minutes to prevent brute-force attacks.
*   **Helmet**: Sets secure HTTP headers (HSTS, X-Frame-Options, etc.).
*   **Input Sanitization**: The `xss` library is used to sanitize user inputs (e.g., in chat or comments) to prevent Cross-Site Scripting.
*   **Secure Cookies**: Cookies are set with `httpOnly: true` to prevent client-side script access.

## 15. Configuration Reference

The application relies on the following environment variables. Create a `.env` file in the root directory.

| Variable | Description | Required |
| :--- | :--- | :--- |
| `PORT` | Server port (default: 3000) | No |
| `MONGO_URI` | MongoDB connection string | **Yes** |
| `JWT_SECRET` | Secret key for signing JSON Web Tokens | **Yes** |
| `GOOGLE_CLIENT_ID` | OAuth Client ID from Google Cloud Console | **Yes** |
| `GOOGLE_CLIENT_SECRET` | OAuth Client Secret from Google Cloud Console | **Yes** |
| `GOOGLE_CALLBACK_URL` | OAuth Callback URL (e.g., `https://domain.com/auth/google/callback`) | **Yes** |
| `AWS_ACCESS_KEY_ID` | AWS IAM Access Key | **Yes** |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM Secret Key | **Yes** |
| `AWS_S3_REGION` | AWS Region (e.g., `ap-south-1`) | **Yes** |
| `AWS_S3_BUCKET_NAME` | Main S3 Bucket for file uploads | **Yes** |
| `RAZORPAY_KEY_ID` | Razorpay API Key ID | **Yes** |
| `RAZORPAY_KEY_SECRET` | Razorpay API Key Secret | **Yes** |
| `CLOUDFRONT_DOMAIN` | CloudFront distribution domain (e.g., `d123.cloudfront.net`) | **Yes** |

## 16. API Reference (Expanded)

### 16.1. Chat API (`routes/chatRoutes.js`)

*   **WebSocket Endpoint**: `ws://domain.com`
    *   **Handshake**: Standard HTTP upgrade.
    *   **Events**:
        *   `register`: `{ type: 'register', userId: '...' }`
        *   `private_message`: `{ type: 'private_message', recipientId: '...', text: '...' }`
        *   `typing`: `{ type: 'typing', recipientId: '...' }`

*   **HTTP Endpoints**:
    *   `GET /user/chat/:userId`: Renders the chat UI for a specific conversation.
    *   `GET /api/messages/:userId`: Fetches message history (JSON).

### 16.2. Course API (`controllers/courseController.js`)

*   **POST /api/courses/create-course**
    *   **Headers**: `Authorization: Bearer <token>`
    *   **Body**:
        ```json
        {
          "title": "Course Title",
          "description": "Description...",
          "price": 499,
          "modules": [
            {
              "title": "Module 1",
              "resources": [
                { "title": "Lesson 1", "type": "Video", "fileUrl": "s3://..." }
              ]
            }
          ]
        }
        ```
    *   **Response**: `201 Created` with the Course object.

## 17. Detailed Code Walkthrough

This section provides a line-by-line analysis of critical system components to aid developers in understanding the implementation details.

### 17.1. Server Entry Point (`server.js`)

The `server.js` file is the backbone of the application. It orchestrates the HTTP server, WebSocket server, database connection, and middleware integration.

**Key Responsibilities:**
1.  **Initialization**: Sets up the Express app and HTTP server.
2.  **Database**: Connects to MongoDB Atlas using Mongoose.
3.  **Middleware**: Configures `cors`, `cookie-parser`, and `express.json`.
4.  **Routes**: Mounts all API and View routes (`/auth`, `/api/courses`, `/chat`, etc.).
5.  **WebSockets**: Initializes the `ws` server for real-time features.
6.  **Background Services**: Initializes Firebase Admin and Razorpay instances.

**Critical Code Block: WebSocket Integration**
```javascript
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    // Handles new connections
    // Manages user registration and message routing
});
```

### 17.2. Authentication Middleware

The application uses two primary middleware functions to protect routes.

#### **A. `jwtAuth.js` (Soft Auth)**
This middleware attempts to authenticate the user but **does not block** access if authentication fails. It is useful for routes that have optional user-specific features (e.g., a landing page that shows "Login" vs "Profile").

*   **Logic**:
    1.  Checks for `token` in cookies or `Authorization` header.
    2.  Verifies JWT using `JWT_SECRET`.
    3.  If valid, fetches `User` from DB and attaches to `req.user`.
    4.  If invalid/missing, `req.user` remains `null`, but request proceeds.

#### **B. `reaquireAuth.js` (Hard Auth)**
This middleware **enforces** authentication. It is used for protected routes like "Create Course" or "Chat".

*   **Logic**:
    1.  Checks for `token`.
    2.  If missing, redirects to `/` (Home/Login).
    3.  Verifies JWT.
    4.  If invalid, redirects to `/`.
    5.  If valid, attaches `req.user` and calls `next()`.

**Code Snippet (`reaquireAuth.js`):**
```javascript
const requireAuth = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/'); // Block access
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.userId);
        next();
    } catch (error) {
        res.redirect('/');
    }
};
```

## 18. Deployment Guide

### 18.1. Prerequisites
*   Node.js v18+
*   MongoDB Atlas Cluster
*   AWS Account (S3, CloudFront, MediaConvert, SES)
*   Razorpay Account

### 18.2. AWS EC2 Deployment (Recommended)

1.  **Launch Instance**: Ubuntu 22.04 LTS, t3.small or larger.
2.  **Security Groups**: Allow ports 22 (SSH), 80 (HTTP), 443 (HTTPS).
3.  **Setup Environment**:
    ```bash
    sudo apt update && sudo apt upgrade -y
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt install -y nodejs git nginx certbot python3-certbot-nginx
    ```
4.  **Clone & Install**:
    ```bash
    git clone <repo_url>
    cd DigitalMarketProject
    npm install
    ```
5.  **PM2 Process Management**:
    ```bash
    sudo npm install -g pm2
    pm2 start server.js --name "digital-market"
    pm2 startup
    pm2 save
    ```
6.  **Nginx Reverse Proxy**:
    Configure `/etc/nginx/sites-available/default` to proxy requests to `localhost:3000`.
    ```nginx
    server {
        listen 80;
        server_name yourdomain.com;
        location / {
            proxy_pass http://localhost:3000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
| **Email Not Sent** | SES Sandbox Mode | Verify sender email in AWS SES or move out of sandbox. |

### 19.2. Logs & Debugging
*   **Application Logs**: `pm2 logs digital-market`
*   **Nginx Logs**: `/var/log/nginx/error.log`
*   **Browser Console**: Check for client-side JS errors or network failures.

## 20. Testing Strategy

Currently, the project relies on manual testing scripts (`test.js`, `test2.js`) and ad-hoc verification. A more robust testing strategy is recommended for production.

### 20.1. Current Manual Tests
*   **Notification Testing (`test.js`)**: A script using `axios` to send POST requests to the `/send` endpoint to verify push notification delivery.
*   **Firebase FCM Testing (`test2.js`)**: A standalone script using `firebase-admin` to send test messages to specific device tokens, verifying the FCM configuration.

### 20.2. Recommended Automated Testing
To ensure stability, the following testing layers should be implemented:

1.  **Unit Tests (Jest/Mocha)**:
    *   Test individual utility functions (e.g., `addslug.js`).
    *   Test Mongoose models for validation rules.
2.  **Integration Tests (Supertest)**:
    *   Test API endpoints (`/auth/login`, `/api/courses/create-course`) with a test database.
*   **Live Streaming**: Add support for live classes using AWS IVS or similar.
*   **Mobile App**: Develop a React Native app reusing the existing API.
*   **Analytics Dashboard**: Advanced reporting for sellers (conversion rates, engagement time).

---

# Appendix A: Full API Specification

## A.1. Authentication Endpoints

### **1. Login (Local)**
*   **Endpoint**: `POST /auth/login`
*   **Description**: Authenticates a user using email and password.
*   **Request Body**:
    ```json
    {
        "email": "user@example.com",
        "password": "securePassword123"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
        "message": "Login successful",
        "token": "eyJhbGciOiJIUzI1NiIsIn...",
        "user": {
            "id": "65a1b2c3d4e5f6g7h8i9j0k1",
            "email": "user@example.com",
            "username": "user123",
            "role": "buyer"
        }
    }
    ```
*   **Error Response (401 Unauthorized)**:
    ```json
    { "message": "Invalid email or password" }
    ```

### **2. Signup (Local)**
*   **Endpoint**: `POST /auth/signup`
*   **Description**: Registers a new user.
*   **Request Body**:
    ```json
    {
        "username": "newuser",
        "email": "new@example.com",
        "password": "securePassword123"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
        "message": "Verification Link Sent Please Check Your Email",
        "token": "...",
        "user": { ... }
    }
    ```

### **3. Google OAuth**
*   **Endpoint**: `GET /auth/google`
*   **Description**: Redirects to Google Login.
*   **Callback**: `GET /auth/google/callback`
    *   **Success**: Redirects to `/` with `token` cookie set.
    *   **2FA Required**: Redirects to `/verify-2fa?token=...`.

## A.2. Course Management Endpoints

### **1. Generate Presigned URL**
*   **Endpoint**: `POST /api/courses/generate-presigned-url`
*   **Headers**: `Authorization: Bearer <token>`
*   **Request Body**:
    ```json
    {
        "fileName": "lesson1.mp4",
        "fileType": "video/mp4"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
        "signedUrl": "https://s3.ap-south-1.amazonaws.com/bucket/key?Signature=...",
        "finalUrl": "https://bucket.s3.ap-south-1.amazonaws.com/courses/uploads/unique-lesson1.mp4"
    }
    ```

### **2. Create Course**
*   **Endpoint**: `POST /api/courses/create-course`
*   **Headers**: `Authorization: Bearer <token>`
*   **Request Body**:
    ```json
    {
        "title": "Advanced Node.js",
        "description": "Master Node.js...",
        "price": 999,
        "category": "Development",
        "thumbnailUrl": "https://...",
        "modules": [
            {
                "title": "Introduction",
                "order": 1,
                "resources": [
                    {
                        "title": "Setup",
                        "type": "Video",
                        "fileUrl": "https://...",
                        "order": 1
                    }
                ]
            }
        ]
    }
    ```
*   **Success Response (201 Created)**: Returns the created Course object.

### **3. Get Course Details**
*   **Endpoint**: `GET /api/courses/:courseId`
*   **Headers**: `Authorization: Bearer <token>`
*   **Response**: Returns HTML (EJS Render) of the course player.
    *   **Note**: Internally transforms S3 URLs to CloudFront HLS URLs (`.m3u8`) for video content.

## A.3. User Profile & Dashboard

### **1. Update Payment Method**
*   **Endpoint**: `POST /user/update/payment-method`
*   **Request Body**:
    ```json
    {
        "method": "upi",
        "details": { "upiId": "user@upi" }
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
        "success": true,
        "message": "Payment method updated successfully"
    }
    ```

### **2. Withdrawal Request**
*   **Endpoint**: `POST /user/withdrawal`
*   **Request Body**:
    ```json
    { "amount": 500 }
    ```
*   **Success Response (200 OK)**:
    ```json
    { "success": true, "message": "Withdrawal request sent successfully" }
    ```

# Appendix B: Dependency Graph

This section details the purpose of every production dependency listed in `package.json`.

| Package | Version | Purpose |
| :--- | :--- | :--- |
| `@aws-sdk/client-mediaconvert` | `^3.888.0` | Interacts with AWS MediaConvert to trigger video transcoding jobs. |
| `@aws-sdk/client-s3` | `^3.896.0` | Core AWS SDK for S3 object storage operations (upload, delete). |
| `@aws-sdk/client-ses` | `^3.883.0` | Sends transactional emails via AWS Simple Email Service (SES). |
| `@aws-sdk/client-sqs` | `^3.888.0` | Manages Simple Queue Service (SQS) for asynchronous video processing tasks. |
| `@aws-sdk/cloudfront-signer` | `^3.916.0` | Generates signed URLs/Cookies for private CloudFront content. |
| `@aws-sdk/s3-request-presigner` | `^3.896.0` | Generates presigned URLs for direct client-to-S3 uploads. |
| `@supabase/supabase-js` | `^2.50.0` | Client for Supabase (likely used for legacy or auxiliary DB features). |
| `aws-cloudfront-sign` | `^3.0.2` | Alternative library for signing CloudFront URLs. |
| `aws-sdk` | `^2.1692.0` | Legacy AWS SDK (v2), likely kept for compatibility with older modules. |
| `axios` | `^1.9.0` | Promise-based HTTP client for making external API requests. |
| `bcrypt` | `^6.0.0` | Library for hashing and salting user passwords. |
| `cookie-parser` | `^1.4.7` | Middleware to parse `Cookie` header and populate `req.cookies`. |
| `cors` | `^2.8.5` | Middleware to enable Cross-Origin Resource Sharing. |
| `crypto` | `^1.0.1` | Node.js native crypto module (often polyfilled or explicitly required). |
| `dayjs` | `^1.11.13` | Lightweight date manipulation library (alternative to Moment.js). |
| `dotenv` | `^16.5.0` | Loads environment variables from `.env` file. |
| `ejs` | `^3.1.10` | Embedded JavaScript templating engine for server-side rendering. |
| `express` | `^5.1.0` | The web framework for Node.js. |
| `express-rate-limit` | `^8.1.0` | Middleware to limit repeated requests to public APIs. |
| `express-session` | `^1.18.2` | Simple session middleware for Express. |
| `firebase` | `^12.4.0` | Firebase client SDK. |
| `firebase-admin` | `^13.5.0` | Firebase Admin SDK for server-side operations (FCM, Auth). |
| `helmet` | `^8.1.0` | Security middleware that sets various HTTP headers. |
| `jsonwebtoken` | `^9.0.2` | Implementation of JSON Web Tokens (JWT) for stateless auth. |
| `mime-types` | `^3.0.1` | Utility to get MIME types from file extensions. |
| `mongoose` | `^8.18.0` | MongoDB object modeling tool designed to work in an asynchronous environment. |
| `multer` | `^1.4.4` | Middleware for handling `multipart/form-data` (file uploads). |
| `multer-s3` | `^3.0.1` | Streaming multer storage engine for AWS S3. |
| `node-cache` | `^5.1.2` | Simple in-memory caching module. |
| `node-cron` | `^4.2.1` | Task scheduler for Node.js (used for cleanup bots). |
| `node-fetch` | `^3.3.2` | A light-weight module that brings `window.fetch` to Node.js. |
| `nodemailer` | `^7.0.6` | Module to send emails (used with SES or SMTP). |
| `passport` | `^0.7.0` | Authentication middleware for Node.js. |
| `passport-facebook` | `^3.0.0` | Facebook authentication strategy for Passport. |
| `passport-google-oauth20` | `^2.0.0` | Google OAuth 2.0 strategy for Passport. |
| `razorpay` | `^2.9.6` | Official Razorpay Node.js SDK for payments. |
 * routes for managing files, admin dashboard, notifications, and error handling.
 */

const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const Order = require("./models/Order");
const { fileroute } = require("./fileupload.js");

const { authRouter } = require("./routes/authentication/googleAuth");
const fs = require("fs");
const Message = require("./models/message");
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const dayjs = require("dayjs");
const bcrypt = require("bcrypt");
const mime = require("mime-types");
const axios = require("axios");
const http=require('http');
const NodeCache = require("node-cache");
const categories = require("./models/categories");
const { createClient } = require("@supabase/supabase-js");
const Location = require("./models/userlocation");
const chatRoutes = require("./routes/chat.js");
const File = require("./models/file");
const courseRoutes = require("./routes/courseroutes");
const progressRoutes = require("./routes/progressroutes");
const authenticateJWT_user = require("./routes/authentication/jwtAuth.js");
const User = require("./models/userData");
const UserDownloads = require("./models/userDownloads.js");
const Userpurchases = require("./models/userPerchase.js");
const requireAuth = require("./routes/authentication/reaquireAuth.js");
const Usernotifications = require("./models/userNotifications");
const CF_DOMAIN = "https://d3tonh6o5ach9f.cloudfront.net";
const Usertransaction = require("./models/userTransactions.js");
const UserChats = require('./testings4.js');
const Coupon=require("./models/couponschema.js");
const WebSocket = require('ws');
const admin = require('firebase-admin');
const UserMessage = require('./models/UserMessage.js');
const userbal=require("./models/userBalance.js");
const pushNotificationroute = require('./pushNotification.js');
const serviceAccount = require('./serviceAccountKey.json');
const sendNotification=require("./test.js")
const Course=require("./models/course.js")

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const app = express();
app.use(cookieParser());

app.use("/",UserChats);

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();

// Helper function to broadcast a message to a user if they are online
function notifyUser(userId, payload) {
  const userSocket = clients.get(String(userId));
  if (userSocket && userSocket.readyState === WebSocket.OPEN) {
    userSocket.send(JSON.stringify(payload));
  }
}

wss.on('connection', (ws) => {
    let userId;

    const broadcastStatus = (targetUserId, isOnline) => {
        const statusPayload = JSON.stringify({
            type: 'user_status_update',
            userId: targetUserId,
            isOnline: isOnline
        });
        clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(statusPayload);
            }
        });
    };

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type !== 'register' && !userId) {
                return console.error("Message received from unregistered client.");
            }

            switch (data.type) {
                case 'register':
                    userId = String(data.userId);
                    clients.set(userId, ws);
                    broadcastStatus(userId, true);
                    const recipientId = String(data.recipientId);
                    if (clients.has(recipientId)) {
                        const statusPayload = {
                            type: 'user_status_update',
                            userId: recipientId,
                            isOnline: true
                        };
                        ws.send(JSON.stringify(statusPayload));
                    }
                    break;

                case 'private_message':
                case 'reply_message':
                case 'product_message': {
                    const { id, recipientId, text, repliedTo, productInfo, createdAt } = data;
                    const conversationId = [userId, recipientId].sort().join('--');
                    const isProduct = data.type === 'product_message';
                    
                    const senderProfile = await User.findById(userId).select('username profilePicUrl isVerified');

                    const messageDoc = new UserMessage({
                        id,
                        conversationId,
                        senderId: userId,
                        recipientId,
                        text: isProduct ? `Shared product: ${productInfo.name}` : text,
                        repliedTo: repliedTo || null,
                        productInfo: productInfo || null,
                        createdAt,
                        status: clients.has(String(recipientId)) ? 'delivered' : 'sent', 
                    });
                    await messageDoc.save();

                    const fullMessagePayload = { 
                        ...messageDoc.toObject(), 
                        type: data.type,
                        partner: {
                            _id: userId,
                            username: senderProfile.username,
                            profilePicUrl: senderProfile.profilePicUrl,
                            isVerified: senderProfile.isVerified
                        }
                    };
                    notifyUser(recipientId, fullMessagePayload);

                    if (messageDoc.status === 'delivered') {
                        notifyUser(userId, { type: 'message_status_update', messageId: id, status: 'delivered' });
                    }
                    break;
                }
                // ... (Other cases omitted for brevity)
            }
        } catch (err) {
            console.error("❌ Failed to process message:", err);
        }
    });

    ws.on('close', () => {
        if (userId) {
            clients.delete(String(userId));
            broadcastStatus(userId, false);
        }
    });
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const cors = require("cors");
app.use(cors());

app.use("/api/courses", courseRoutes);
app.use("/api/progress", progressRoutes);
app.use(authRouter);
app.use(fileroute);
app.use(pushNotificationroute);

// ... (Rest of the server configuration)

mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

## C.2. Multipart Upload Logic (`fileupload.js`)

```javascript
const {
    S3Client,
    CreateMultipartUploadCommand,
    UploadPartCommand,
    CompleteMultipartUploadCommand,
    AbortMultipartUploadCommand
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const express = require('express');
const router = express.Router();
const File = require("./models/file");

const s3Client = new S3Client({
    region: process.env.AWS_REGION || 'ap-south-1',
    useAccelerateEndpoint: false
});

router.post('/start-multipart-upload', async (req, res) => {
    const { fileName, contentType, fileType, fileId } = req.body;
    // ... Validation logic ...
    try {
        const command = new CreateMultipartUploadCommand({
            Bucket: process.env.S3_MAIN_FILE_BUCKET,
            Key: `main-files/${fileName}`,
            ContentType: contentType,
        });
        const { UploadId } = await s3Client.send(command);
        res.json({ uploadId: UploadId, key: `main-files/${fileName}` });
    } catch (err) {
        res.status(500).json({ error: 'Could not initiate multipart upload.' });
    }
});

router.get('/get-presigned-part-url', async (req, res) => {
    const { key, uploadId, partNumber } = req.query;
    const command = new UploadPartCommand({
        Bucket: process.env.S3_MAIN_FILE_BUCKET,
        Key: key,
        UploadId: uploadId,
        PartNumber: parseInt(partNumber, 10),
    });
    try {
        const url = await getSignedUrl(s3Client, command, { expiresIn: 21600 });
        res.json({ url });
    } catch (err) {
        res.status(500).json({ error: 'Could not get presigned URL.' });
    }
});

router.post('/complete-multipart-upload', async (req, res) => {
    const { key, uploadId, parts, fileId } = req.body;
    const sortedParts = [...parts].sort((a, b) => a.PartNumber - b.PartNumber);
    const command = new CompleteMultipartUploadCommand({
        Bucket: process.env.S3_MAIN_FILE_BUCKET,
        Key: key,
        UploadId: uploadId,
        MultipartUpload: { Parts: sortedParts },
    });
    try {
        await s3Client.send(command);
        await File.findByIdAndUpdate(fileId, { fileUrl: key });
        res.json({ message: 'Upload completed successfully!' });
    } catch (err) {
        res.status(500).json({ error: 'Could not complete multipart upload.' });
    }
});

module.exports = { fileroute: router };
```

# Appendix D: Complete Database Schema Reference

This appendix provides the full Mongoose schema definitions for all data models used in the application.

## D.1. User Message (`models/UserMessage.js`)
Stores chat messages between users, including text, file attachments, and product shares.

```javascript
const mongoose = require('mongoose');

const userMessageSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true }, // Client-side ID
    conversationId: { type: String, required: true, index: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, default: 'private_message' },
    text: { type: String },
    fileUrl: { type: String },
    productInfo: {
        productId: String,
        name: String,
        price: String,
        imageUrl: String,
        slug: String
    },
    repliedTo: {
        senderName: String,
        text: String
    },
    status: {
        type: String,
        enum: ['sent', 'delivered', 'read'],
        default: 'sent'
    },
    isEdited: { type: Boolean, default: false },
    isDeleted: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('UserMessage', userMessageSchema);
```

## D.2. Order (`models/Order.js`)
Tracks customer orders and payment status.

```javascript
const mongoose = require("mongoose");

const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  quantity: { type: Number, required: true },
  price: { type: Number, required: true }
});

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  transactionId: { type: String, required: true, unique: true },
  dateTime: { type: Date, default: Date.now },
  customer: { type: String, required: true },
  payment: { type: String, required: true },
  total: { type: Number, required: true },
  items: [itemSchema],
  productId: { type:String, required: true },
  productName:{type:String,required:true},
  status: { 
    type: String, 
    enum: ["Successfull","unsuccessfull", "Pending"], 
    default: "Pending" 
  }
});

module.exports = mongoose.model("Order", orderSchema);
```

## D.3. User Transaction (`models/userTransactions.js`)
Records successful transactions for revenue calculation.

```javascript
const mongoose=require("mongoose");
const userTran=new mongoose.Schema({
    ProductName:{type:String,required:true},
    ProductId:{type:String,required:true},
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true},
    status:{type:String,required:true,default:"Completed"},
    totalAmount:{type:Number,required:true},
    discount:{type:Number,default:0},
    transactionId:{type:String,required:true},
    purchaserId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true}
},{ timestamps: true });
module.exports=mongoose.model("UserTransaction",userTran);
```

## D.4. User Withdrawal (`models/userWithdrawels.js`)
Manages payout requests from sellers.

```javascript
const mongoose=require("mongoose");
const WithDraw=new mongoose.Schema({
    totalAmount:{type:Number,required:true,min:100},
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true},
    status:{type:String,default:"pending",enum:["pending","success","failed"]},
    transactionId:{type:String,required:true},
    createdAt:{type:Date,default:Date.now}
})
module.exports=mongoose.model("WithDraw",WithDraw);
```

## D.5. User Balance (`models/userBalance.js`)
Tracks the current wallet balance of a user.

```javascript
const mongoose=require("mongoose");
const UserBal=new mongoose.Schema({
    UserId:{type:String,required:true,unique:true},
    Balance:{type:Number,default:0},
    prevBal:{type:Number,default:0},
},{timestamps:true})
module.exports = mongoose.models.UserBal || mongoose.model("UserBal", UserBal);
```

## D.6. User Purchase (`models/userPerchase.js`)
Detailed record of items purchased by a user.

```javascript
const mongoose = require("mongoose");

const userPurchaseSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  productName: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true, default: 1 },
  totalPrice: { type: Number, required: true },
  productType: { type: String },
  status: { type: String, enum: ["completed", "pending", "refunded"], default: "completed" },
  purchaseDate: { type: Date, default: Date.now },
   purchaseId: { type: String },
}, { timestamps: true });

module.exports = mongoose.model("UserPurchase", userPurchaseSchema);
```

## D.7. User Download (`models/userDownloads.js`)
Tracks file downloads to prevent unauthorized access and count download stats.

```javascript
const mongoose = require("mongoose");

const userdownloadsSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    filename: { type: String, required: true },
    fileId: { type: String, required: true },
    fileUrl: { type: String, required: true },
    fileType: { type: String, required: true },
  },
  { timestamps: true }
);

userdownloadsSchema.index({ userId: 1, fileId: 1 }, { unique: true });

module.exports = mongoose.model("UserDownload", userdownloadsSchema);
```

## D.8. Coupon (`models/couponschema.js`)
Manages discount codes for files.

```javascript
const mongoose=require('mongoose')
const couponSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},
  code: String,
  file: { type: mongoose.Schema.Types.ObjectId, ref: "File" },
  discountValue: Number,
  expiry: Date
});
module.exports=mongoose.model('Coupon', couponSchema);
```

## D.9. Category (`models/categories.js`)
Defines product categories.

```javascript
const mongoose = require("mongoose");

const category = new mongoose.Schema({
  name: { type: String, required: true,unique: true },
});
const categories = mongoose.model("category", category);
module.exports = categories;
```

## D.10. Visitor Location (`models/userlocation.js`)
Stores visitor IP and location data for analytics.

```javascript
const mongoose = require('mongoose');

const visitorSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  city: String,
  region: String,
  country: String,
  postal_code: String,
  latitude: Number,
  longitude: Number,
  full_address: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Visitor', visitorSchema);
```

# Appendix E: Frontend Template Analysis

This appendix analyzes key EJS templates to explain how the server-side data is rendered and how client-side interactivity is handled.

## E.1. Landing Page (`views/landing.ejs`)

The landing page serves as the entry point, showcasing the platform's value proposition and popular content.

### **1. Data Context**
The server passes the following variables to this template:
*   `popularFiles`: An array of file objects to display in the "Popular This Week" section. Each object contains:
    *   `previewUrl`: URL for the thumbnail image.
    *   `filename`: Name of the file.
    *   `user`: Username of the creator.
    *   `downloadCount`: Number of times downloaded.
    *   `price`: Cost of the file.

### **2. Key UI Components**
*   **Animated Gradient Background**: A CSS animation (`vidyari-landing-99-animated-gradient`) creates a dynamic, shifting background using the brand colors (Pink, Green, Yellow, Blue).
*   **Chunky UI Elements**: The design uses a "Retro-Brutalist" aesthetic with thick black borders, heavy box shadows (`box-shadow: 6px 6px 0 var(--color-black)`), and bold typography (`Montserrat`).
*   **Scroll Animations**: An `IntersectionObserver` triggers a "fade-in" effect for elements as they scroll into view (`data-animation="fade-in"`).

### **3. Client-Side Logic**
*   **FAQ Accordion**: Simple JavaScript toggles the `active` class on FAQ items to expand/collapse answers.
*   **Intersection Observer**: Monitors elements with `data-animation="fade-in"` and adds the `visible` class when they enter the viewport.

## E.2. Creator Dashboard (`views/createcourse.ejs`)

This is a complex, single-page-application (SPA) style interface for creators to manage their content and earnings.

### **1. Data Context**
*   `profileUrl`: URL of the logged-in user's profile picture.
*   `transactions`: Array of transaction objects for the "Revenue Analytics" chart and table.
*   `files`: Array of uploaded files for the "Uploaded Documents" grid.
*   `Ubalance`: Current user balance for the payout section.
*   `userwithreq`: Array of past withdrawal requests.
*   `payouts`: Array of completed payouts.
*   `upiId`: User's saved UPI ID for payments.

### **2. Key UI Components**
*   **Sidebar Navigation**: A responsive sidebar that toggles on mobile. It uses `data-target` attributes to switch between content sections (e.g., `upload-file-section`, `transactions-section`) without page reloads.
*   **Revenue Chart**: A `Chart.js` line chart visualizing income over time. It supports filtering by "7 Days", "30 Days", and "Year".
*   **Data Tables**: Custom-styled tables for transactions and payouts with status pills (Completed, Pending, Failed).
*   **Modals**: A reusable `universal-modal` for actions like editing files or confirming withdrawals.

### **3. Client-Side Logic**
*   **SPA Navigation**:
    ```javascript
    mainNav.addEventListener('click', (e) => {
        // Hides all sections and shows the target section based on data-target
        // Triggers specific initialization logic (e.g., renderRevenueChart) when specific tabs are opened
    });
    ```
*   **Chart Rendering**: The `renderRevenueChart` function processes the `transactionsData` (injected via EJS) to aggregate daily/monthly revenue and updates the canvas.
*   **Dynamic Search**: The transaction table includes a client-side search input that filters rows based on text content.

---
 **End of Documentation**











