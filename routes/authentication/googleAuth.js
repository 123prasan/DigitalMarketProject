const express = require("express");
const passport = require("passport");
const session = require("express-session");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet"); // Import helmet to configure it explicitly
const mongoose = require("mongoose");
const User = require("../../models/userData");
const router = express.Router();
const bcrypt = require("bcrypt");
const EmailVerify = require("../../emails/templates/auth/emailVerification");
const PassReset = require("../../emails/templates/auth/passwordReset");
const authenticateJWT_user = require("./jwtAuth");
const Course = require("../../models/course");
// const userdownloads = require("../../models/userDownloads");
const reaquireAuth = require("./reaquireAuth.js");
const Notification = require("../../models/userNotifications");
const File = require("../../models/file.js");
const UserDownloads = require("../../models/userDownloads");
const Report = require("../../models/userReports");

router.use(express.json());
router.use(cookieParser());

// ----- Rate Limiter -----
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, try again later.",
});
router.use("/auth/", limiter);

// ----- MongoDB Schemas -----

const log_activiesSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  last_logged_in: [{ date: { type: Date, default: Date.now } }],
  last_logged_out: [{ date: { type: Date } }],
});

const log_activities = mongoose.model("LogActivities", log_activiesSchema);

// ----- Session Middleware (optional) -----
router.use(
  session({
    secret: "supersecret", // hardcoded
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// ----- Initialize Passport -----
router.use(passport.initialize());
router.use(passport.session());
console.log(process.env.GOOGLE_CLIENT_ID);
console.log(process.env.GOOGLE_CLIENT_SECRET);
console.log(process.env.GOOGLE_CALLBACK_URL);
// ----- Passport Google OAuth -----
passport.use(
  new GoogleStrategy(
    {
      clientID: `999822886943-57g7g478kmkq4aqebukvlei2mijppqof.apps.googleusercontent.com`,
      clientSecret: `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`,
      callbackURL: `http://localhost:8000/auth/google/callback`,
      state: true,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails[0].value,
            profilePicUrl: profile.photos[0].value,
            isEmailVerified: true,
          });
        }
        await log_activities.create({
          userId: user._id,
          last_logged_in: [{ date: new Date() }],
        });
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// ----- Passport Facebook OAuth (NEW) -----
passport.use(
  new FacebookStrategy(
    {
      // You MUST replace these with your actual Facebook App ID and App Secret
      clientID: "YOUR_FACEBOOK_APP_ID",
      clientSecret: "YOUR_FACEBOOK_APP_SECRET",
      callbackURL: "http://localhost:3000/auth/facebook/callback",
      profileFields: ["id", "displayName", "photos", "emails"], // Requesting user data
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ facebookId: profile.id });
        if (!user) {
          user = await User.create({
            facebookId: profile.id,
            name: profile.displayName,
            // Check if emails exist before accessing the first one
            email:
              profile.emails && profile.emails.length > 0
                ? profile.emails[0].value
                : null,
            photo:
              profile.photos && profile.photos.length > 0
                ? profile.photos[0].value
                : null,
          });
        }
        await log_activities.create({
          userId: user._id,
          last_logged_in: [{ date: new Date() }],
        });
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// // ----- Middleware to protect routes -----
// const authenticateJWT_user = async (req, res, next) => {
//     try {
//         const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
//         if (!token) return res.redirect("/");

//         const payload = jwt.verify(token, '3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2');
//         req.user = await User.findById(payload.userId);
//         if (!req.user) return res.redirect("/");

//         next();
//     } catch (err) {
//         res.redirect("/");
//     }
// };

// ----- Routes -----
// router.get('/login', (req, res) => res.render('login2'));

router.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  async (req, res) => {
    const user = req.user;

    if (user.twoFAEnabled) {
      const tempToken = jwt.sign(
        { userId: user.id },
        "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
        { expiresIn: "5m" }
      );

      // Redirect to a 2FA verification page with the temporary token
      // The frontend should read this URL parameter and handle the verification
      return res.redirect(`/verify-2fa?token=${tempToken}`);
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
      { expiresIn: "7d" }
    );

    // Set the JWT as a cookie before redirecting
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Redirect the user to the dashboard or home page after successful login
    console.log("callback recieved");
    res.redirect("/");
  }
);

// ----- Facebook Auth Routes (NEW) -----
router.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email", "public_profile"] }) // Requesting email and public profile
);

router.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  async (req, res) => {
    const user = req.user;

    if (user.twoFAEnabled) {
      const tempToken = jwt.sign(
        { userId: user.id },
        "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
        { expiresIn: "5m" }
      );
      return res.json({ message: "2FA required", tempToken });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
      { expiresIn: "7d" }
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        photo: user.photo,
      },
    });
  }
);

router.post("/verify-2fa", async (req, res) => {
  const { token, code } = req.body;
  try {
    const payload = jwt.verify(
      token,
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2"
    );
    const user = await User.findById(payload.userId);
    const verified = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: "base32",
      token: code,
    });
    if (!verified) return res.status(401).json({ message: "Invalid 2FA code" });

    const jwtToken = jwt.sign(
      { userId: user.id, email: user.email },
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
      { expiresIn: "7d" }
    );
    res.cookie("token", jwtToken, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({ message: "Login successful", token: jwtToken });
  } catch (err) {
    res.status(400).json({ message: "Invalid or expired token" });
  }
});
const UserTransactions = require("../../models/userTransactions.js");
const Payouts = require("../../models/userWithdrawels.js");
router.get(
  "/dashboard",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    const latestCourse = await Course.findOne().sort({ _id: -1 });
    console.log("Latest course ID:", latestCourse._id);
    const userTransactions = await UserTransactions.find({
      userId: req.user._id,
    });
    console.log(userTransactions);
    // const reports= await Report.find({userId:req.user._id})
    const payouts = await Payouts.find({ userId: req.user._id });
    const files = await File.find({ userId: req.user._id });

    const courses = await Course.find();
    let user = null;

    if (req.user) {
      const userId = req.user._id;
      // Fetch only the necessary fields
      user = await User.findById(userId).select("profilePicUrl username email");
      if (user) {
        console.log("User profile pic URL:", user.profilePicUrl);
      }
    }
    res.render("createcourse", {
      transactions: userTransactions,
      payouts,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      files,
    });
  }
);
const paymentMethod = require("../../models/userPayout.js");
const withdrawelReq = require("../../models/admin/withdrawelRequests.js");
router.post(
  "/user/withdrawel",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    try {
      const paymentmethod = await paymentMethod.findOne({
        userId: req.user._id,
      });

      const withdrawelRequests = new withdrawelReq({
        userId: req.user._id,
        Amount: amount,
        paymentWay: paymentmethod.upi,
      });
      await withdrawelRequests.save();
      res.status(200).message("withdrawel request sent successfully");
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);
function isValidUpi(upi) {
  const upiRegex = /^[\w.-]{2,}@[a-zA-Z]{2,64}$/;
  return upiRegex.test(upi);
}

router.post(
  "/user/update/payment-method",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    try {
      const { upi } = req.body;

      if (!upi || !isValidUpi(upi)) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid UPI ID" });
      }

      const paymentmethod = await paymentMethod.findOneAndUpdate(
        { userId: req.user._id, type: "upi" },
        {
          $set: {
            upi,
            name: req.user.username,
            type: "upi",
            isDefault: true,
            status: "active",
          },
        },
        { upsert: true, new: true }
      );

      return res.status(200).json({
        success: true,
        message: "Payment method updated successfully",
        paymentmethod,
      });
    } catch (err) {
      console.error("Error updating payment method:", err);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

router.get("/viewprofile/:username", async (req, res) => {
  const username = req.params.username;
  const user = await User.findOne({ username: username });
  if (!user) {
    res.render("profileNotfound.ejs");
  }
  res.render("publicprofile.ejs");
});

router.get(
  "/downloads",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    try {
      // 1. Get the logged-in user's ID
      const userId = req.user._id;

      // 2. Fetch all download records for that user from the database
      const userDownloads = await UserDownloads.find({ userId: userId }).sort({
        createdAt: -1,
      });
      let user = null;

      if (req.user) {
        const userId = req.user._id;
        // Fetch only the necessary fields
        user = await User.findById(userId).select(
          "profilePicUrl username email"
        );
        if (user) {
          console.log("User profile pic URL:", user.profilePicUrl);
        }
      }
      // const downloads = await userdownloads.find({ userId: req.user._id });

      // res.render("mydownloads.ejs", {  downloads });
      // 3. Render the EJS view, passing the downloads data to it
      res.render("mydownloads", {
        isLoggedin: !!req.user,
        pageTitle: "My Downloads",
        downloads: userDownloads,
        isLoggedin: !!req.user,
        profileUrl: user?.profilePicUrl || null,
        username: user?.username || null,
        useremail: user?.email || null, // This 'downloads' variable will be available in downloads.ejs
      });
    } catch (error) {
      console.error("Error fetching user downloads:", error);
      // Render an error page or redirect
      res.status(500).send("Sorry, something went wrong.");
    }
  }
);
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  if (req.session)
    req.session.destroy((err) => {
      if (err) console.log(err);
    });
  res.redirect("/user-login");
});
router.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2", // replace with your real secret
      { expiresIn: "7d" }
    );

    // Set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // true in production (HTTPS)
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Send response
    if (!user.isEmailVerified) {
      return res
        .status(401)
        .json({ message: "Email not verified Please verify your email" });
    }
    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        email: user.email,
        username: user.username, // consistent with signup response
      },
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Error logging in", error: err.message });
  }
});
router.post("/auth/signup", async (req, res) => {
  try {
    const { email, password, username } = req.body;

    // Check for email
    if (await User.findOne({ email })) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Optional: auto-generate unique username
    let finalUsername = username;
    // while (await User.findOne({ username: finalUsername })) {
    //   finalUsername = `${username}_${Math.floor(Math.random()*10000)}`;
    // }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      passwordHash: hashedPassword,
      username: finalUsername,
    });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
      { expiresIn: "7d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //email verification token
    const verificationToken = jwt.sign(
      { userId: user._id, email: email },
      "email-d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2",
      { expiresIn: "1d" }
    );

    const verifi_link = `https://vidyari.com/auth/verify-email?token=${verificationToken}`;
    await EmailVerify(email, "verify user account", finalUsername, verifi_link);
    res.json({
      message: "Verification Link Sent Please Check Your Email",
      token,
      user: { id: user._id, email: user.email, username: finalUsername },
    });
  } catch (err) {
    if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
      res.status(400).json({ message: "Username already taken" });
    } else {
      res.status(500).json({ message: "Server error", error: err.message });
    }
  }
});

router.get("/auth/verify-email", async (req, res) => {
  const token = req.query.token;

  if (!token) return res.status(400).send("Invalid or missing token");

  try {
    const payload = jwt.verify(
      token,
      "email-d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2"
    );

    // Mark user as verified
    const user = await User.findByIdAndUpdate(payload.userId, {
      isEmailVerified: true,
    });

    res.render("emailVerified.ejs", { email: user.email });
  } catch (err) {
    console.log(err);
    res.status(400).send("Token expired or invalid");
  }
});

router.post("/check/username", async (req, res) => {
  try {
    // let usersData=await User.find({username})
    let exists = await User.findOne({
      username: new RegExp("^" + req.body.username + "$", "i"),
    });

    if (exists) {
      res.json({ exists: true });
    } else {
      res.json({ exists: false });
    }
  } catch (err) {
    console.log(err);
    res
      .status(500)
      .json({ message: "Error checking username", error: err.message });
  }
});

router.post("/auth/forgot-pass", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ message: "No account found with this email." });
    }

    if (!user.isEmailVerified) {
      return res.status(400).json({
        message: "Please verify your email before resetting password.",
      });
    }

    // Generate reset token (valid for 1 hour)
    const resetToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || "supersecret",
      { expiresIn: "1h" }
    );

    // Reset link
    const resetLink = `https://yourdomain.com/reset-password/${resetToken}`;

    // Send password reset email
    await PassReset(
      user.email,
      "Password Reset Request",
      user.username,
      resetLink
    );

    res.status(200).json({ message: "Password reset email sent successfully" });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/reset-password/:token", (req, res) => {
  res.render("resetpass.ejs");
});

router.post("/auth/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long." });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || "supersecret");
    } catch (err) {
      return res
        .status(400)
        .json({ message: "Invalid or expired reset link." });
    }

    // Find user by ID
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ message: "User not found." });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save new password
    user.passwordHash = hashedPassword;
    await user.save();

    res.status(200).json({
      message:
        "Password reset successful. You can now log in with your new password.",
    });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

//endpoint to view user profile
router.get(
  "/user-profile",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    let user = null;
    if (req.user) {
      const userId = req.user._id;
      // Fetch only the necessary fields
      user = await User.findById(userId).select("profilePicUrl username email");
      if (user) {
        console.log("User profile pic URL:", user.profilePicUrl);
      }
    }

    const userData = await User.findById(req.user._id);
    const hasPassword = !!user.password;
    const files = await File.find({ userId: user._id });
    const numsOfDocs = files.length;
    const numOfCourses = 0; // For now only

    // console.log("userData",userData)
    res.render("myprofile.ejs", {
      numsOfDocs,
      numOfCourses,
      userData: userData,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      hasPassword: hasPassword,
    });
  }
);

// const express = require('express');
require("dotenv").config();
const multer = require("multer");
const multerS3 = require("multer-s3");
const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");
const userTransactions = require("../../models/userTransactions.js");
// const bcrypt = require('bcrypt');
// const User = require('../../models/UserData'); // Adjust path to your User model
// const { authenticateJWT_user } = require('..'); // Import your JWT middleware
// authenticateJWT_user
// const router = express.Router();

// --- S3 and Multer Configuration ---
const s3 = new S3Client({
  region: process.env.AWS_S3_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const s3Storage = multerS3({
  s3: s3,
  bucket: process.env.AWS_S3_BUCKET_NAME,
  acl: "public-read",
  key: function (req, file, cb) {
    // Create a unique filename using the user's ID from req.user
    const fileName = `avatars/avatar-${req.user._id
      }-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, fileName);
  },
});

const upload = multer({ storage: s3Storage });

// --- User Detail Update Route ---
router.post(
  "/update/user-detail",
  authenticateJWT_user,
  upload.single("profilepic"),
  async (req, res) => {
    try {
      const userId = req.user._id; // Get user ID from the JWT middleware
      const updateData = {};

      // Collect text fields from the request body
      if (req.body.fullname) updateData.fullname = req.body.fullname;
      if (req.body.bio) updateData.bio = req.body.bio;
      if (req.body.dob) updateData.DOB = req.body.dob;
      if (req.body.githubUrl) updateData.githubUrl = req.body.githubUrl;
      if (req.body.instagramUrl)
        updateData.instagramUrl = req.body.instagramUrl;

      // If a new file was uploaded, get its S3 URL
      let newProfilePicUrl = null;
      if (req.file) {
        updateData.profilepicUrl = req.file.location;
        newProfilePicUrl = req.file.location;
      }

      const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
        new: true,
      });

      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      console.log("updated");
      res.status(200).json({
        message: "Profile updated successfully!",
        newProfilePicUrl: newProfilePicUrl,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error while updating profile." });
    }
  }
);

// --- Password Update Route ---
router.post("/update/user-password", authenticateJWT_user, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id; // Get user ID from the JWT middleware

    const user = await User.findById(userId).select("+password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect current password." });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.status(200).json({ message: "Password updated successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error while updating password." });
  }
});

router.get(
  "/user-notifications",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    try {
      // Fetch notifications for the logged-in user, sorted by most recent
      const notifications = await Notification.find({ userId: req.user._id })
        .sort({ createdAt: -1 })
        .limit(20); // Limit to recent 20 for performance

      // Count only the unread notifications
      const unreadCount = await Notification.countDocuments({
        userId: req.user._id,
        isRead: false,
      });

      // Example of creating a dynamic message with a link
      // You would do this when you create the notification
      // let message = `<strong>@eleanor_mac</strong> commented on your post <strong>"Abstract Art Vol. 3"</strong>`;
      let user = null;

      if (req.user) {
        const userId = req.user._id;
        // Fetch only the necessary fields
        user = await User.findById(userId).select(
          "profilePicUrl username email"
        );
        if (user) {
          console.log("User profile pic URL:", user.profilePicUrl);
        }
      }
      res.render("notifications", {
        isLoggedin: !!req.user,
        notifications: notifications,
        unreadCount: unreadCount,
      });
    } catch (error) {
      console.error(error);
      res.status(500).send("Server Error");
    }
  }
);

// Add this to your backend routes file (e.g., routes/updateRoutes.js)

// const Notification = require('../models/Notification'); // Make sure path is correct
// const { authenticateJWT_user } = require('../middleware/auth'); // Your JWT middleware

// ... your other routes

/**
 * @route   POST /notifications/:id/mark-as-read
 * @desc    Marks a specific notification as read
 * @access  Private
 */
router.post(
  "/notifications/:id/mark-as-read",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    try {
      const notificationId = req.params.id;
      const userId = req.user._id;

      // Find the specific notification that belongs to the logged-in user and update it.
      // This prevents one user from marking another user's notifications as read.
      const notification = await Notification.findOneAndUpdate(
        { _id: notificationId, userId: userId },
        { isRead: true },
        { new: true } // optional: returns the updated document
      );

      if (!notification) {
        // If no notification was found or updated, it either doesn't exist
        // or doesn't belong to this user.
        return res.status(404).json({ message: "Notification not found" });
      }
      console.log("notification marked as read");
      res.status(200).json({ message: "Notification marked as read" });
    } catch (error) {
      console.error("Error marking notification as read:", error);
      res.status(500).json({ message: "Server Error" });
    }
  }
);

// router.get("/reportfile", async (req, res) => {
//   const file = await File.findById("68482f3b587c63be6321bfc6");
//   res.render("reporttemplate.ejs", { file: file });
// });
router.post("/report", authenticateJWT_user, reaquireAuth, async (req, res) => {
  try {
    console.log("req praram:", req.query.file_id, "req body", req.body);
    const fileId = req.query.file_id;
    // console.log(typeof(fileId))
    const file = await File.findById(fileId);
    if (!file) {
      console.log("file not found");
      return res.status(404).json({ message: "file not found" });
    }
    const reporterid = req.user._id;
    const resporter = await User.findById(reporterid);
    if (!resporter) {
      console.log("reporter not found");
      return res.status(404).json({ message: "reporter not found" });
    }
    const user = await User.findById(file.userId);
    const filename = file.filename;
    if (!user) {
      console.log("user not found");
      return res.status(404).json({ message: "user not found" });
    }
    const notification = new Notification({
      userId: user._id,
      type: "report",
      message: `<strong>someone reported your file${filename}: ${req.body.reason} </strong>`,
      targetId: `${file._id}`,
    });
    await notification.save();
    const report = new Report({
      userId: user._id,
      reporterId: reporterid,
      productId: file._id,
      reason: req.body.reason,
    });
    await report.save();
    res.status(200).json({ message: "report sent" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "server error" });
  }
});
const CF_DOMAIN = "https://d3tonh6o5ach9f.cloudfront.net";

router.get("/profile/:username", authenticateJWT_user, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });

    // 1. Handle user not found case FIRST and exit immediately.
    if (!user) {
      return res.status(404).render("404.ejs"); // Or send a simple message
    }
    //  let user = null;

    // 2. Fetch the profile user's files and prepare them ONCE.
    const files = await File.find({ userId: user._id });
    const numsOfDocs = files.length;
    const numOfCourses = 0; // For now only

    const filesWithPreviews = files.map((file) => ({
      ...file.toObject(),
      previewUrl: `${CF_DOMAIN}/files-previews/images/${file._id}.${file.imageType || "jpg"
        }`,
      pdfUrl: `${CF_DOMAIN}/${file.fileUrl}`,
    }));

    let renderOptions = {
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      numsOfDocs,
      numOfCourses,
      files: filesWithPreviews,
      userData: user,
      follow: false, // Default value for own profile or logged-out users
      isFollowed: false, // Default value for other profiles or logged-out users
    };

    // 3. Check if a user is logged in to determine follow status.
    if (req.user) {
      // Check if the logged-in user is viewing their OWN profile
      if (user._id.toString() === req.user._id.toString()) {
        renderOptions.follow = false; // Or a flag indicating it's their own profile
      } else {
        // Check if the logged-in user follows the profile user
        renderOptions.isFollowed = user.followers.some(
          (id) => id.toString() === req.user._id.toString()
        );
      }
    }

    // 4. Render the page exactly ONCE with the final options.
    return res.render("publicprofile.ejs", renderOptions);
  } catch (error) {
    console.error("Error fetching profile:", error);
    return res.status(500).send("Something went wrong.");
  }
});
router.post(
  "/update/file-meta",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    const { id, filename, description, price, coupons } = req.body;

    try {
      // Build update object dynamically
      const updateData = {};
      if (filename) updateData.filename = filename;
      if (price !== undefined) updateData.price = price;
      if (description) updateData.description = description; // only if not empty
      if (coupons && coupons.length > 0) updateData.coupons = coupons; // only if array has items

      const updatedFile = await File.findByIdAndUpdate(
        id,
        { $set: updateData },
        { new: true }
      );

      if (!updatedFile) {
        return res.status(404).json({ message: "File not found" });
      }

      res.status(200).json({ success: true, file: updatedFile });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);
// const s3 = new AWS.S3({
//   accessKeyId: process.env.AWS_ACCESS_KEY,
//   secretAccessKey: process.env.AWS_SECRET_KEY,
//   region: process.env.AWS_REGION,
// });
// const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");
// const s3 = new S3Client({
//   region: "ap-south-1",
//   credentials: {
//     accessKeyId: process.env.AWS_ACCESS_KEY_ID,
//     secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
//   },
// });

router.delete(
  "/delete/file-meta",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    const { id } = req.body;

    try {
      // Find file in DB
      const file = await File.findById(id);
      if (!file) return res.status(404).json({ message: "File not found" });

      // Parameters for both buckets
      const mainBucketParams = {
        Bucket: "vidyarimain",
        Key: `main-files/${file.fileUrl}`,
      };

      const previewBucketParams = {
        Bucket: "vidyari2",
        Key: `files-previews/images/${file._id}`,
      };

      // Delete from both buckets
      await Promise.all([
        s3.send(new DeleteObjectCommand(mainBucketParams)),
        s3.send(new DeleteObjectCommand(previewBucketParams)),
      ]);

      // Delete from DB
      await File.findByIdAndDelete(id);

      res.status(200).json({ success: true, message: "File deleted from DB and S3" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  }
);


// module.exports = router;
// module.exports = router;
module.exports = { authRouter: router, authenticateJWT_user, User };
