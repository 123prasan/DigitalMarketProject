require("dotenv").config();
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
const paymentMethod = require("../../models/userPayout.js");
const validator = require("validator");
const xss = require("xss");
const Report = require("../../models/userReports");
const userbal=require("../../models/userBalance.js");

const CF_DOMAIN = "https://d3tonh6o5ach9f.cloudfront.net"; // e.g., https://d123abcd.cloudfront.net

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
      callbackURL: `https://www.vidyari.com/auth/google/callback`,
      state: true,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        let userWithEmail = await User.findOne({ email: profile.emails[0].value })
        if (!user && !userWithEmail) {
          let username = profile.displayName;
          let finalUsername = username;

          // Check if username already exists
          const existingUser = await User.findOne({ username: finalUsername });

          if (existingUser) {
            // Username exists, generate a unique one
            while (await User.findOne({ username: finalUsername })) {
              finalUsername = `${username}_${Math.floor(Math.random() * 10000)}`;
            }
          }

          user = await User.create({
            googleId: profile.id,
            username: finalUsername,
            email: profile.emails[0].value,
            profilePicUrl: profile.photos[0].value,
            isEmailVerified: true,
          });
        }
        if (userWithEmail && !user) {
          await User.findByIdAndUpdate(
            userWithEmail._id,       // pass the ID directly
            {
              googleId: profile.id,  // update field
            }
          );
        }



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
        process.env.JWT_SECRET_USER_LOGIN,
        { expiresIn: "5m" }
      );

      // Redirect to a 2FA verification page with the temporary token
      // The frontend should read this URL parameter and handle the verification
      return res.redirect(`/verify-2fa?token=${tempToken}`);
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET_USER_LOGIN,
      { expiresIn: "7d" }
    );

    // Set the JWT as a cookie before redirecting
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // HTTPS only in prod
      sameSite: "lax", // or "lax" if you need cross-site redirects (Google OAuth)
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      domain: process.env.NODE_ENV === "production" ? ".vidyari.com" : undefined, // allow across subdomains
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



    
    // const reports= await Report.find({userId:req.user._id})
    const payouts = await Payouts.find({ userId: req.user._id });
    const files = await File.find({ userId: req.user._id });

    let user = null;

    if (req.user) {
      const userId = req.user._id;
      // Fetch only the necessary fields
      user = await User.findById(userId).select("profilePicUrl username email");
      if (user) {
        console.log("User profile pic URL:", user.profilePicUrl);
      }
    }
    const userPaymentMethod = await paymentMethod.findOne({ userId: req.user._id });
    const userwithreq=await withdrawelReq.find({
      userId:req.user._id
    });
   
   const Ubalance=await userbal.findOne({
    UserId:req.user._id
   });
   console.log(userwithreq)
   console.log(Ubalance.Balance)
    res.render("createcourse", {
      upiId: userPaymentMethod ? userPaymentMethod.upi : null,
      transactions: userTransactions,
      payouts,
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      files,
      userwithreq,
      Ubalance:Ubalance.Balance
    });
  }
);

const withdrawelReq = require("../../models/admin/withdrawelRequests.js");
router.post(
  "/user/withdrawal",
  authenticateJWT_user,
  reaquireAuth,
  async (req, res) => {
    try {
      const paymentmethod = await paymentMethod.findOne({ userId: req.user._id });
      const amount = req.body.amount;
     
      if (!paymentmethod || !paymentmethod.upi) {
        return res
          .status(400)
          .json({ success: false, message: "No payment method found. Please set your payment method first." });
      }
      const Ubalance=await userbal.findOne({
        UserId:req.user._id
       });
      if(req.body.amount>Ubalance.Balance){
         return res.status(400).json({ success: false, message: "Insufficient Balance" });
      }
      const withdrawalRequest = new withdrawelReq({
        userId: req.user._id,
        Amount: amount,
        paymentway: paymentmethod.upi,
        status: "pending",
      });

      await withdrawalRequest.save();

      return res
        .status(200)
        .json({ success: true, message: "Withdrawal request sent successfully" });

    } catch (err) {
      console.error("Error while creating withdrawal request:", err);
      return res.status(500).json({ success: false, message: "Server error" });
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
      const { method, details } = req.body;
      const upi = method === "upi" ? details?.upiId : null;

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
      console.log("updated user payment method")
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
    let { email, password } = req.body;

    // Step 1: Basic validation
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Step 2: Sanitize and normalize input
    
email = xss(email.trim().toLowerCase());
     
    password = xss(password.trim());

    // Step 3: Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // Step 4: Check for JWT secret
    if (!process.env.JWT_SECRET_USER_LOGIN) {
      throw new Error("JWT secret not configured");
    }

    // Step 5: Find user by email
 const user = await User.findOne({ email: email });

   
    
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Step 6: Compare password hash
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Step 7: Check email verification
    if (!user.isEmailVerified) {
      return res.status(403).json({
        message: "Email not verified. Please verify your email to continue.",
      });
    } else {
      

      // Step 8: Generate JWT token
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        process.env.JWT_SECRET_USER_LOGIN,
        { expiresIn: "7d" }
      );

      // Step 9: Set secure cookie
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // only HTTPS in production
        sameSite: "strict", // prevents CSRF
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        domain: process.env.NODE_ENV === "production" ? ".vidyari.com" : undefined,
        path: "/",
      });

      // Step 10: Send response
      res.status(200).json({
        message: "Login successful",
        token,
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          role: user.role,
        },
      });
    }



  } catch (err) {
    console.error("Login error:", err);
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
    while (await User.findOne({ username: finalUsername })) {
      finalUsername = `${username}_${Math.floor(Math.random() * 10000)}`;
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      email,
      passwordHash: hashedPassword,
      username: finalUsername,
    });

    // const token = jwt.sign(
    //   { userId: user._id, email: user.email },
    //   process.env.JWT_SECRET_USER_LOGIN,
    //   { expiresIn: "7d" }
    // );

    // res.cookie("token", token, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === "production", // HTTPS only in prod
    //   sameSite: "strict", // or "lax" if you need cross-site redirects (Google OAuth)
    //   maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    //   domain: process.env.NODE_ENV === "production" ? ".vidyari.com" : undefined, // allow across subdomains
    // });

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
    const resetLink = `https://www.vidyari.com/reset-password/${resetToken}`;

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
      return res.status(400).json({
        message: "Password must be at least 8 characters long.",
      });
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("JWT secret not configured");
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).json({ message: "Invalid or expired reset link." });
    }

    // Find user
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({ message: "User not found." });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Save new password
    user.passwordHash = hashedPassword;

    // Optional: invalidate other sessions or refresh tokens here
   console.log("password save for user ",user.username,"passwordHash",user.passwordHash)
    await user.save();

    res.status(200).json({
      message: "Password reset successful. You can now log in with your new password.",
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
    let fileUrl = userData.profilePicUrl;
    console.log(fileUrl);

    if (fileUrl) {
      try {
        // If fileUrl is relative (starts with /), prepend your domain
        if (fileUrl.startsWith("/")) {
          fileUrl = `${CF_DOMAIN}${fileUrl}`;
        }

        const url = new URL(fileUrl); // now this should always work
        const key = url.pathname.substring(1); // remove leading "/"
        userData.profilePicUrl = `${CF_DOMAIN}/${key}`;
      } catch (err) {
        console.error("Invalid URL for profile pic:", fileUrl, err);
        userData.profilePicUrl = null; // fallback
      }
    }




    // "avatars/avatar-68d611a993f888f73f6306fe-1758875009169.jpg"

    //  userData.profilePicUrl= `${CF_DOMAIN}/files-previews/images/${file._id}.${files.imageType || "jpg"}`

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

const multer = require("multer");
const multerS3 = require("multer-s3");
const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const path = require("path");
const userTransactions = require("../../models/userTransactions.js");
const requireAuth = require("./reaquireAuth.js");
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

  key: function (req, file, cb) {
    // Create a unique filename using the user's ID from req.user
    const fileName = `avatars/avatar-${req.user._id
      }-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, fileName);
  },
});
router.get('/following', authenticateJWT_user, reaquireAuth, async (req, res) => {
  try {
    // Example: Fetch the current user and populate their 'following' list
    const currentUser = await User.findById(req.user.id).populate({
      path: 'following',
      select: 'username fullname profilePicUrl' // Only get the fields you need
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

    res.render('following', {
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      followingList: currentUser.following // This must be an array of user objects
    });

  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

router.get('/followers', authenticateJWT_user, reaquireAuth, async (req, res) => {
  try {
    // Example: Fetch the current user and populate their 'followers' list
    const currentUser = await User.findById(req.user.id).populate({
      path: 'followers',
      select: 'username fullname profilePicUrl' // Only get the fields you need
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

    res.render('followers', {
      isLoggedin: !!req.user,
      profileUrl: user?.profilePicUrl || null,
      username: user?.username || null,
      useremail: user?.email || null,
      followersList: currentUser.followers // Pass the populated array to the EJS file
    });

  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
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

        updateData.profilePicUrl = req.file.location;

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
        profileUrl: user?.profilePicUrl || null,
        username: user?.username || null,
        useremail: user?.email || null,
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

router.get("/profile/:username", authenticateJWT_user, async (req, res) => {
  try {
    const user = await User.findOne({
      username: new RegExp(`^${req.params.username}$`, "i")
    });
    console.log("user id is", user._id)

    // 1. Handle user not found case FIRST and exit immediately.
    if (!user) {
      return res.status(404).render("404.ejs"); // Or send a simple message
    }
    //  let user = null;

    // 2. Fetch the profile user's files and prepare them ONCE.
    const files = await File.find({ userId: user._id });
    const numsOfDocs = files.length;
    const numOfCourses = 0; // For now only
 const S3_BUCKET = 'vidyari2';
  const REGION = 'ap-south-1';

  const BASE_URL = `https://${S3_BUCKET}.s3.${REGION}.amazonaws.com`;
    const filesWithPreviews = files.map((file) => ({
      ...file.toObject(),
      previewUrl: `${BASE_URL}/files-previews/images/${file._id}.${file.imageType || "jpg"
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



/**
 * @route   POST /user/follow
 * @desc    Follow a user
 * @access  Private
 */
router.post('/user/follow', authenticateJWT_user, reaquireAuth, async (req, res) => {
  const currentUserId = req.user._id; // ID of the user performing the action (from middleware)
  const { userId: userIdToFollow } = req.body; // ID of the user to be followed (from frontend)

  if (currentUserId === userIdToFollow) {
    return res.status(400).json({ success: false, message: "You cannot follow yourself." });
  }

  try {
    // Find both users in the database
    const currentUser = await User.findById(currentUserId);
    const userToFollow = await User.findById(userIdToFollow);

    if (!userToFollow) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    // Check if already following
    if (currentUser.following.includes(userIdToFollow)) {
      return res.status(400).json({ success: false, message: "You are already following this user." });
    }

    // Update both users' documents in one transaction for safety
    await User.updateOne(
      { _id: currentUserId },
      { $addToSet: { following: userIdToFollow } } // Use $addToSet to avoid duplicates
    );
    await User.updateOne(
      { _id: userIdToFollow },
      { $addToSet: { followers: currentUserId } }
    );

    res.status(200).json({ success: true, message: `Successfully followed ${userToFollow.username}.` });

  } catch (error) {
    console.error("Error in /user/follow route:", error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

/**
 * @route   POST /user/unfollow
 * @desc    Unfollow a user
 * @access  Private
 */
router.post('/user/unfollow', authenticateJWT_user, reaquireAuth, async (req, res) => {
  const currentUserId = req.user._id; // ID of the user performing the action
  const { userId: userIdToUnfollow } = req.body; // ID of the user to be unfollowed

  try {
    // Find the user to unfollow to get their username for the message
    const userToUnfollow = await User.findById(userIdToUnfollow);
    if (!userToUnfollow) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    // Update both users' documents
    await User.updateOne(
      { _id: currentUserId },
      { $pull: { following: userIdToUnfollow } } // Use $pull to remove the ID
    );
    await User.updateOne(
      { _id: userIdToUnfollow },
      { $pull: { followers: currentUserId } }
    );

    res.status(200).json({ success: true, message: `Successfully unfollowed ${userToUnfollow.username}.` });

  } catch (error) {
    console.error("Error in /user/unfollow route:", error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});


// module.exports = router;
// module.exports = router;
module.exports = { authRouter: router, authenticateJWT_user, User };
