const User = require("../../models/userData"); // Assuming this path is correct
const jwt = require('jsonwebtoken');

// const User = require("../../models/userData");
// const jwt = require("jsonwebtoken");

const authenticateJWT_user = async (req, res, next) => {
  try {
    let token;

    // Check Authorization header or cookies
    const authHeader = req.header("Authorization");
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.replace("Bearer ", "");
    } else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      req.user = null; // No token → just continue as guest
      return next();
    }

    // Verify token
    const payload = jwt.verify(
      token,
      "3a1f0b9d5c7e2a8f6d1c4b8a9e3f0d7a2c5e8b6d1a4f7c3e9b0d2a1f6e4c8b2"|| "fallback-secret"
    );

    // Get user
    const user = await User.findById(payload.userId).select("-password");
    req.user = user || null;
    console.log("user id",req.user._id)
    next();
  } catch (err) {
    console.error("Optional Auth Error:", err.message);
    req.user = null; // if token invalid → still treat as guest
    next();
  }
};

module.exports = authenticateJWT_user;

