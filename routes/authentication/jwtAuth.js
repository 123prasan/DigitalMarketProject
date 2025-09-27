require("dotenv").config();
const express = require("express");
const User = require("../../models/userData");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET_USER_LOGIN || "fallback-secret";

const authenticateJWT_user = async (req, res, next) => {
  try {
    let token;

    // Check Authorization header or cookies
    const authHeader = req.header("Authorization");
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    } else if (req.cookies?.token) {
      token = req.cookies.token;
    }

    if (!token) {
      req.user = null; // No token → guest
      return next();
    }

    // Verify token
    const payload = jwt.verify(token, JWT_SECRET);

    // Fetch user
    const user = await User.findById(payload.userId).select("-password");
    req.user = user || null;

    if (req.user) {
      console.log("User authenticated:", req.user._id.toString());
    } else {
      console.log("Token valid, but user not found");
    }

    next();
  } catch (err) {
    console.error("Optional Auth Error:", err.message);
    req.user = null; // Invalid token → guest
    next();
  }
};

module.exports = authenticateJWT_user;


