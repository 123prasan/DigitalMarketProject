
const Visitor = require("../models/userlocation");

const axios = require("axios");
const logVisitorMiddleware = async (ip) => {
  try {
   let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
   
     // Handle localhost IPs for development
     if (ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1") {
       ip = "103.21.244.0"; // Sample IP from India (or choose your own real IP)
     }
    
   //    console.log("IP Address:", ipadd);
    
       const geoRes = await fetch(`http://ip-api.com/json/${ip}`);
       const geoData = await geoRes.json();
   
       console.log("GeoData:", geoData);
   
    
  } catch (err) {
    console.warn("⚠️ Visitor logging failed:", err.message);
  }

  next(); // continue to route regardless of errors
};

module.exports = logVisitorMiddleware;
// console.log("📍 Visitor:", {
//       ip: ip,
//       city: data.city,
//       region: data.region,
//       country: data.country,
//       latitude: data.latitude,
//       longitude: data.longitude,
//       postal: data.postal,
//     });

//     await Visitor.create({
//       ip,
//       city: data.city,
//       region: data.region,
//       country: data.country,
//       latitude: data.latitude,
//       longitude: data.longitude,
//       zip: data.postal,
//     });