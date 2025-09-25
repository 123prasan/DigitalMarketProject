const nodemailer = require("nodemailer")
module.exports= async function passReset(email,subject,username,resetLink){
 let  html= `<!DOCTYPE html>
<html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin:0;padding:0;font-family:Arial,sans-serif;background-color:#f5f7fa;">
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:20px;border:1px solid #e0e0e0;border-radius:8px;">
        <div style="text-align:center; margin-bottom: 20px;">
          <!-- Your logo will appear here -->
          <img src="cid:vidyari_logo" alt="Vidyari Logo" style="max-width:150px; height:auto; display:block; margin: 0 auto;">
        </div>
        <h2 style="color:#333;text-align:center;">Reset Your Password</h2>
        <p>Hello,${username}</p>
        <p>We received a request to reset your password for your Vidyari account.</p>
        <div style="text-align:center;margin:30px 0;">
          <a href="${resetLink}" style="background-color:#007BFF;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;display:inline-block;">Reset Password</a>
        </div>
        <p>If you didn’t request this, please ignore this email. This password reset link will expire in 1 hour.</p>
        <p style="color:#888;font-size:12px;">© ${new Date().getFullYear()} Vidyari. All rights reserved.</p>
      </div>
</body>
</html>`;
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "vidyari.inc@gmail.com",
      pass: "tskm uekr dgkc rbsc", // Gmail app password
    },
  });

  const mailOptions = {
    from: `"Vidyari" <vidyari.inc@gmail.com>`,
    to: email,
    subject: subject,
    html,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return console.log("Error:", error);
    }
    console.log("✅ Email sent:", info.response);
  });
};
