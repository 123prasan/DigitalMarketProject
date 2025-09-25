const nodemailer = require("nodemailer");

module.exports = async function sendVerifyEmail(email, subject, username, verify_link) {
  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verification</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f5f7fa; margin: 0; padding: 0; }
    .email-container { max-width: 600px; margin: 40px auto; background-color: #fff; padding: 30px; border: 1px solid #dadce0; border-radius: 8px; }
    .header { text-align: center; margin-bottom: 25px; }
    .logo { font-size: 24px; font-weight: bold; color: #1a73e8; text-decoration: none; }
    h2 { color: #202124; font-size: 22px; font-weight: 500; margin-top: 0; }
    p { color: #5f6368; font-size: 15px; margin-bottom: 20px; }
    .btn { display: inline-block; padding: 12px 24px; background-color: #1a73e8; color: #fff !important; text-decoration: none; border-radius: 4px; font-size: 15px; font-weight: 500; }
    .footer { margin-top: 30px; padding-top: 20px; text-align: center; font-size: 12px; color: #999; border-top: 1px solid #e8e8e8; }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="header">
      <a href="https://vidyari.com" class="logo">
        <img src="https://vidyari.com/images/logo.svg" alt="Logo" width="150">
      </a>
    </div>
    
    <h2>Verify your email address</h2>
    <p>Hi ${username},</p>
    <p>Thanks for signing up! To activate your account and start using our services, please click the button below to verify your email address.</p>
    
    <div style="text-align: center; margin: 20px 0;">
      <a href="${verify_link}" class="btn">Verify Email</a>
    </div>

    <p style="font-size: 13px;">If the button above doesn't work, copy and paste this link into your browser:</p>
    <p style="font-size: 13px; color: #1286fbff; word-break: break-all;">${verify_link}</p>
    
    <div class="footer">
      <p>&copy; 2024 Vidyari. All rights reserved.</p>
    </div>
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
