const axios = require("axios");
const nodemailer = require("nodemailer");

// ============================================
// EMAIL SERVICE - REAL NODEMAILER SENDING
// ============================================

class EmailService {
  constructor() {
    // Create transporter using Gmail/SMTP credentials
    this.transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: {
        user: process.env.EMAIL_USER || process.env.ADMIN_EMAIL || "vidyari.inc@gmail.com",
        pass: process.env.EMAIL_PASS || process.env.ADMIN_PASSWORD || "tskm uekr dgkc rbsc",
      },
    });
  }

  // Wrap email content in spam-friendly HTML template
  wrapEmailTemplate(htmlContent) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email</title>
  <style type="text/css">
    body { margin: 0; padding: 0; min-width: 100% !important; font-family: 'Segoe UI', Arial, sans-serif; }
    .email-container { background-color: #f5f5f5; width: 100%; }
    .email-wrapper { max-width: 600px; margin: 0 auto; background: white; }
    textarea { display: none; }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="email-wrapper">
      ${htmlContent}
      <div style="text-align: center; padding: 20px; font-size: 12px; color: #999; border-top: 1px solid #eee; margin-top: 20px;">
        <p>&copy; ${new Date().getFullYear()} ${process.env.COMPANY_NAME || 'DigitalMarket'}. All rights reserved.</p>
        <p style="margin: 10px 0 0 0;">
          <a href="${process.env.BASE_URL || 'http://localhost:8000'}/contact" style="color: #2e86de; text-decoration: none;">Contact</a> | 
          <a href="${process.env.BASE_URL || 'http://localhost:8000'}/privacy" style="color: #2e86de; text-decoration: none;">Privacy</a> | 
          <a href="${process.env.BASE_URL || 'http://localhost:8000'}/unsubscribe?email={email}" style="color: #2e86de; text-decoration: none;">Unsubscribe</a>
        </p>
      </div>
    </div>
  </div>
</body>
</html>`;
  }

  // Send email to single recipient with full HTML
  async sendEmail(to, subject, html) {
    return new Promise((resolve, reject) => {
      const mailOptions = {
        from: `"${process.env.COMPANY_NAME || 'DigitalMarket'}" <${process.env.EMAIL_USER || 'vidyari.inc@gmail.com'}>`,
        to: to,
        subject: subject,
        html: html,
        // Add text version for better deliverability
        text: html.replace(/<[^>]*>/g, '').substring(0, 500),
        // Add headers to avoid spam folder
        headers: {
          'X-Mailer': 'Vidyari-Mailer',
          'X-Priority': '3',
          'Importance': 'normal',
          'List-Unsubscribe': `<${process.env.BASE_URL || 'http://localhost:8000'}/unsubscribe?email=${to}>`,
          'X-MSMail-Priority': 'Normal',
          'Precedence': 'list',
        },
        // Reply-To header
        replyTo: process.env.SUPPORT_EMAIL || process.env.EMAIL_USER || 'vidyari.inc@gmail.com',
      };

      this.transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(`❌ Error sending email to ${to}:`, error);
          reject(error);
        } else {
          console.log(`✅ Email sent to ${to}:`, info.response);
          resolve({
            email: to,
            messageId: info.messageId,
            status: 'sent',
            timestamp: new Date()
          });
        }
      });
    });
  }

  // Send bulk emails to multiple recipients with personalization
  async sendEmailBulk(recipients, subject, htmlContent, options = {}) {
    try {
      const results = [];
      const errors = [];

      for (const recipient of recipients) {
        try {
          // Replace placeholders with recipient data
          let personalizedHtml = htmlContent
            .replace(/{username}/g, recipient.username || 'User')
            .replace(/{email}/g, recipient.email);

          // Wrap in spam-friendly template if not already wrapped
          if (!personalizedHtml.includes('<html')) {
            personalizedHtml = this.wrapEmailTemplate(personalizedHtml);
          }

          const result = await this.sendEmail(recipient.email, subject, personalizedHtml);
          results.push(result);
        } catch (error) {
          console.error(`Failed to send to ${recipient.email}:`, error.message);
          errors.push({
            email: recipient.email,
            error: error.message
          });
        }
      }

      console.log(`\n📊 Email Campaign Summary:`);
      console.log(`✅ Sent: ${results.length}/${recipients.length}`);
      if (errors.length > 0) console.log(`❌ Failed: ${errors.length}`);

      return {
        success: true,
        sent: results.length,
        failed: errors.length,
        results: results,
        errors: errors
      };
    } catch (error) {
      console.error('❌ Bulk email sending error:', error);
      throw error;
    }
  }

  // Send email from template file
  async sendEmailTemplate(templateName, recipients, customData = {}) {
    try {
      const template = emailTemplates[templateName];
      if (!template) {
        throw new Error(`Template "${templateName}" not found`);
      }

      const htmlContent = template.getHtml(customData);
      return await this.sendEmailBulk(recipients, template.subject, htmlContent);
    } catch (error) {
      console.error('❌ Template email error:', error);
      throw error;
    }
  }
}

// ============================================
// PROFESSIONAL EMAIL TEMPLATES
// ============================================

const emailTemplates = {
  welcome: {
    subject: "🎉 Welcome to DigitalMarket!",
    getHtml: (data) => `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: #f9f9f9; padding: 20px; border-radius: 8px; }
          .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { background: white; padding: 30px; border-radius: 0 0 8px 8px; }
          .button { background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }
          .footer { text-align: center; padding-top: 20px; color: #666; font-size: 12px; border-top: 1px solid #eee; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to DigitalMarket! 🚀</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${data.username || "there"}</strong>,</p>
            <p>We're thrilled to have you join <strong>DigitalMarket</strong>!</p>
            <p><a href="https://digitalmarket.com/dashboard" class="button">Start Exploring →</a></p>
            <p>Best regards,<br><strong>The DigitalMarket Team</strong></p>
          </div>
          <div class="footer">
            <p>&copy; 2026 DigitalMarket. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  },
  promotional: {
    subject: "🎁 Exclusive Offer Just For You!",
    getHtml: (data) => `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: 'Segoe UI', sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; background: #fff; }
          .promo-box { background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
          .discount { font-size: 32px; font-weight: bold; color: #ff6b6b; }
          .button { background: #ff6b6b; color: white; padding: 15px 40px; text-decoration: none; border-radius: 5px; display: inline-block; }
          .footer { text-align: center; padding: 20px; color: #999; font-size: 11px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div style="background: #f9f9f9; padding: 20px; text-align: center;">
            <h1>🎉 Limited Time Offer!</h1>
          </div>
          <div style="padding: 30px;">
            <p>Dear <strong>${data.username || "Valued Member"}</strong>,</p>
            <div class="promo-box">
              <div class="discount">${data.discount || "50%"} OFF</div>
              <p style="margin: 10px 0;">Use code: <strong>${data.couponCode || "SAVE50"}</strong></p>
            </div>
            <p style="text-align: center;"><a href="https://digitalmarket.com/explore" class="button">Claim Your Offer →</a></p>
          </div>
          <div class="footer">
            <p>&copy; 2026 DigitalMarket</p>
          </div>
        </div>
      </body>
      </html>
    `
  }
};

// ============================================
// PUSH NOTIFICATION SERVICE
// ============================================

async function sendNotification({
  userId,
  title,
  body,
  image = "",
  target_link = "/",
  notification_type = "GENERAL",
}) {
  try {
    const res = await axios.post("https://www.vidyari.com/send", {
      userId,
      title,
      body,
      image,
      target_link,
      notification_type,
    });

    console.log("✅ Notification sent:", res.data);
    return { success: true, data: res.data };
  } catch (err) {
    console.error("❌ Error sending notification:", err.response?.data || err.message);
    return { success: false, error: err.message };
  }
}

// ✅ Export services
module.exports = { EmailService, emailTemplates, sendNotification };