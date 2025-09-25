const { SendEmailCommand,SESClient } = require("@aws-sdk/client-ses");
require("dotenv").config();

const sesClient = new SESClient({
  region: "ap-south-1", // your SES region
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});




async function sendMail() {
  try {
    const params = {
      Source: "vidyari@vidyari.com", // From address
      Destination: {
        ToAddresses: ["prasannaprasanna35521@gmail.com"], // recipient
      },
      Message: {
        Subject: { Data: "Welcome to Vidyari" },
        Body: {
          Text: { Data: "Hello! This is a test email from SES + Node.js backend." },
          Html: { Data: "<h1>Hello!</h1><p>This is a test email from SES + Node.js backend.</p>" }
        }
      }
    };

    const command = new SendEmailCommand(params);
    const response = await sesClient.send(command);
    console.log("Email sent:", response);
  } catch (err) {
    console.error("Error sending email:", err);
  }
}

sendMail();
