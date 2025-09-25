const cloudfrontSigner = require("aws-cloudfront-sign");
const fs = require("fs");

const CF_DOMAIN2 = "https://d1ez1nge3m6khs.cloudfront.net";
const CF_KEY_PAIR_ID = "APKAYPJZ6PT3QQ7YGXNK";
const CF_PRIVATE_KEY_PATH = "C:/Users/prasa/Downloads/pk-APKAYPJZ6PT3QQ7YGXNK.pem";

const privateKey = fs.readFileSync(CF_PRIVATE_KEY_PATH, "utf8").replace(/\r\n/g,"\n").trim() + "\n";

const signedUrl = cloudfrontSigner.getSignedUrl(`${CF_DOMAIN2}/test.pdf`, {
  keypairId: CF_KEY_PAIR_ID,
  privateKey,
  expireTime: Math.floor(Date.now() / 1000) + 60,
});

console.log(signedUrl);
