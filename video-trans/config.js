// config.js
module.exports = {
  // AWS region - Using us-east-1 for MediaConvert availability
  region: "us-east-1",

  // SQS configuration
  sqsUrl: "https://sqs.us-east-1.amazonaws.com/718383533207/vidyarisqs",
  waitTimeSeconds: 5,   // Long polling
  maxMessages: 5,       // Number of messages to receive per poll

  // S3 configuration
  inputBucket: "vidyari3",              // Bucket where raw videos are uploaded
  outputBucket: "post-upload-pending2",  // Not used for direct serving

  // MediaConvert configuration
  mediaconvertEndpoint: "https://mediaconvert.us-east-1.amazonaws.com",
  mediaConvertRole: "arn:aws:iam::718383533207:role/service-role/MediaConvert_Default_Role",

  // Transcoding presets (multi-quality HLS)
  transcodingPresets: {
    hls_1080p: {
      nameModifier: "_1080p",
      maxBitrate: 5000000,
      width: 1920,
      height: 1080
    },
    hls_720p: {
      nameModifier: "_720p",
      maxBitrate: 3000000,
      width: 1280,
      height: 720
    },
    hls_480p: {
      nameModifier: "_480p",
      maxBitrate: 1500000,
      width: 854,
      height: 480
    }
  }
};
