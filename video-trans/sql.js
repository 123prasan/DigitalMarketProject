const { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } = require("@aws-sdk/client-sqs");
const { MediaConvertClient, CreateJobCommand } = require("@aws-sdk/client-mediaconvert");
const config = require("./config.js");

// Initialize AWS SDK v3 clients
const sqsClient = new SQSClient({ region: config.region });
const mediaConvertClient = new MediaConvertClient({
  region: config.region,
  endpoint: config.mediaconvertEndpoint
});

// Allowed video extensions
const videoExtensions = [".mp4", ".mov", ".mkv", ".avi", ".webm"];

// Poll SQS for messages continuously
async function pollMessages() {
  try {
    const command = new ReceiveMessageCommand({
      QueueUrl: config.sqsUrl,
      MaxNumberOfMessages: config.maxMessages,
      WaitTimeSeconds: config.waitTimeSeconds
    });

    const data = await sqsClient.send(command);

    if (!data.Messages || data.Messages.length === 0) {
      return pollMessages();
    }

    for (const message of data.Messages) {
      try {
        const body = JSON.parse(message.Body);

        // Check if message is direct S3 or SNS-wrapped
        const s3Event = body.Records
          ? body
          : body.Message
            ? JSON.parse(body.Message)
            : null;

        if (!s3Event || !s3Event.Records) {
          console.warn("Skipping invalid SQS message:", body);
          continue;
        }

        const record = s3Event.Records[0];
        const inputKey = decodeURIComponent(record.s3.object.key.replace(/\+/g, " "));

        // Skip non-video files
        const isVideo = videoExtensions.some(ext => inputKey.toLowerCase().endsWith(ext));
        if (!isVideo) {
          console.log(`Skipping non-video file: ${inputKey}`);
          // Optionally delete SQS message to avoid re-processing
          const deleteCmd = new DeleteMessageCommand({
            QueueUrl: config.sqsUrl,
            ReceiptHandle: message.ReceiptHandle
          });
          await sqsClient.send(deleteCmd);
          continue;
        }

        console.log(`New video uploaded: ${inputKey}`);
        await createHlsJob(inputKey);

        // Delete message after success
        const deleteCmd = new DeleteMessageCommand({
          QueueUrl: config.sqsUrl,
          ReceiptHandle: message.ReceiptHandle
        });
        await sqsClient.send(deleteCmd);
        console.log(`Processed and deleted SQS message.`);
      } catch (err) {
        console.error("Error processing message:", err);
      }
    }

    // Continue polling
    pollMessages();
  } catch (err) {
    console.error("SQS Polling error:", err);
    setTimeout(pollMessages, 5000);
  }
}

// Create MediaConvert HLS job
async function createHlsJob(inputKey) {
  const outputPrefix = `hls-output/`;

  const params = {
    Role: config.mediaConvertRole, // e.g., arn:aws:iam::123456789012:role/MediaConvert_Default_Role
    Settings: {
      Inputs: [
        {
          FileInput: `s3://${config.inputBucket}/${inputKey}`,
          AudioSelectors: {
            "Audio Selector 1": { DefaultSelection: "DEFAULT" }
          }
        }
      ],
      OutputGroups: [
        {
          Name: "HLS Group",
          OutputGroupSettings: {
            Type: "HLS_GROUP_SETTINGS",
            HlsGroupSettings: {
              SegmentLength: 5,
              MinSegmentLength: 1,
              Destination: `s3://${config.outputBucket}/${outputPrefix}`
            }
          },
          Outputs: Object.values(config.transcodingPresets).map(preset => ({
            VideoDescription: {
              Width: preset.width,
              Height: preset.height,
              CodecSettings: {
                Codec: "H_264",
                H264Settings: {
                  MaxBitrate: preset.maxBitrate,
                  RateControlMode: "QVBR",
                  SceneChangeDetect: "TRANSITION_DETECTION"
                }
              }
            },
            AudioDescriptions: [
              {
                AudioSelectorName: "Audio Selector 1",
                CodecSettings: {
                  Codec: "AAC",
                  AacSettings: {
                    Bitrate: 128000,
                    CodingMode: "CODING_MODE_2_0",
                    SampleRate: 48000
                  }
                }
              }
            ],
            ContainerSettings: { Container: "M3U8" },
            NameModifier: preset.nameModifier
          }))
        }
      ]
    }
  };

  try {
    const command = new CreateJobCommand(params);
    const job = await mediaConvertClient.send(command);
    console.log("MediaConvert job created:", job.Job.Id);
  } catch (err) {
    console.error("Error creating MediaConvert job:", err);
  }
}

// Start polling
pollMessages();
