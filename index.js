import "dotenv/config";
import { google } from "googleapis";
import crypto from "crypto";
import { Storage } from "@google-cloud/storage";

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = 16;

const encrypt = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY, "hex"), iv);

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  return {
    iv: iv.toString("hex"),
    data: encrypted
  }
}

const storage = new Storage();
const BUCKET_NAME = process.env.BUCKET_NAME;
const FILE_NAME = process.env.FILE_NAME;

/**
 * HTTP Cloud Function
 * Expects a query param `code` (OAuth2 authorization code)
 * Exchanges it for tokens, encrypts it and saves the token in gcs bucket
 */
export async function generate(req, res) {
  try {
    // Step 1: Extract `code`
    const code = req.query.code;
    console.log("Code: ", code);
    if (!code) {
      return res.status(400).json({ error: "Missing 'code' query parameter" });
    }

    // Step 2: OAuth2 client
    const CLIENT_ID = process.env.CLIENT_ID;
    const CLIENT_SECRET = process.env.CLIENT_SECRET;
    const REDIRECT_URI = process.env.REDIRECT_URI; // must match Google console settings

    const oAuth2Client = new google.auth.OAuth2(
      CLIENT_ID,
      CLIENT_SECRET,
      REDIRECT_URI
    );

    // Step 3: Exchange code for tokens
    const { tokens } = await oAuth2Client.getToken(code);
    console.log("Token has been generated.")

    if (!tokens.refresh_token) {
      return res.status(400).json({
        error:
          "No refresh token returned. Ensure 'access_type=offline' and 'prompt=consent' were used in the OAuth request.",
      });
    }

    oAuth2Client.setCredentials({ refresh_token: tokens.refresh_token });

    // Get OAuth2 API client
    const oauth2 = google.oauth2({
      auth: oAuth2Client,
      version: "v2",
    });

    // Call userinfo endpoint
    const { data } = await oauth2.userinfo.get();
    console.log("User info fetched");

    let encrypted;

    try {
      encrypted = encrypt(tokens.refresh_token);
      console.log("Token encrypted successfully");
    } catch (error) {
      return res.status(500).json({message: "Server error! try again"});
    }

    const bucket = storage.bucket(BUCKET_NAME);
    const file = bucket.file(FILE_NAME);

    let existingData = [];

    const [exists] = await file.exists();

    console.log("Checked for existence of file");

    if(exists){
      const [fileContent] = await file.download();

      console.log("File downloaded");

      try {
        existingData = JSON.parse(fileContent.toString());
      } catch (error) {
        console.warn("File is empty or corrupted");
        existingData = [];
      }
    }

    existingData.push({
      createdAt: new Date().toLocaleString("en-IN", {timeZone: "Asia/Kolkata"}),
      userName: data.name,
      userEmail: data.email,
      token: encrypted
    });

    try {
      await file.save(JSON.stringify(existingData, null, 2), {
        contentType: "application/json"
      })
      console.log("File saved in gcs bucket.");
    } catch (error) {
      console.error("Failed to save file: ", error);
      res.status(500).json({message: "Server error! try again"});
    }

    // Step 4: Return refresh token (and optionally access token)
    return res.json({message: "Authorization successfull, you can close the tab."});

  } catch (error) {
    console.error("Error exchanging code:", error);
    return res.status(500).json({ message: "Server error! Failed to authorize. Please contact app owner for details." });
  }
}
