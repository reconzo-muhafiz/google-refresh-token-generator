import "dotenv/config";
import { google } from "googleapis";

/**
 * HTTP Cloud Function
 * Expects a query param `code` (OAuth2 authorization code)
 * Exchanges it for tokens and returns the refresh token
 */
export async function getRefreshToken(req, res) {
  try {
    // Step 1: Extract `code`
    const code = req.query.code;
    if (!code) {
      return res.status(400).json({ error: "Missing 'code' query parameter" });
    }

    // Step 2: OAuth2 client
    const CLIENT_ID = process.env.CLIENT_ID;
    const CLIENT_SECRET = process.env.CLIENT_SECRET;
    const REDIRECT_URI = process.env.REDIRECT_URI; // must match Google console settings

    console.log("CLIENT_ID: ", CLIENT_ID);
    console.log("CLIENT_SECRET: ", CLIENT_SECRET);
    console.log("REDIRECT_URI: ", REDIRECT_URI);

    const oAuth2Client = new google.auth.OAuth2(
      CLIENT_ID,
      CLIENT_SECRET,
      REDIRECT_URI
    );

    // Step 3: Exchange code for tokens
    const { tokens } = await oAuth2Client.getToken(code);

    if (!tokens.refresh_token) {
      return res.status(400).json({
        error:
          "No refresh token returned. Ensure 'access_type=offline' and 'prompt=consent' were used in the OAuth request.",
      });
    }

    // Step 4: Return refresh token (and optionally access token)
    return res.json(tokens);
  } catch (error) {
    console.error("Error exchanging code:", error);
    return res.status(500).json({ error: "Failed to exchange code for tokens" });
  }
}
