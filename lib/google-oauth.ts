import { google } from "googleapis";

export const GMAIL_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "openid",
  "email",
];

export function getOAuthClient() {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${baseUrl}/api/auth/google/callback`
  );
}
