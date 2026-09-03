/**
 * TRACEGUARD AI - EML / MIME Encoding and Decoding Helpers
 */

/**
 * Decodes Gmail API raw base64url string to standard Base64 string
 */
export function base64UrlToBase64(rawBase64Url) {
  if (!rawBase64Url) return "";
  let b64 = rawBase64Url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) {
    b64 += '=';
  }
  return b64;
}

/**
 * Decodes Gmail API raw base64url string to raw UTF-8 string
 */
export function decodeRawToText(rawBase64Url) {
  const b64 = base64UrlToBase64(rawBase64Url);
  return atob(b64);
}

/**
 * Decodes base64url to Uint8Array bytes
 */
export function decodeRawToEmlBytes(rawBase64Url) {
  const b64 = base64UrlToBase64(rawBase64Url);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Constructs a synthetic RFC822 EML string from DOM extracted metadata
 */
export function constructEmlFromMeta({ from, to, subject, date, body, headers = {} }) {
  const dateHeader = date || new Date().toUTCString();
  const headerLines = [
    `From: ${from || "unknown@domain.com"}`,
    `To: ${to || "user@gmail.com"}`,
    `Subject: ${subject || "(No Subject)"}`,
    `Date: ${dateHeader}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=utf-8`
  ];

  for (const [k, v] of Object.entries(headers)) {
    headerLines.push(`${k}: ${v}`);
  }

  return `${headerLines.join('\r\n')}\r\n\r\n${body || ""}`;
}
