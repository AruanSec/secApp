const DEFAULT_URL = "http://127.0.0.1:5173";

function frontendUrl(value = DEFAULT_URL) {
  const url = new URL(value);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
      || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("SENTINEL_FRONTEND_URL must be a local HTTP origin, such as http://127.0.0.1:5173");
  }
  return url.origin;
}

function sameOrigin(candidate, origin) {
  try { return new URL(candidate).origin === origin; }
  catch { return false; }
}

module.exports = { DEFAULT_URL, frontendUrl, sameOrigin };
