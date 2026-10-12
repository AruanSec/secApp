const { test } = require("node:test");
const assert = require("node:assert/strict");
const { frontendUrl, sameOrigin } = require("./config.cjs");

test("accepts only local HTTP frontend origins", () => {
  assert.equal(frontendUrl(), "http://127.0.0.1:5173");
  assert.equal(frontendUrl("http://localhost:5174/"), "http://localhost:5174");
  for (const url of ["https://example.com", "http://example.com", "file:///tmp/index.html",
    "http://127.0.0.1.evil.test:5173", "http://user:password@localhost:5173",
    "http://localhost:5173/other", "http://localhost:5173/?url=evil", "http://localhost:5173/#other"]) {
    assert.throws(() => frontendUrl(url));
  }
});

test("navigation remains on the configured origin", () => {
  const origin = frontendUrl();
  assert.equal(sameOrigin(`${origin}/#quarantine`, origin), true);
  assert.equal(sameOrigin("http://127.0.0.1:8000", origin), false);
  assert.equal(sameOrigin("https://example.com", origin), false);
  assert.equal(sameOrigin("javascript:alert(1)", origin), false);
  assert.equal(sameOrigin("not a URL", origin), false);
});
