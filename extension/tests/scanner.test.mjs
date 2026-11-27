import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { scanText } = require("../scanner.js");

test("raw IP HTTP link is flagged Dangerous before opening", () => {
  const result = scanText("http://198.51.100.42/verify");
  assert.equal(result.risk_level, "Dangerous");
  assert.ok(result.risk_score >= 60);
  assert.equal(result.content_type, "url");
});

test("benign reserved domain stays Safe", () => {
  const result = scanText("https://www.example.com");
  assert.equal(result.risk_level, "Safe");
  assert.equal(result.risk_score, 0);
});

test("brand spoof and shortened pressure link trigger warning threshold", () => {
  const brandSpoof = scanText("https://paypal-verify.example/login");
  assert.ok(brandSpoof.risk_score >= 25);
  assert.notEqual(brandSpoof.risk_level, "Safe");

  const shortener = scanText("http://bit.ly/verify");
  assert.equal(shortener.risk_level, "Suspicious");
  assert.ok(shortener.risk_score >= 25);
});

test("OTP KYC scam message is flagged Dangerous", () => {
  const result = scanText("Urgent: share your OTP today to verify your KYC");
  assert.equal(result.risk_level, "Dangerous");
  assert.equal(result.content_type, "message");
});
