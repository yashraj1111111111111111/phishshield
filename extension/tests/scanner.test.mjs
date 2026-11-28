import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { scanText, checkLinkTextMismatch } = require("../scanner.js");

test("raw IP HTTP link is flagged Dangerous before opening", () => {
  const result = scanText("http://198.51.100.42/verify");
  assert.equal(result.risk_level, "Dangerous");
  assert.ok(result.risk_score >= 60);
  assert.equal(result.content_type, "url");
});

test("benign reserved domain stays Low Risk (unverified)", () => {
  const result = scanText("https://www.example.com");
  assert.equal(result.risk_level, "Low Risk");
  assert.equal(result.risk_score, 0);
});

test("brand spoof and shortened pressure link trigger warning threshold", () => {
  const brandSpoof = scanText("https://paypal-verify.example/login");
  assert.ok(brandSpoof.risk_score >= 25);
  assert.notEqual(brandSpoof.risk_level, "Low Risk");

  const shortener = scanText("http://bit.ly/verify");
  assert.equal(shortener.risk_level, "Suspicious");
  assert.ok(shortener.risk_score >= 25);
});

test("OTP KYC scam message is flagged Dangerous", () => {
  const result = scanText("Urgent: share your OTP today to verify your KYC");
  assert.equal(result.risk_level, "Dangerous");
  assert.equal(result.content_type, "message");
});

test("threshold split: Suspicious (25–59) stays below Dangerous boundary", () => {
  // bit.ly/verify should be Suspicious, not Dangerous — soft toast applies
  const shortener = scanText("http://bit.ly/verify");
  assert.ok(shortener.risk_score >= 25, "must meet toast threshold");
  assert.ok(shortener.risk_score < 60, "must NOT reach hard-block threshold");
  assert.equal(shortener.risk_level, "Suspicious");
});

test("threshold split: raw IP link (60+) reaches hard-block Dangerous boundary", () => {
  const dangerous = scanText("http://198.51.100.42/verify");
  assert.ok(dangerous.risk_score >= 60, "must reach hard-block threshold");
  assert.equal(dangerous.risk_level, "Dangerous");
});

test("Low Risk link (0–24) does not reach any interception threshold", () => {
  const safe = scanText("https://www.example.com");
  assert.ok(safe.risk_score < 25, "must not trigger toast or hard block");
  assert.equal(safe.risk_level, "Low Risk");
});

test("checkLinkTextMismatch flags deceptive visible domain vs href target", () => {
  const deceptive = checkLinkTextMismatch("Click hdfcbank.com to verify", "https://bit.ly/fake-hdfc");
  assert.equal(deceptive.mismatch, true);
  assert.equal(deceptive.visibleDomain, "hdfcbank.com");
  assert.equal(deceptive.targetHost, "bit.ly");

  const genuine = checkLinkTextMismatch("Visit hdfcbank.com", "https://netbanking.hdfcbank.com/login");
  assert.equal(genuine.mismatch, false);
});
