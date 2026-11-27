import test from "node:test";
import assert from "node:assert/strict";

import { extractErrorMessage, submitScan } from "../src/api.js";

test("submitScan returns parsed scan result on 200 OK", async () => {
  const payload = { scan_reference: "261127000001", risk_score: 0, risk_level: "Safe" };
  const result = await submitScan({
    content: "https://www.example.com",
    language: "en",
    fetchImpl: async () => new Response(JSON.stringify(payload), { status: 200 }),
  });
  assert.deepEqual(result, payload);
});

test("submitScan surfaces friendly 429 rate-limit detail", async () => {
  await assert.rejects(
    () =>
      submitScan({
        content: "https://www.example.com",
        language: "en",
        fetchImpl: async () =>
          new Response(JSON.stringify({ detail: "Too many scan requests. Please wait one minute and try again." }), {
            status: 429,
          }),
      }),
    /Too many scan requests/,
  );
});

test("submitScan handles validation arrays, non-JSON errors, and unreachable API", async () => {
  assert.equal(extractErrorMessage({ detail: [{ msg: "String should have at least 3 characters" }] }), "String should have at least 3 characters");

  await assert.rejects(
    () =>
      submitScan({
        content: "https://www.example.com",
        language: "en",
        fetchImpl: async () => new Response("Bad Gateway", { status: 502 }),
      }),
    /Unable to scan this content/,
  );

  await assert.rejects(
    () =>
      submitScan({
        content: "https://www.example.com",
        language: "en",
        fetchImpl: async () => {
          throw new TypeError("fetch failed");
        },
      }),
    /Unable to reach the PhishShield API/,
  );
});
