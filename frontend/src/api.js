export const DEFAULT_API_URL = "http://127.0.0.1:8001";

export function extractErrorMessage(data, fallback = "Unable to scan this content.") {
  if (!data || typeof data !== "object") return fallback;
  if (typeof data.detail === "string" && data.detail.trim()) return data.detail;
  if (Array.isArray(data.detail) && data.detail.length > 0) {
    const first = data.detail[0];
    if (first && typeof first.msg === "string") return first.msg;
  }
  return fallback;
}

export async function submitScan({ content, language, apiUrl = DEFAULT_API_URL, fetchImpl = fetch }) {
  let response;
  try {
    response = await fetchImpl(`${apiUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, language }),
    });
  } catch {
    throw new Error(`Unable to reach the PhishShield API at ${apiUrl}. Make sure the backend is running.`);
  }

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const fallback =
      response.status === 429
        ? "Too many scan requests. Please wait one minute and try again."
        : "Unable to scan this content.";
    const error = new Error(extractErrorMessage(data, fallback));
    error.status = response.status;
    throw error;
  }
  return data;
}
