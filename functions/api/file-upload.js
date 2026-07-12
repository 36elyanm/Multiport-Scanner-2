import { VT_BASE, vtHeaders, jsonResponse } from "./_vt.js";

const MAX_BYTES = 32 * 1024 * 1024;

export async function onRequestPost({ request, env }) {
  const headers = vtHeaders(env);
  if (!headers) {
    return jsonResponse({ error: "VirusTotal isn't configured on this deployment yet (missing VT_API_KEY)." }, 501);
  }

  const incoming = await request.formData();
  const file = incoming.get("file");
  if (!file || typeof file === "string") return jsonResponse({ error: "No file provided." }, 400);
  if (file.size > MAX_BYTES) {
    return jsonResponse({ error: "File is larger than VirusTotal's 32MB limit for direct upload." }, 413);
  }

  const forward = new FormData();
  forward.append("file", file, file.name);

  const res = await fetch(`${VT_BASE}/files`, { method: "POST", headers, body: forward });
  if (res.status === 429) return jsonResponse({ error: "VirusTotal rate limit reached. Try again in a minute." }, 429);
  if (!res.ok) return jsonResponse({ error: "VirusTotal couldn't accept this file for scanning." }, 502);

  const json = await res.json();
  return jsonResponse({ status: "queued", analysisId: json.data.id });
}
