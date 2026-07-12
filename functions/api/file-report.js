import { VT_BASE, vtHeaders, jsonResponse, normalizeAnalysisData } from "./_vt.js";

export async function onRequestPost({ request, env }) {
  const headers = vtHeaders(env);
  if (!headers) {
    return jsonResponse({ error: "VirusTotal isn't configured on this deployment yet (missing VT_API_KEY)." }, 501);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid request body." }, 400);
  }

  const hash = (body.hash || "").trim();
  if (!/^[a-f0-9]{64}$/i.test(hash)) return jsonResponse({ error: "Invalid SHA-256 hash." }, 400);

  const res = await fetch(`${VT_BASE}/files/${hash}`, { headers });
  if (res.status === 404) return jsonResponse({ status: "unknown" });
  if (res.status === 429) return jsonResponse({ error: "VirusTotal rate limit reached. Try again in a minute." }, 429);
  if (!res.ok) return jsonResponse({ error: "VirusTotal lookup failed." }, 502);

  const json = await res.json();
  const { stats, results } = normalizeAnalysisData(json.data.attributes);
  return jsonResponse({
    status: "completed",
    stats,
    results,
    permalink: `https://www.virustotal.com/gui/file/${hash}`,
  });
}
