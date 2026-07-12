import { VT_BASE, vtHeaders, jsonResponse, normalizeAnalysisData } from "./_vt.js";

function urlToId(url) {
  return btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

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

  const url = (body.url || "").trim();
  if (!url) return jsonResponse({ error: "Missing url." }, 400);

  const id = urlToId(url);

  const reportRes = await fetch(`${VT_BASE}/urls/${id}`, { headers });

  if (reportRes.status === 200) {
    const json = await reportRes.json();
    const { stats, results } = normalizeAnalysisData(json.data.attributes);
    return jsonResponse({
      status: "completed",
      stats,
      results,
      permalink: `https://www.virustotal.com/gui/url/${id}`,
    });
  }

  if (reportRes.status === 404) {
    const submitRes = await fetch(`${VT_BASE}/urls`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
    });
    if (submitRes.status === 429) return jsonResponse({ error: "VirusTotal rate limit reached. Try again in a minute." }, 429);
    if (!submitRes.ok) return jsonResponse({ error: "VirusTotal couldn't accept this URL for scanning." }, 502);
    const submitJson = await submitRes.json();
    return jsonResponse({ status: "queued", analysisId: submitJson.data.id });
  }

  if (reportRes.status === 429) return jsonResponse({ error: "VirusTotal rate limit reached. Try again in a minute." }, 429);
  return jsonResponse({ error: "VirusTotal lookup failed." }, 502);
}
