import { VT_BASE, vtHeaders, jsonResponse, normalizeAnalysisData } from "./_vt.js";

export async function onRequestGet({ request, env }) {
  const headers = vtHeaders(env);
  if (!headers) {
    return jsonResponse({ error: "VirusTotal isn't configured on this deployment yet (missing VT_API_KEY)." }, 501);
  }

  const id = new URL(request.url).searchParams.get("id");
  if (!id) return jsonResponse({ error: "Missing id." }, 400);

  const res = await fetch(`${VT_BASE}/analyses/${id}`, { headers });
  if (res.status === 429) return jsonResponse({ error: "VirusTotal rate limit reached. Try again in a minute." }, 429);
  if (!res.ok) return jsonResponse({ error: "VirusTotal lookup failed." }, 502);

  const json = await res.json();
  const attrs = json.data.attributes;
  if (attrs.status !== "completed") return jsonResponse({ status: attrs.status });

  const { stats, results } = normalizeAnalysisData(attrs);
  return jsonResponse({ status: "completed", stats, results });
}
