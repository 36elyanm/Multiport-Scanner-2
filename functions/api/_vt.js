export const VT_BASE = "https://www.virustotal.com/api/v3";

export function vtHeaders(env) {
  if (!env.VT_API_KEY) return null;
  return { "x-apikey": env.VT_API_KEY };
}

export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function normalizeAnalysisData(attrs) {
  const stats = attrs.last_analysis_stats || attrs.stats || {};
  const rawResults = attrs.last_analysis_results || attrs.results || {};
  const results = Object.entries(rawResults).map(([engine, r]) => ({
    engine,
    category: r.category,
    result: r.result || null,
  }));
  return { stats, results };
}
