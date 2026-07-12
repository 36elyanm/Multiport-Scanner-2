import { onRequestPost as urlReportPost } from "../functions/api/url-report.js";
import { onRequestGet as analysisGet } from "../functions/api/analysis.js";
import { onRequestPost as fileReportPost } from "../functions/api/file-report.js";
import { onRequestPost as fileUploadPost } from "../functions/api/file-upload.js";

const ROUTES = [
  { method: "POST", path: "/api/url-report", handler: urlReportPost },
  { method: "GET", path: "/api/analysis", handler: analysisGet },
  { method: "POST", path: "/api/file-report", handler: fileReportPost },
  { method: "POST", path: "/api/file-upload", handler: fileUploadPost },
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = ROUTES.find((r) => r.method === request.method && r.path === url.pathname);
    if (route) return route.handler({ request, env });

    return env.ASSETS.fetch(request);
  },
};
