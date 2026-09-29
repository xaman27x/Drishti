const baseUrl = import.meta.env.VITE_API_BASE_URL ?? "";

async function request(path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...(body === undefined ? {} : { method: "POST", body: JSON.stringify(body) }),
    headers: { "Content-Type": "application/json", "X-Drishti-Demo": "true" },
    signal: AbortSignal.timeout(20000),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : JSON.stringify(result.detail ?? result));
  return result;
}

export const api = {
  getSystemHealth: () => request("/health/dependencies"),
  getDashboard: () => request("/api/dashboard"),
  getPipelineStatus: () => request("/api/pipeline/status"),
  getIngestionStatus: () => request("/api/ingestion/status"),
  getEvents: () => request("/api/events"),
  getEvent: (id) => request(`/api/events/${encodeURIComponent(id)}`),
  getParserStatus: () => request("/api/parsers"),
  getEvidence: (id) => request(`/v1/events/${encodeURIComponent(id)}/evidence`),
  getReplay: () => request("/api/replay"),
  createReplay: (body) => request("/api/replay", body),
  approveReplay: (id) => request(`/api/replay/${id}/approve`, {}),
  getGovernanceAudit: () => request("/api/governance/audit"),
  getProposals: () => request("/api/governance/proposals"),
  propose: (pack) => request("/api/governance/proposals", { pack }),
  proposalAction: (id, body) => request(`/api/governance/proposals/${id}`, body),
  copilot: (event_ids, version) => request("/api/copilot/proposals", { event_ids, version }),
  getProof: (revision) => request(`/api/parsers/${revision}/proof`),
  workerControl: (action) => request("/api/worker/control", { action }),
  ingest: (raw, sourceType, sourceId, idempotencyKey) => {
    const bytes = new TextEncoder().encode(raw);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return request("/v1/events", { tenant_id: "sih-demo", source_id: sourceId, source_type: sourceType,
      idempotency_key: idempotencyKey, payload_base64: btoa(binary) });
  },
};
