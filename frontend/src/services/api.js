import { mockApi } from "./mockApi.js";

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? "";
const environmentMocks = import.meta.env.VITE_USE_MOCK_API !== "false";

function useMocks() {
  const savedSource = localStorage.getItem("drishti-data-source");
  return savedSource ? savedSource !== "live" : environmentMocks;
}

async function getOrMock(path, mockRequest) {
  if (useMocks()) return mockRequest();

  try {
    const response = await fetch(`${baseUrl}${path}`);
    if (!response.ok) throw new Error(`Request failed: ${response.status}`);
    return await response.json();
  } catch {
    return mockRequest();
  }
}

export const api = {
  getSystemHealth: () => getOrMock("/health/ready", mockApi.getSystemHealth),
  getDashboard: () => getOrMock("/api/dashboard", mockApi.getDashboard),
  getPipelineStatus: () => getOrMock("/api/pipeline/status", mockApi.getPipelineStatus),
  getIngestionStatus: () => getOrMock("/api/ingestion/status", mockApi.getIngestionStatus),
  getEvents: () => getOrMock("/api/events", mockApi.getEvents),
  getEvent: (id) => getOrMock(`/api/events/${encodeURIComponent(id)}`, () => mockApi.getEvent(id)),
  getParserStatus: () => getOrMock("/api/parsers", mockApi.getParserStatus),
  getProvenance: (id) => getOrMock(`/api/provenance/${encodeURIComponent(id)}`, mockApi.getProvenance),
  getReplay: (id) => getOrMock(`/api/replay/${encodeURIComponent(id)}`, mockApi.getReplay),
  getGovernanceAudit: () => getOrMock("/api/governance/audit", mockApi.getGovernanceAudit),
};