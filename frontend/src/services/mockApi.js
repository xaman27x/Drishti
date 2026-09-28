import {
  auditEvents,
  dashboardData,
  ingestionData,
  mockEvents,
  parserData,
  provenanceData,
  systemHealth,
} from "../data/mockData.js";

const pause = (value) => new Promise((resolve) => window.setTimeout(() => resolve(structuredClone(value)), 140));

export const mockApi = {
  getSystemHealth: () => pause(systemHealth),
  getDashboard: () => pause(dashboardData),
  getPipelineStatus: () => pause(dashboardData.pipeline),
  getIngestionStatus: () => pause(ingestionData),
  getEvents: () => pause(mockEvents),
  getEvent: (id) => pause(mockEvents.find((event) => event.id === id) ?? null),
  getParserStatus: () => pause(parserData),
  getProvenance: () => pause(provenanceData),
  getReplay: () => pause([]),
  getGovernanceAudit: () => pause(auditEvents),
};