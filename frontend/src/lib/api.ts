import type {
  FeedHealth,
  FeedbackAction,
  ModelMetadata,
  ForecastingBenchmark,
  QueryResult,
  SimulatorType,
  StatsResponse,
  ThresholdConfig,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8081";

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export function queryDomain(domain: string, clientIp?: string): Promise<QueryResult> {
  return fetchJson<QueryResult>("/api/v1/query", {
    method: "POST",
    body: JSON.stringify({ domain, client_ip: clientIp }),
  });
}

export function getStats(): Promise<StatsResponse> {
  return fetchJson<StatsResponse>("/api/v1/stats");
}

export function getEvents(limit = 50): Promise<QueryResult[]> {
  return fetchJson<QueryResult[]>(`/api/v1/events?limit=${limit}`);
}

export function getEvent(id: string): Promise<QueryResult> {
  return fetchJson<QueryResult>(`/api/v1/events/${id}`);
}

export function submitFeedback(id: string, action: FeedbackAction): Promise<{ ok: boolean }> {
  return fetchJson<{ ok: boolean }>(`/api/v1/events/${id}/feedback`, {
    method: "POST",
    body: JSON.stringify({ action }),
  });
}

export function getFeedHealth(): Promise<FeedHealth[]> {
  return fetchJson<FeedHealth[]>("/api/v1/feed-health");
}

export function getModelMetadata(): Promise<ModelMetadata> {
  return fetchJson<ModelMetadata>("/api/v1/models/metadata");
}

export function getForecastingBenchmark(): Promise<ForecastingBenchmark> {
  // This report is served by the Next.js application because it is a local,
  // persisted evaluation artifact rather than a live gateway operation.
  return fetch("/api/v1/models/forecasting-benchmark")
    .then(async (res) => {
      if (!res.ok) throw new Error(`Request failed: ${res.status}`);
      return res.json() as Promise<ForecastingBenchmark>;
    });
}

export function getThresholds(): Promise<ThresholdConfig> {
  return fetchJson<ThresholdConfig>("/api/v1/settings/thresholds");
}

export function setThresholds(thresholds: ThresholdConfig): Promise<ThresholdConfig> {
  return fetchJson<ThresholdConfig>("/api/v1/settings/thresholds", {
    method: "PUT",
    body: JSON.stringify(thresholds),
  });
}

export function runSimulator(type: SimulatorType): Promise<QueryResult> {
  return fetchJson<QueryResult>("/api/v1/simulate", {
    method: "POST",
    body: JSON.stringify({ type }),
  });
}

export function getEndpoint(): Promise<{ endpoint: string }> {
  return fetchJson<{ endpoint: string }>("/api/v1/config");
}
