export type Verdict = "ALLOW" | "FLAG" | "BLOCK";

export interface PipelineStage {
  stage: number;
  name: string;
  contribution: number;
  reason: string;
  active?: boolean;
  decided?: boolean;
}

export interface LexicalChar {
  char: string;
  score: number;
}

export interface LexicalFeatures {
  entropy: number;
  digit_ratio: number;
  vowel_ratio: number;
  longest_consonant_run: number;
  subdomain_count: number;
  tld_suspicion: number;
  char_ngram_score: number;
}

export interface QueryResult {
  id: string;
  domain: string;
  client_ip: string;
  risk_score: number;
  verdict: Verdict;
  pipeline: PipelineStage[];
  reasons?: string[];
  latency_ms?: number;
  ml?: Record<string, unknown>;
  lexical_features?: LexicalFeatures;
  lexical_chars?: LexicalChar[];
  behavioral_context?: string;
  decided_by?: string;
  timestamp: string;
  source?: "live" | "offline import" | "simulator";
  tags?: string[];
}

export interface StatsResponse {
  allowed_24h: number;
  flagged_24h: number;
  blocked_24h: number;
  open_incidents: number;
}

export interface FeedHealth {
  name: string;
  status: "healthy" | "degraded" | "failed";
  indicator_count: number;
  last_sync: string;
  latency_ms?: number;
  error?: string;
}

export interface ModelMetadata {
  version: string;
  trained_date: string;
  dataset_source: string;
  dataset_sha256: string;
  split_strategy: string;
  weighted_f1: number;
  hyperparameter_tuning: boolean;
  holdout_size: number;
}

export interface ForecastingClassMetric {
  precision: number;
  recall: number;
  f1: number;
  support: number;
  reliability: string;
}

export interface ForecastingBenchmark {
  available: boolean;
  source?: string;
  modelArtifact?: string;
  split?: string;
  sequenceGrouping?: string;
  deploymentStatus?: string;
  evaluatedAt?: string;
  metrics?: {
    weighted: { precision: number; recall: number; f1: number };
    benign_fpr: number;
    per_class: Record<string, ForecastingClassMetric>;
  };
  message?: string;
}

export interface ThresholdConfig {
  allow_max: number;
  flag_max: number;
}

export type SimulatorType =
  | "benign"
  | "dga"
  | "typosquat"
  | "c2_beaconing"
  | "dns_tunnelling";

export type FeedbackAction =
  | "Confirmed Threat"
  | "False Positive"
  | "Needs Investigation";
