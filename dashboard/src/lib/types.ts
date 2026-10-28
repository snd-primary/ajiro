// Response shapes of the collector query API (internal/collector/query.go).
// Every string in here was written by an attacker: render it as text only,
// through visible() when it is a raw value.

export type Summary = {
  events: number;
  http_requests: number;
  conn_no_request: number;
  rate_limited: number;
  distinct_src_ips: number;
  first?: string;
  last?: string;
};

export type EventType = "http_request" | "conn_no_request" | "rate_limited";

export type Point = { t: string; event_type: EventType; n: number };

export const TOP_FIELDS = ["path", "query", "user_agent", "method", "host", "src_ip", "dst_port"] as const;
export type TopField = (typeof TOP_FIELDS)[number];

export type TopItem = { value: string; n: number; sources: number; first: string; last: string };

export type EventRow = {
  id: string;
  ts: string;
  event_type: EventType;
  src_ip: string;
  src_port: number | null;
  dst_port: number | null;
  http_method: string | null;
  http_uri: string | null;
  http_path: string | null;
  http_user_agent: string | null;
  http_status: number | null;
  http_proxy_request: boolean | null;
  http_body_len: number | null;
  dropped_count: number | null;
};

export const RANGES = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 } as const;
export type RangeKey = keyof typeof RANGES;
