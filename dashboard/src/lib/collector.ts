import { createServerFn } from "@tanstack/solid-start";
import { align, BUCKET_FOR } from "./series";
import { RANGES, type EventRow, type Point, type RangeKey, type Summary, type TopField, type TopItem } from "./types";

// Server functions are the only path from the browser to the collector. The
// query token stays in this process; the browser never sees it. Inputs are
// re-validated here because anyone who can reach the dashboard can call these
// endpoints directly, not only through our UI.

async function query<T>(path: string, params: Record<string, string>): Promise<T> {
  const base = process.env.COLLECTOR_QUERY_URL ?? "http://127.0.0.1:9100";
  const token = process.env.COLLECTOR_QUERY_TOKEN;
  if (!token) throw new Error("COLLECTOR_QUERY_TOKEN is not set");

  const url = new URL(path, base);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  // Report only the status: the body is not ours to echo into the page.
  if (!res.ok) throw new Error(`collector ${path}: HTTP ${res.status}`);
  return (await res.json()) as T;
}

function rangeParams(range: RangeKey) {
  const to = new Date();
  const from = new Date(to.getTime() - RANGES[range] * 3600_000);
  return { from: from.toISOString().replace(/\.\d+Z$/, "Z"), to: to.toISOString().replace(/\.\d+Z$/, "Z") };
}

function parseRange(v: unknown): RangeKey {
  return typeof v === "string" && Object.hasOwn(RANGES, v) ? (v as RangeKey) : "7d";
}

const top = async (rp: Record<string, string>, field: TopField, limit = 10) =>
  (await query<{ items: TopItem[] }>("/api/top", { ...rp, field, limit: String(limit) })).items;

// getOverview gathers everything the overview page shows in one round trip.
// The collector answers at most 4 queries at a time and rejects the rest
// (429) to protect DuckDB, so we ask one after another instead of in parallel.
export const getOverview = createServerFn({ method: "GET" })
  .validator((d: { range: RangeKey }) => ({ range: parseRange(d?.range) }))
  .handler(async ({ data }) => {
    const rp = rangeParams(data.range);
    const bucket = BUCKET_FOR[data.range];
    const summary = await query<Summary>("/api/summary", rp);
    const ts = await query<{ points: Point[] }>("/api/timeseries", { ...rp, bucket });
    const paths = await top(rp, "path");
    const sources = await top(rp, "src_ip");
    const agents = await top(rp, "user_agent");
    const { events } = await query<{ events: EventRow[] }>("/api/events", { ...rp, limit: "50" });
    return { summary, series: align(ts.points, rp.from, rp.to, bucket), paths, sources, agents, events };
  });
