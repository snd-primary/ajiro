import type { Point, RangeKey } from "./types";

export type Bucket = "minute" | "hour" | "day";

// How finely each range is cut: about 24-170 points, enough to see shape
// without asking the collector for thousands of rows.
export const BUCKET_FOR: Record<RangeKey, Bucket> = { "24h": "hour", "7d": "hour", "30d": "day" };

const STEP: Record<Bucket, number> = { minute: 60, hour: 3600, day: 86400 };

// Aligned is the chart's data: one x array (Unix seconds, UTC bucket starts)
// and one y array per event type, all the same length.
export type Aligned = {
  bucket: Bucket;
  t: number[];
  http: number[];
  silent: number[];
  dropped: number[];
};

// align turns the collector's sparse points into dense arrays. Buckets with
// no events are absent from the API; here they become 0 so the line drops
// to the floor instead of bridging the gap.
export function align(points: Point[], from: string, to: string, bucket: Bucket): Aligned {
  const step = STEP[bucket];
  const start = Math.floor(Date.parse(from) / 1000 / step) * step; // = date_trunc in UTC
  const end = Date.parse(to) / 1000;
  const out: Aligned = { bucket, t: [], http: [], silent: [], dropped: [] };
  const index = new Map<number, number>();
  for (let t = start; t < end; t += step) {
    index.set(t, out.t.length);
    out.t.push(t);
    out.http.push(0);
    out.silent.push(0);
    out.dropped.push(0);
  }
  for (const p of points) {
    const i = index.get(Date.parse(p.t) / 1000);
    if (i === undefined) continue;
    if (p.event_type === "http_request") out.http[i] += p.n;
    else if (p.event_type === "conn_no_request") out.silent[i] += p.n;
    else if (p.event_type === "rate_limited") out.dropped[i] += p.n;
  }
  return out;
}
