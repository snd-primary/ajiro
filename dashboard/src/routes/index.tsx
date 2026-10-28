import { Link, createFileRoute } from "@tanstack/solid-router";
import { For } from "solid-js";
import { TimeChart } from "../components/TimeChart";
import { EventTable } from "../components/EventTable";
import { TopTable } from "../components/TopTable";
import { getOverview } from "../lib/collector";
import { num, utc } from "../lib/format";
import { RANGES, type RangeKey } from "../lib/types";

export const Route = createFileRoute("/")({
  validateSearch: (s: Record<string, unknown>): { range: RangeKey } => ({
    range: typeof s.range === "string" && Object.hasOwn(RANGES, s.range) ? (s.range as RangeKey) : "7d",
  }),
  loaderDeps: ({ search }) => ({ range: search.range }),
  loader: ({ deps: { range } }) => getOverview({ data: { range } }),
  component: Overview,
});

function Overview() {
  const data = Route.useLoaderData();
  const search = Route.useSearch();
  return (
    <>
      <nav class="ranges">
        <For each={Object.keys(RANGES) as RangeKey[]}>
          {(r) => (
            <Link to="/" search={{ range: r }} class={{ active: search().range === r }}>
              {r}
            </Link>
          )}
        </For>
      </nav>

      <section class="stats">
        <Stat label="events" value={num(data().summary.events)} />
        <Stat label="HTTP requests" value={num(data().summary.http_requests)} />
        <Stat label="silent connections" value={num(data().summary.conn_no_request)} />
        <Stat label="rate-limited (dropped)" value={num(data().summary.rate_limited)} />
        <Stat label="distinct source IPs" value={num(data().summary.distinct_src_ips)} />
        <Stat label="last event (UTC)" value={utc(data().summary.last)} />
      </section>

      <TimeChart data={data().series} />

      <div class="grid">
        <TopTable title="top paths" items={data().paths} />
        <TopTable title="top source IPs" items={data().sources} />
        <TopTable title="top user agents" items={data().agents} />
      </div>

      <EventTable events={data().events} />
    </>
  );
}

function Stat(props: { label: string; value: string }) {
  return (
    <div class="stat">
      <div class="stat-value">{props.value}</div>
      <div class="stat-label">{props.label}</div>
    </div>
  );
}
