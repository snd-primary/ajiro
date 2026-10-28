import { For, Show } from "solid-js";
import { utc } from "../lib/format";
import { visible } from "../lib/visible";
import type { EventRow } from "../lib/types";

function what(e: EventRow): string {
  switch (e.event_type) {
    case "http_request":
      return `${visible(e.http_method)} ${visible(e.http_uri)}`;
    case "conn_no_request":
      return "(connected, sent no request)";
    case "rate_limited":
      return `(rate limited: ${e.dropped_count ?? 0} dropped)`;
  }
}

export function EventTable(props: { events: EventRow[] }) {
  return (
    <section class="card wide">
      <h2>latest events</h2>
      <Show when={props.events.length > 0} fallback={<p class="muted">no events in range</p>}>
        <div class="scroll">
          <table class="events">
            <thead>
              <tr>
                <th>time (UTC)</th>
                <th>source</th>
                <th>port</th>
                <th>request</th>
                <th>user agent</th>
              </tr>
            </thead>
            <tbody>
              <For each={props.events}>
                {(e) => (
                  <tr class={{ proxy: !!e.http_proxy_request }}>
                    <td class="ts">{utc(e.ts)}</td>
                    <td><code>{e.src_ip}</code></td>
                    <td class="num">{e.dst_port ?? ""}</td>
                    <td class="value">
                      <code>{what(e)}</code>
                      <Show when={e.http_proxy_request}>
                        <span class="tag">proxy req · not forwarded</span>
                      </Show>
                    </td>
                    <td class="value"><code>{visible(e.http_user_agent)}</code></td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}
