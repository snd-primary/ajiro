import { For, Show } from "solid-js";
import { utc, num } from "../lib/format";
import { visible, hasHidden } from "../lib/visible";
import type { TopItem } from "../lib/types";

export function TopTable(props: { title: string; items: TopItem[] }) {
  const max = () => Math.max(1, ...props.items.map((it) => it.n));
  return (
    <section class="card">
      <h2>{props.title}</h2>
      <Show when={props.items.length > 0} fallback={<p class="muted">no data</p>}>
        <table class="top">
          <thead>
            <tr>
              <th>value</th>
              <th class="num">count</th>
              <th class="num">sources</th>
              <th>last seen</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.items}>
              {(it) => (
                <tr>
                  <td class="value">
                    <span class="bar" style={{ width: `${(it.n / max()) * 100}%` }} />
                    <code class={{ hidden: hasHidden(it.value) }}>{visible(it.value) || "(empty)"}</code>
                  </td>
                  <td class="num">{num(it.n)}</td>
                  <td class="num">{num(it.sources)}</td>
                  <td class="ts">{utc(it.last)}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>
    </section>
  );
}
