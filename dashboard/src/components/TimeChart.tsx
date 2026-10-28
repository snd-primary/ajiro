import { createEffect, For, onSettled } from "solid-js";
import type uPlot from "uplot";
import { num, utc } from "../lib/format";
import type { Aligned } from "../lib/series";

// Series are tied to event types, never to their order on screen, so a
// type keeps its color in every range (validated palette, slots 1-3).
const SERIES = [
  { key: "http", label: "HTTP requests", color: "--series-1" },
  { key: "silent", label: "silent connections", color: "--series-2" },
  { key: "dropped", label: "rate-limited (dropped)", color: "--series-3" },
] as const;

const HEIGHT = 240;

const toData = (d: Aligned): uPlot.AlignedData => [d.t, d.http, d.silent, d.dropped];

// TimeChart hands a <div> to uPlot and lets it draw on a canvas; Solid only
// owns the box. Two pieces connect them:
//   - onSettled: create the plot once the element is in the page (uPlot
//     measures it), and destroy it on unmount via the returned cleanup.
//   - createEffect: when the loader brings new data, push it with setData
//     instead of rebuilding the plot.
export function TimeChart(props: { data: Aligned }) {
  let el!: HTMLDivElement;
  let plot: uPlot | undefined;
  let current: Aligned | undefined;

  createEffect(
    () => props.data,
    (d) => {
      current = d;
      plot?.setData(toData(d));
    },
  );

  onSettled(() => {
    let disposed = false;
    let ro: ResizeObserver | undefined;
    const dark = window.matchMedia("(prefers-color-scheme: dark)");
    let rebuild = () => {};

    // uPlot touches the DOM, so load it only in the browser, after hydration.
    import("uplot").then(({ default: UPlot }) => {
      if (disposed || !current) return;
      // Canvas can't read CSS variables, so resolve them now and again
      // whenever the color scheme flips.
      rebuild = () => {
        plot?.destroy();
        plot = new UPlot(options(UPlot, el), toData(current!), el);
      };
      rebuild();
      ro = new ResizeObserver(() => plot?.setSize({ width: el.clientWidth, height: HEIGHT }));
      ro.observe(el);
      dark.addEventListener("change", rebuild);
    });

    return () => {
      disposed = true;
      ro?.disconnect();
      dark.removeEventListener("change", rebuild);
      plot?.destroy();
      plot = undefined;
    };
  });

  return (
    <section class="card wide">
      <h2>events over time</h2>
      <div ref={el} class="chart" style={{ "min-height": `${HEIGHT}px` }} />
      <details class="table-view">
        <summary>table view</summary>
        <div class="scroll">
          <table>
            <thead>
              <tr>
                <th>bucket start (UTC)</th>
                <For each={SERIES}>{(s) => <th class="num">{s.label}</th>}</For>
              </tr>
            </thead>
            <tbody>
              <For each={nonEmptyRows(props.data)}>
                {(r) => (
                  <tr>
                    <td class="ts">{utc(new Date(r.t * 1000).toISOString())}</td>
                    <td class="num">{num(r.http)}</td>
                    <td class="num">{num(r.silent)}</td>
                    <td class="num">{num(r.dropped)}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}

function nonEmptyRows(d: Aligned) {
  return d.t
    .map((t, i) => ({ t, http: d.http[i], silent: d.silent[i], dropped: d.dropped[i] }))
    .filter((r) => r.http + r.silent + r.dropped > 0)
    .reverse();
}

function options(UPlot: typeof uPlot, el: HTMLElement): uPlot.Options {
  const css = getComputedStyle(el);
  const v = (name: string) => css.getPropertyValue(name).trim();
  const axis: uPlot.Axis = {
    stroke: v("--muted"),
    grid: { stroke: v("--line"), width: 1 },
    ticks: { stroke: v("--line"), width: 1 },
    font: "11px system-ui, sans-serif",
  };
  return {
    width: el.clientWidth,
    height: HEIGHT,
    // Show the axis in UTC like the rest of the page, not browser local time.
    tzDate: (ts) => UPlot.tzDate(new Date(ts * 1000), "Etc/UTC"),
    cursor: { y: false, drag: { x: false, y: false }, points: { size: 8 } },
    legend: { live: true },
    scales: { y: { range: (_u, _min, max) => [0, Math.max(1, max)] } },
    axes: [axis, { ...axis, size: 48, values: (_u, ticks) => ticks.map((t) => (Number.isInteger(t) ? num(t) : "")) }],
    series: [
      { label: "time (UTC)", value: (_u, t) => (t == null ? "—" : utc(new Date(t * 1000).toISOString())) },
      ...SERIES.map((s) => ({
        label: s.label,
        stroke: v(s.color),
        width: 2,
        points: { size: 6 },
        value: (_u: uPlot, n: number | null) => (n == null ? "—" : num(n)),
      })),
    ],
  };
}
