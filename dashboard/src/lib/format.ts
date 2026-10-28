// Timestamps are shown in UTC so the server render and the browser agree
// and so they line up with the collector's logs.
export function utc(ts: string | null | undefined): string {
  if (!ts) return "—";
  return ts.replace("T", " ").replace(/\.\d+/, "").replace(/(Z|[+-]00:00)$/, "Z");
}

const nf = new Intl.NumberFormat("en-US");
export const num = (n: number) => nf.format(n);
