import { HeadContent, Outlet, Scripts, createRootRoute } from "@tanstack/solid-router";
import { Loading } from "solid-js";
import type { JSX } from "@solidjs/web";
import uplotCss from "uplot/dist/uPlot.min.css?url";
import appCss from "../styles.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { name: "robots", content: "noindex, nofollow" },
      { name: "referrer", content: "no-referrer" },
      { title: "ajiro" },
    ],
    links: [
      { rel: "stylesheet", href: uplotCss },
      { rel: "stylesheet", href: appCss },
    ],
  }),
  shellComponent: RootDocument,
  component: () => <Outlet />,
});

function RootDocument(props: { children: JSX.Element }) {
  return (
    <html lang="ja">
      <head>
        <HeadContent />
      </head>
      <body>
        <header class="topbar">
          <span class="brand">ajiro</span>
          <span class="muted">honeypot observations · local only</span>
        </header>
        <main>
          <Loading fallback={<p class="muted">loading…</p>}>{props.children}</Loading>
        </main>
        <Scripts />
      </body>
    </html>
  );
}
